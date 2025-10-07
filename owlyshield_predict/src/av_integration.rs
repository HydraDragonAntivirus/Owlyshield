// av_integration.rs - Dual Named Pipe Integration for HydraDragon AV ↔ Owlyshield EDR
// Place this in: src/av_integration.rs

use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver, Sender, TryRecvError};
use std::thread;
use std::time::Duration;
use serde::{Deserialize, Serialize};
use windows::core::PCSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE, ERROR_PIPE_CONNECTED};
use windows::Win32::Storage::FileSystem::{ReadFile, WriteFile, FlushFileBuffers};
use windows::Win32::System::Pipes::{
    CreateNamedPipeA, ConnectNamedPipe, DisconnectNamedPipe,
    PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE, PIPE_READMODE_MESSAGE,
    PIPE_WAIT, PIPE_UNLIMITED_INSTANCES,
};

use crate::Logging;

// Pipe 1: AV sends threat events TO EDR (Owlyshield receives)
const PIPE_AV_TO_EDR: &str = "\\\\.\\pipe\\hydradragon_to_owlyshield";

// Pipe 2: EDR sends scan requests TO AV (HydraDragon receives)
const PIPE_EDR_TO_AV: &str = "\\\\.\\pipe\\owlyshield_to_hydradragon";

const BUFFER_SIZE: u32 = 8192;

/// Event sent FROM HydraDragon AV TO Owlyshield EDR
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AVThreatEvent {
    pub timestamp: String,
    pub file_path: String,
    pub virus_name: String,
    pub is_malicious: bool,
    pub detection_type: String,  // "signature", "behavioral", "heuristic"
    pub action_required: String, // "kill_and_remove", "monitor", "quarantine"
    #[serde(default)]
    pub pid: Option<u32>,
    #[serde(default)]
    pub gid: Option<u64>,
}

/// Request sent FROM Owlyshield EDR TO HydraDragon AV
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EDRScanRequest {
    pub event_type: String,      // "NEW_FILE_DETECTED", "SUSPICIOUS_ACTIVITY"
    pub file_path: String,
    pub timestamp: String,
    #[serde(default)]
    pub pid: Option<u32>,
    #[serde(default)]
    pub additional_context: Option<String>,
}

/// Response sent FROM HydraDragon AV back TO Owlyshield EDR
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AVScanResponse {
    pub file_path: String,
    pub is_malicious: bool,
    pub virus_name: Option<String>,
    pub scan_timestamp: String,
}

/// AVIntegration manages both named pipes for bidirectional communication
pub struct AVIntegration {
    // Receiver for incoming scan requests from EDR
    scan_request_rx: Receiver<EDRScanRequest>,
    // Sender for outgoing threat events to EDR (kept for internal use)
    _threat_event_handle: thread::JoinHandle<()>,
    // Handle for the scan request listener thread
    _scan_request_handle: thread::JoinHandle<()>,
}

impl AVIntegration {
    /// Create a new AVIntegration with both pipes
    pub fn new() -> Self {
        // Channel for receiving scan requests FROM EDR
        let (scan_tx, scan_rx) = channel();
        
        // Start the scan request listener (Pipe 2: EDR → AV)
        let scan_handle = thread::spawn(move || {
            scan_request_server_loop(scan_tx);
        });

        // Threat event sender is now a function call, not a persistent thread
        // We'll keep a dummy handle for compatibility
        let threat_handle = thread::spawn(|| {
            // This thread does nothing but keeps the structure consistent
            loop {
                thread::sleep(Duration::from_secs(60));
            }
        });

        Logging::info("AVIntegration: Dual-pipe communication initialized");
        Logging::info(&format!("  - Listening for scan requests on: {}", PIPE_EDR_TO_AV));
        Logging::info(&format!("  - Ready to send threats to: {}", PIPE_AV_TO_EDR));
        
        AVIntegration {
            scan_request_rx: scan_rx,
            _threat_event_handle: threat_handle,
            _scan_request_handle: scan_handle,
        }
    }

    /// Send a threat event TO Owlyshield EDR (Pipe 1: AV → EDR)
    /// This is called by HydraDragon when it detects malware
    pub fn send_threat_event(&self, event: AVThreatEvent) -> Result<(), String> {
        send_threat_to_edr(event)
    }

    /// Poll for scan requests FROM Owlyshield EDR (Pipe 2: EDR → AV)
    /// Returns a list of files that the EDR wants scanned
    pub fn poll_scan_requests(&mut self) -> Vec<EDRScanRequest> {
        let mut requests = Vec::new();
        
        loop {
            match self.scan_request_rx.try_recv() {
                Ok(request) => {
                    Logging::info(&format!(
                        "Received scan request from EDR: {} ({})",
                        request.file_path, request.event_type
                    ));
                    requests.push(request);
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    Logging::error("AVIntegration: Scan request channel disconnected");
                    break;
                }
            }
        }
        
        requests
    }

    /// Send a scan response back TO Owlyshield EDR
    /// This is called after HydraDragon completes a scan requested by the EDR
    pub fn send_scan_response(&self, response: AVScanResponse) -> Result<(), String> {
        // For now, we'll send this as a special threat event
        // You could create a third pipe if you want separate response handling
        let event = AVThreatEvent {
            timestamp: response.scan_timestamp,
            file_path: response.file_path,
            virus_name: response.virus_name.unwrap_or_else(|| "Clean".to_string()),
            is_malicious: response.is_malicious,
            detection_type: "on_demand_scan".to_string(),
            action_required: if response.is_malicious { "monitor" } else { "none" }.to_string(),
            pid: None,
            gid: None,
        };
        
        self.send_threat_event(event)
    }

    /// Check if a specific file path is marked as malicious (for backward compatibility)
    pub fn is_file_malicious(&mut self, file_path: &PathBuf) -> Option<AVThreatEvent> {
        // This method is no longer needed in the new architecture
        // but kept for backward compatibility
        None
    }
}

/// Pipe 1 Server: Send threat events TO EDR (one-shot connection per event)
fn send_threat_to_edr(event: AVThreatEvent) -> Result<(), String> {
    unsafe {
        // Try to connect to the EDR's receiving pipe
        let pipe_handle = windows::Win32::Storage::FileSystem::CreateFileA(
            PCSTR(format!("{}\0", PIPE_AV_TO_EDR).as_ptr()),
            windows::Win32::Storage::FileSystem::FILE_GENERIC_WRITE.0,
            windows::Win32::Storage::FileSystem::FILE_SHARE_NONE,
            None,
            windows::Win32::Storage::FileSystem::OPEN_EXISTING,
            windows::Win32::Storage::FileSystem::FILE_ATTRIBUTE_NORMAL,
            None,
        );

        if let Err(e) = pipe_handle {
            return Err(format!("Failed to connect to EDR pipe: {:?}", e));
        }

        let pipe_handle = pipe_handle.unwrap();
        
        // Serialize and send the event
        let message = serde_json::to_string(&event)
            .map_err(|e| format!("Failed to serialize event: {}", e))?;
        let message_bytes = message.as_bytes();
        
        let mut bytes_written = 0u32;
        let result = WriteFile(
            pipe_handle,
            Some(message_bytes.as_ptr() as *const _),
            message_bytes.len() as u32,
            Some(&mut bytes_written),
            None,
        );

        let _ = FlushFileBuffers(pipe_handle);
        let _ = CloseHandle(pipe_handle);

        if result.is_err() {
            return Err("Failed to write to EDR pipe".to_string());
        }

        Logging::info(&format!(
            "Successfully sent threat event to EDR: {} - {}",
            event.file_path, event.virus_name
        ));
        
        Ok(())
    }
}

/// Pipe 2 Server: Receive scan requests FROM EDR (persistent listener)
fn scan_request_server_loop(tx: Sender<EDRScanRequest>) {
    Logging::info(&format!("Starting scan request listener: {}", PIPE_EDR_TO_AV));
    
    loop {
        unsafe {
            // Create the named pipe to RECEIVE requests from EDR
            let pipe_handle = CreateNamedPipeA(
                PCSTR(format!("{}\0", PIPE_EDR_TO_AV).as_ptr()),
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                PIPE_UNLIMITED_INSTANCES,
                BUFFER_SIZE,
                BUFFER_SIZE,
                0,
                None,
            );

            if let Err(e) = pipe_handle {
                Logging::error(&format!("Failed to create scan request pipe: {:?}", e));
                thread::sleep(Duration::from_secs(5));
                continue;
            }

            let pipe_handle = pipe_handle.unwrap();
            
            // Wait for EDR to connect
            let connected = ConnectNamedPipe(pipe_handle, None);
            
            match connected {
                Ok(_) | Err(e) if e.code().0 as u32 == ERROR_PIPE_CONNECTED.0 => {
                    // EDR connected, read the scan request
                    if let Some(request) = read_scan_request(pipe_handle) {
                        if let Err(e) = tx.send(request) {
                            Logging::error(&format!("Failed to forward scan request: {}", e));
                        }
                    }
                    
                    // Disconnect and close
                    let _ = FlushFileBuffers(pipe_handle);
                    let _ = DisconnectNamedPipe(pipe_handle);
                    let _ = CloseHandle(pipe_handle);
                }
                Err(e) => {
                    Logging::error(&format!("ConnectNamedPipe failed on scan request listener: {:?}", e));
                    let _ = CloseHandle(pipe_handle);
                    thread::sleep(Duration::from_millis(100));
                }
            }
        }
    }
}

/// Read and parse a scan request from the pipe
fn read_scan_request(pipe_handle: HANDLE) -> Option<EDRScanRequest> {
    unsafe {
        let mut buffer = vec![0u8; BUFFER_SIZE as usize];
        let mut bytes_read = 0u32;
        
        let result = ReadFile(
            pipe_handle,
            Some(buffer.as_mut_ptr() as *mut _),
            buffer.len() as u32,
            Some(&mut bytes_read),
            None,
        );

        if result.is_err() || bytes_read == 0 {
            return None;
        }

        let data = match std::str::from_utf8(&buffer[..bytes_read as usize]) {
            Ok(s) => s,
            Err(e) => {
                Logging::error(&format!("Invalid UTF-8 in scan request: {}", e));
                return None;
            }
        };

        match serde_json::from_str::<EDRScanRequest>(data) {
            Ok(request) => Some(request),
            Err(e) => {
                Logging::error(&format!("Failed to parse scan request JSON: {}", e));
                Logging::error(&format!("Data received: {}", data));
                None
            }
        }
    }
}
