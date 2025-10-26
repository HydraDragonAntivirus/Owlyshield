#![cfg(feature = "hydradragon")]

use std::ffi::CString;
use std::sync::mpsc::{channel, Receiver, Sender, TryRecvError};
use std::thread;
use std::time::Duration;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use windows::core::PCSTR;
use windows::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, ERROR_PIPE_CONNECTED, BOOL};
use windows::Win32::Storage::FileSystem::{
    CreateFileA, FlushFileBuffers, ReadFile, WriteFile, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_WRITE,
    FILE_SHARE_NONE, OPEN_EXISTING, FILE_FLAGS_AND_ATTRIBUTES,
};
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeA, DisconnectNamedPipe, PIPE_READMODE_MESSAGE, PIPE_TYPE_MESSAGE,
    PIPE_UNLIMITED_INSTANCES, PIPE_WAIT, NAMED_PIPE_MODE,
};

use crate::IOMessage;
use crate::process::ProcessRecord;
use crate::logging::Logging;

// Pipe 1: AV sends threat events TO EDR (Owlyshield receives)
const PIPE_AV_TO_EDR: &str = r"\\.\pipe\Global\hydradragon_to_owlyshield";

// Pipe 2: EDR sends scan requests TO AV (HydraDragon receives)
const PIPE_EDR_TO_AV: &str = r"\\.\pipe\Global\owlyshield_to_hydradragon";

const BUFFER_SIZE: u32 = 8192;

/// Event sent FROM HydraDragon AV TO Owlyshield EDR
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AVThreatEvent {
    pub timestamp: String,
    pub file_path: String,
    pub virus_name: String,
    pub is_malicious: bool,
    pub detection_type: String,  // "signature", "behavioral", "heuristic"
    pub action_required: String, // "kill_and_remove"
    #[serde(default)]
    pub pid: Option<u32>,
    #[serde(default)]
    pub gid: Option<u64>,
}

/// Request sent FROM Owlyshield EDR TO HydraDragon AV
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EDRScanRequest {
    pub event_type: String,      // "NEW_IO_EVENT", "SUSPICIOUS_ACTIVITY"
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
    // Receiver for incoming scan requests (from EDR or internal)
    scan_request_rx: Receiver<EDRScanRequest>,
    // ** CHANGED: Added sender for internal events **
    internal_scan_tx: Sender<EDRScanRequest>, 
    // Handle for the scan request listener thread
    _scan_request_handle: thread::JoinHandle<()>,
}

impl AVIntegration {
    /// Create a new AVIntegration with both pipes
    pub fn new() -> Self {
        // Channel for receiving scan requests
        let (scan_tx, scan_rx) = channel();

        // ** CHANGED: Clone the sender for internal use **
        let internal_tx = scan_tx.clone();

        // Start the scan request listener (Pipe 2: EDR → AV)
        // This is the SERVER side, which is correct for the AV.
        // ** CHANGED: Move the original 'scan_tx' into the thread **
        let scan_handle = thread::spawn(move || {
            scan_request_server_loop(scan_tx);
        });


        AVIntegration {
            scan_request_rx: scan_rx,
            // ** CHANGED: Store the cloned sender **
            internal_scan_tx: internal_tx,
            _scan_request_handle: scan_handle,
        }
    }

    /// Send a threat event TO Owlyshield EDR (Pipe 1: AV → EDR)
    /// This is the CLIENT role for Pipe 1. This function is correct.
    pub fn send_threat_event(&self, event: AVThreatEvent) -> Result<(), String> {
        send_threat_to_edr(event)
    }

    /// Poll for scan requests FROM Owlyshield EDR (Pipe 2: EDR → AV)
    /// This function is correct. It pulls from the channel.
    pub fn poll_scan_requests(&mut self) -> Vec<EDRScanRequest> {
        let mut requests = Vec::new();
        
        loop {
            match self.scan_request_rx.try_recv() {
                Ok(request) => {
                    // use existing logging methods (warning/error/novelty/alert) as appropriate
                    Logging::novelty(&format!(
                        "Received scan request: {} ({})",
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
    /// This is correct. It just re-uses the CLIENT function for Pipe 1.
    pub fn send_scan_response(&self, response: AVScanResponse) -> Result<(), String> {
        // For now, we'll send this as a special threat event
        let event = AVThreatEvent {
            timestamp: response.scan_timestamp,
            file_path: response.file_path,
            virus_name: response.virus_name.unwrap_or_else(|| "Clean".to_string()),
            is_malicious: response.is_malicious,
            detection_type: "on_demand_scan".to_string(),
            action_required: "kill_and_remove".to_string(),
            pid: None,
            gid: None,
        };
        
        self.send_threat_event(event)
    }
    
    /// **CHANGED: This function is now logical and correct.**
    /// Queue a file event to be scanned by HydraDragon AV
    /// This function is called by add_irp_record
    pub fn queue_file_event(&mut self, iomsg: &IOMessage, precord: &ProcessRecord) {
        let request = EDRScanRequest {
            event_type: "NEW_IO_EVENT".to_string(),
            file_path: precord.exepath.to_string_lossy().to_string(),
            timestamp: Utc::now().to_rfc3339(),
            pid: Some(iomsg.pid),
            additional_context: Some(format!("Event triggered by GID: {}", precord.gid)),
        };

        // ** THE FIX: **
        // Instead of calling 'send_scan_request_to_av' (client),
        // we send the message *internally* through the channel.
        if let Err(e) = self.internal_scan_tx.send(request) {
            Logging::error(&format!("Failed to send internal scan request: {}", e));
        }
    }
}

fn log_get_last_error_context(context: &str) {
    let last = unsafe { GetLastError() };
    Logging::error(&format!("{} - GetLastError={:?}", context, last));
}

/// Pipe 1 Client: Send threat events TO EDR (one-shot connection per event)
/// This is the AV's CLIENT role. It is correct.
fn send_threat_to_edr(mut event: AVThreatEvent) -> Result<(), String> {
    unsafe {
        // Use CString to ensure lifetime of the pointer passed into the WinAPI call
        let pipe_name_c = CString::new(PIPE_AV_TO_EDR).map_err(|e| format!("Invalid pipe name: {}", e))?;

        // enforce kill_and_remove policy
        event.action_required = "kill_and_remove".to_string();

        let pipe_handle_res = CreateFileA(
            PCSTR(pipe_name_c.as_ptr() as *const u8),
            FILE_GENERIC_WRITE.0,
            FILE_SHARE_NONE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            HANDLE::default(),
        );

        let pipe_handle = match pipe_handle_res {
            Ok(h) => h,
            Err(e) => {
                let last = GetLastError();
                Logging::error(&format!("Failed to connect to EDR pipe: {:?}, GetLastError={:?}", e, last));
                return Err(format!("Failed to connect to EDR pipe: {:?}, GetLastError={:?}", e, last));
            }
        };
        
        // Serialize and send the event
        let message = match serde_json::to_string(&event) {
            Ok(m) => m,
            Err(e) => {
                Logging::error(&format!("Failed to serialize event: {}", e));
                return Err(format!("Failed to serialize event: {}", e));
            }
        };
        let message_bytes = message.as_bytes();
        
        let mut bytes_written = 0u32;
        let result = WriteFile(
            pipe_handle,
            Some(message_bytes),
            Some(&mut bytes_written),
            None,
        );

        let _ = FlushFileBuffers(pipe_handle);
        let _ = CloseHandle(pipe_handle);

        if !result.as_bool() {
            Logging::error("Failed to write to EDR pipe");
            return Err("Failed to write to EDR pipe".to_string());
        }

        // success: use novelty (or another existing level) to note the event
        Logging::novelty(&format!(
            "Successfully sent threat event to EDR: {} - {} ({} bytes)",
            event.file_path, event.virus_name, bytes_written
        ));
        
        Ok(())
    }
}



/// Pipe 2 Server: Receive scan requests FROM EDR (persistent listener)
/// This is the AV's SERVER role. It is correct.
fn scan_request_server_loop(tx: Sender<EDRScanRequest>) {
    Logging::novelty(&format!("Starting scan request listener: {}", PIPE_EDR_TO_AV));
    
    loop {
        unsafe {
            let pipe_name_c = match CString::new(PIPE_EDR_TO_AV) {
                Ok(s) => s,
                Err(e) => {
                    Logging::error(&format!("Invalid pipe name for scan listener: {}", e));
                    thread::sleep(Duration::from_secs(5));
                    continue;
                }
            };

            let pcstr = PCSTR(pipe_name_c.as_ptr() as *const u8);
            let pipe_handle_res = CreateNamedPipeA(
                pcstr,
                // Using Duplex access, which is fine.
                FILE_FLAGS_AND_ATTRIBUTES(0x0000_0003), 
                NAMED_PIPE_MODE(PIPE_TYPE_MESSAGE.0 | PIPE_READMODE_MESSAGE.0 | PIPE_WAIT.0),
                PIPE_UNLIMITED_INSTANCES,
                BUFFER_SIZE,
                BUFFER_SIZE,
                0,
                None,
            );

            let pipe_handle = match pipe_handle_res {
                Ok(h) => h,
                Err(e) => {
                    Logging::error(&format!("Failed to create scan request pipe: {:?}, GetLastError={:?}", e, GetLastError()));
                    thread::sleep(Duration::from_secs(5));
                    continue;
                }
            };

            // Wait for EDR to connect
            let connected: BOOL = ConnectNamedPipe(pipe_handle, None);

            let handle_connection = |pipe_handle: HANDLE| {
                // This 'read_scan_request' function reads from the EDR
                if let Some(request) = read_scan_request(pipe_handle) {
                    // This 'tx.send' forwards it to the main AV loop
                    if let Err(e) = tx.send(request) {
                        Logging::error(&format!("Failed to forward scan request: {}", e));
                    }
                }
                
                // Disconnect and close
                let _ = FlushFileBuffers(pipe_handle);
                let _ = DisconnectNamedPipe(pipe_handle);
                let _ = CloseHandle(pipe_handle);
            };
            
            if connected.as_bool() {
                handle_connection(pipe_handle);
            } else {
                let last_error = GetLastError();
                if last_error == ERROR_PIPE_CONNECTED {
                    handle_connection(pipe_handle);
                } else {
                    Logging::error(&format!("ConnectNamedPipe failed on scan request listener: {:?}", last_error));
                    let _ = CloseHandle(pipe_handle);
                    thread::sleep(Duration::from_millis(100));
                }
            }
        }
    }
}

/// Read and parse a scan request from the pipe
/// This helper function is correct.
fn read_scan_request(pipe_handle: HANDLE) -> Option<EDRScanRequest> {
    unsafe {
        let mut buffer = vec![0u8; BUFFER_SIZE as usize];
        let mut bytes_read: u32 = 0;

        let result: BOOL = ReadFile(
            pipe_handle,
            Some(buffer.as_mut_ptr() as *mut _),
            buffer.len() as u32,
            Some(&mut bytes_read as *mut u32), 
            None,
        );

        if !result.as_bool() || bytes_read == 0 {
            Logging::warning("read_scan_request: ReadFile failed or returned 0 bytes");
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
