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
const PIPE_EDR_TO_AV: &str = r"\\.\pipe\Global\owlyshield_to_hydragon";

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

        // Threat event listener (Pipe 1: AV -> EDR)
        let threat_handle = thread::spawn(|| {
            threat_event_server_loop();
        });

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
                    // use existing logging methods (warning/error/novelty/alert) as appropriate
                    Logging::novelty(&format!(
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
            action_required: "kill_and_remove".to_string(),
            pid: None,
            gid: None,
        };
        
        self.send_threat_event(event)
    }

    /// Queue a file event to be scanned by HydraDragon AV
    pub fn queue_file_event(&mut self, iomsg: &IOMessage, precord: &ProcessRecord) {
        // Extract the actual file path from the IO message
        // The IOMessage should contain the file that was accessed/created/modified
        let file_path = if let Some(ref path) = iomsg.filepath {
            path.to_string_lossy().to_string()
        } else {
            // Fallback: if no filepath in IOMessage, log error and return
            Logging::warning(&format!(
                "No file path in IOMessage for PID {}, cannot queue for AV scan",
                iomsg.pid
            ));
            return;
        };

        // Build the scan request with the actual file path
        let request = EDRScanRequest {
            event_type: "NEW_IO_EVENT".to_string(),
            file_path,
            timestamp: Utc::now().to_rfc3339(),
            pid: Some(iomsg.pid),
            additional_context: Some(format!(
                "Process: {} (GID: {}), Operation: {:?}",
                precord.exepath.to_string_lossy(),
                precord.gid,
                iomsg.operation // Assuming IOMessage has an operation field
            )),
        };

        // Log what we're sending
        Logging::novelty(&format!(
            "Queuing file for AV scan: {} (triggered by PID: {}, Process: {})",
            request.file_path,
            iomsg.pid,
            precord.exepath.to_string_lossy()
        ));

        if let Err(e) = send_scan_request_to_av(request) {
            Logging::error(&format!("Failed to send scan request to AV: {}", e));
        }
    }
}

fn log_get_last_error_context(context: &str) {
    let last = unsafe { GetLastError() };
    Logging::error(&format!("{} - GetLastError={:?}", context, last));
}

/// Pipe 1 Client: Send threat events TO EDR (one-shot connection per event)
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

/// Pipe 2 Client: Send a scan request TO AV (one-shot connection per request)
fn send_scan_request_to_av(request: EDRScanRequest) -> Result<(), String> {
    unsafe {
        let pipe_name_c = CString::new(PIPE_EDR_TO_AV).map_err(|e| format!("Invalid pipe name: {}", e))?;
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
                Logging::error(&format!("Failed to connect to AV pipe for scan request: {:?}, GetLastError={:?}", e, last));
                return Err(format!("Failed to connect to AV pipe for scan request: {:?}, GetLastError={:?}", e, last));
            }
        };

        let message = match serde_json::to_string(&request) {
            Ok(m) => m,
            Err(e) => {
                Logging::error(&format!("Failed to serialize scan request: {}", e));
                return Err(format!("Failed to serialize scan request: {}", e));
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
            Logging::error("Failed to write scan request to AV pipe");
            return Err("Failed to write scan request to AV pipe".to_string());
        }
        Logging::novelty(&format!("Sent scan request to AV: {} ({} bytes)", request.file_path, bytes_written));
        Ok(())
    }
}

/// Pipe 2 Server: Receive scan requests FROM EDR (persistent listener)
fn scan_request_server_loop(tx: Sender<EDRScanRequest>) {
    Logging::novelty(&format!("Starting scan request listener: {}", PIPE_EDR_TO_AV));
    
    loop {
        unsafe {
            // Create the named pipe to RECEIVE requests from EDR
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
                // dwOpenMode: FILE_FLAGS_AND_ATTRIBUTES(0x0000_0003) == numeric PIPE_ACCESS_DUPLEX
                FILE_FLAGS_AND_ATTRIBUTES(0x0000_0003),
                // dwPipeMode: needs NAMED_PIPE_MODE typed wrapper
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
                if let Some(request) = read_scan_request(pipe_handle) {
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

fn threat_event_server_loop() {
    Logging::novelty(&format!("Starting threat event listener (Pipe 1) on: {}", PIPE_AV_TO_EDR));

    loop {
        unsafe {
            let pipe_name_c = match CString::new(PIPE_AV_TO_EDR) {
                Ok(s) => s,
                Err(e) => {
                    Logging::error(&format!("Invalid pipe name for threat listener: {}", e));
                    thread::sleep(Duration::from_secs(5));
                    continue;
                }
            };

            let pcstr = PCSTR(pipe_name_c.as_ptr() as *const u8);
            let pipe_handle_res = CreateNamedPipeA(
                pcstr,
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
                    Logging::error(&format!("Failed to create threat event pipe: {:?}, GetLastError={:?}", e, GetLastError()));
                    thread::sleep(Duration::from_secs(5));
                    continue;
                }
            };

            let connected: BOOL = ConnectNamedPipe(pipe_handle, None);

            if connected.as_bool() || GetLastError() == ERROR_PIPE_CONNECTED {
                handle_threat_connection(pipe_handle);
            } else {
                Logging::error("ConnectNamedPipe failed on threat listener");
                let _ = CloseHandle(pipe_handle);
                thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

fn handle_threat_connection(pipe_handle: HANDLE) {
    unsafe {
        let mut buffer = vec![0u8; BUFFER_SIZE as usize];
        let mut bytes_read: u32 = 0;

        let result = ReadFile(
            pipe_handle,
            Some(buffer.as_mut_ptr() as *mut _),
            buffer.len() as u32,
            Some(&mut bytes_read as *mut u32),
            None,
        );

        if result.as_bool() && bytes_read > 0 {
            let data = String::from_utf8_lossy(&buffer[..bytes_read as usize]);
            Logging::novelty(&format!("Received threat event: {}", data));
            // optionally process event here
        } else {
            Logging::warning("ReadFile returned no data for threat connection or failed");
        }

        let _ = FlushFileBuffers(pipe_handle);
        let _ = DisconnectNamedPipe(pipe_handle);
        let _ = CloseHandle(pipe_handle);
    }
}

/// Read and parse a scan request from the pipe
fn read_scan_request(pipe_handle: HANDLE) -> Option<EDRScanRequest> {
    unsafe {
        let mut buffer = vec![0u8; BUFFER_SIZE as usize];
        let mut bytes_read: u32 = 0;

        // Correct ReadFile signature for windows = "0.48.0"
        let result: BOOL = ReadFile(
            pipe_handle,
            Some(buffer.as_mut_ptr() as *mut _), // lpBuffer
            buffer.len() as u32,                 // nNumberOfBytesToRead
            Some(&mut bytes_read as *mut u32),   // lpNumberOfBytesRead
            None,                                // lpOverlapped
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
