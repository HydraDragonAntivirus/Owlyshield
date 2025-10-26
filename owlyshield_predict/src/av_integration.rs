#![cfg(feature = "hydradragon")]

use std::ffi::CString;
use std::time::Duration; // Keep for sleep/timeouts if needed, though not used here

use chrono::Utc;
use serde::{Deserialize, Serialize};
use windows::core::PCSTR;
use windows::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, BOOL};
use windows::Win32::Storage::FileSystem::{
    CreateFileA, FlushFileBuffers, WriteFile, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_WRITE,
    FILE_SHARE_NONE, OPEN_EXISTING,
};
// REMOVED: All server-side Win32 imports (CreateNamedPipe, ConnectNamedPipe, etc.)
// REMOVED: ReadFile (it's not reading anymore)

use crate::IOMessage;
use crate::process::ProcessRecord;
use crate::logging::Logging; // <-- your logging module

// Pipe 1: AV sends threat events TO EDR (Owlyshield receives)
const PIPE_AV_TO_EDR: &str = r"\\.\pipe\Global\hydradragon_to_owlyshield";

// Pipe 2: EDR (or in this case, Python) sends scan requests TO AV (HydraDragon receives)
const PIPE_EDR_TO_AV: &str = r"\\.\pipe\Global\owlyshield_to_hydradragon";

// const BUFFER_SIZE: u32 = 8192; // No longer needed for this client-only file

/// Event sent FROM HydraDragon AV TO Owlyshield EDR
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AVThreatEvent {
    pub timestamp: String,
    pub file_path: String,
    pub virus_name: String,
    pub is_malicious: bool,
    pub detection_type: String,
    pub action_required: String,
    #[serde(default)]
    pub pid: Option<u32>,
    #[serde(default)]
    pub gid: Option<u64>,
}

/// Request sent FROM Owlyshield EDR TO HydraDragon AV
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EDRScanRequest {
    pub event_type: String,
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

/// AVIntegration is now a simple struct for sending events.
#[derive(Default)]
pub struct AVIntegration {
    // No handles or channels needed, as it no longer runs background threads.
}

impl AVIntegration {
    /// Create a new AVIntegration
    pub fn new() -> Self {
        // No threads to spawn, just create the struct.
        AVIntegration {}
    }

    /// Send a threat event TO Owlyshield EDR (Pipe 1: AV → EDR)
    pub fn send_threat_event(&self, event: AVThreatEvent) -> Result<(), String> {
        send_threat_to_edr(event)
    }

    // REMOVED: poll_scan_requests
    // This function is gone because this Rust module is no longer receiving scan requests.
    // Your Python script is receiving them.

    /// Send a scan response back TO Owlyshield EDR
    pub fn send_scan_response(&self, response: AVScanResponse) -> Result<(), String> {
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
    /// This now sends the request to your PYTHON server.
    pub fn queue_file_event(&mut self, iomsg: &IOMessage, precord: &ProcessRecord) {
        let request = EDRScanRequest {
            event_type: "NEW_IO_EVENT".to_string(),
            file_path: precord.exepath.to_string_lossy().to_string(),
            timestamp: Utc::now().to_rfc3339(),
            pid: Some(iomsg.pid),
            additional_context: Some(format!("Event triggered by GID: {}", precord.gid)),
        };

        // This function now sends the request to the pipe your Python script is listening on.
        if let Err(e) = send_scan_request_to_av(request) {
            Logging::error(&format!("Failed to send scan request to AV (Python): {}", e));
        }
    }
}

// This helper function is no longer used.
// fn log_get_last_error_context(context: &str) {
//     let last = unsafe { GetLastError() };
//     Logging::error(&format!("{} - GetLastError={:?}", context, last));
// }

/// Pipe 1 Client: Send threat events TO EDR (one-shot connection per event)
/// This function is unchanged.
fn send_threat_to_edr(mut event: AVThreatEvent) -> Result<(), String> {
    unsafe {
        let pipe_name_c = CString::new(PIPE_AV_TO_EDR).map_err(|e| format!("Invalid pipe name: {}", e))?;
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

        Logging::novelty(&format!(
            "Successfully sent threat event to EDR: {} - {} ({} bytes)",
            event.file_path, event.virus_name, bytes_written
        ));
        
        Ok(())
    }
}

/// Pipe 2 Client: Send a scan request TO AV (one-shot connection per request)
/// This function is unchanged. It will now connect to your PYTHON server.
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
                // This error is now expected if the Python server isn't running
                Logging::error(&format!("Failed to connect to AV (Python) pipe for scan request: {:?}, GetLastError={:?}", e, last));
                return Err(format!("Failed to connect to AV (Python) pipe for scan request: {:?}, GetLastError={:?}", e, last));
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
            Logging::error("Failed to write scan request to AV (Python) pipe");
            return Err("Failed to write scan request to AV (Python) pipe".to_string());
        }
        Logging::novelty(&format!("Sent scan request to AV (Python): {} ({} bytes)", request.file_path, bytes_written));
        Ok(())
    }
}
