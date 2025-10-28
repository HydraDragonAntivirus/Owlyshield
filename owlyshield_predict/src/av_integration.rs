#![cfg(feature = "hydradragon")]

use std::ffi::CString;
use std::sync::mpsc::{channel, Receiver, Sender, TryRecvError};
use std::thread;
use std::time::Duration;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use windows::core::PCSTR;

use windows::Win32::Foundation::{
    CloseHandle, GetLastError, HANDLE, ERROR_PIPE_CONNECTED, BOOL,
};
use windows::Win32::Storage::FileSystem::{
    CreateFileA, FlushFileBuffers, ReadFile, WriteFile, FILE_ATTRIBUTE_NORMAL, 
    FILE_GENERIC_WRITE, FILE_SHARE_NONE, OPEN_EXISTING, PIPE_ACCESS_DUPLEX,
};
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeA, DisconnectNamedPipe, PIPE_TYPE_BYTE,
    PIPE_UNLIMITED_INSTANCES, PIPE_WAIT, WaitNamedPipeA, PIPE_READMODE_BYTE, 
};

use crate::IOMessage;
use crate::process::ProcessRecord;
use crate::logging::Logging;
// MODIFIED: Import ActionsOnKill and the new ThreatInfo struct
// (Assuming this import is or should be present for the original code to work)
use crate::actions_on_kill::{ActionsOnKill, ThreatInfo};


// --- Pipe names (single source of truth) ---
const PIPE_AV_TO_EDR: &str = r"\\.\pipe\Global\hydradragon_to_owlyshield";
const PIPE_EDR_TO_AV: &str = r"\\.\pipe\Global\owlyshield_to_hydradragon";

const BUFFER_SIZE: u32 = 8192;
const CONNECT_TIMEOUT_MS: u32 = 900_000; // 900s - adjust as needed

/// Action to take when a threat is detected
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub enum ThreatAction {
    #[serde(rename = "kill_and_quarantine")]
    KillAndQuarantine,
    #[serde(rename = "kill_only")]
    KillOnly,
}

impl Default for ThreatAction {
    fn default() -> Self {
        ThreatAction::KillAndQuarantine
    }
}

impl ThreatAction {
    pub fn as_str(&self) -> &str {
        match self {
            ThreatAction::KillAndQuarantine => "kill_and_quarantine",
            ThreatAction::KillOnly => "kill_only",
        }
    }
}

/// AV -> EDR event
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AVThreatEvent {
    pub timestamp: String,
    pub file_path: String,
    pub virus_name: String,
    pub is_malicious: bool,
    pub detection_type: String,
    #[serde(default)]
    pub action_required: ThreatAction,
    #[serde(default)]
    pub pid: Option<u32>,
    #[serde(default)]
    pub gid: Option<u64>,
}

/// EDR -> AV request
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

/// AV scan response (sent to EDR as a threat event)
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AVScanResponse {
    pub file_path: String,
    pub is_malicious: bool,
    pub virus_name: Option<String>,
    pub scan_timestamp: String,
}

/// Integration struct — keeps internal channel & listener thread
pub struct AVIntegration {
    scan_request_rx: Receiver<EDRScanRequest>,
    internal_scan_tx: Sender<EDRScanRequest>,
    _scan_request_handle: thread::JoinHandle<()>,
}

// NOTE: The following methods are assumed to be part of `impl AVIntegration`
impl AVIntegration {
    /// Process a single threat event according to its configured action
    pub fn process_threat_action(
        &self,
        event: &AVThreatEvent,
        precord: &ProcessRecord,
        prediction_behavioural: f32,
    ) {
        // --- MODIFIED: Common logic to create ThreatInfo ---
        
        // Helper logic to determine threat label
        let threat_label = if event.detection_type.to_lowercase().contains("pua") || event.virus_name.to_lowercase().contains("pua") {
            "Potentially Unwanted Application"
        } else if event.detection_type.to_lowercase().contains("ransom") || event.virus_name.to_lowercase().contains("ransom") {
            "Ransomware"
        } else {
            "Malware" // Default to "Malware" for other detections
        };

        // Create the detailed ThreatInfo struct
        let threat_info = ThreatInfo {
            threat_type_label: threat_label,
            // Use virus_name, or detection_type if virus_name is empty
            virus_name: if event.virus_name.is_empty() { &event.detection_type } else { &event.virus_name },
            prediction: prediction_behavioural, // Use the behavioural score as certainty
        };
        // --- End of modified logic ---

        match event.action_required {
            ThreatAction::KillOnly => {
                Logging::info(&format!(
                    "⚠️ Threat detected [{}] - KillOnly: {}",
                    event.virus_name, event.file_path
                ));

                // Run post-kill actions (driver kill happens via Connectors inside ActionsOnKill)
                // MODIFIED: Call the new function with the detailed info
                ActionsOnKill::new().run_actions_with_info(
                    &self.config,
                    precord,
                    &self.predictor_malware.predictor_behavioural.mlp.timesteps,
                    &threat_info, // Pass the new struct
                );
            }

            ThreatAction::KillAndQuarantine => {
                Logging::info(&format!(
                    "⚠️ Threat detected [{}] - KillAndQuarantine: {}",
                    event.virus_name, event.file_path
                ));

                // Run post-kill actions (driver kill happens via Connectors inside ActionsOnKill)
                // MODIFIED: Call the new function with the detailed info
                ActionsOnKill::new().run_actions_with_info(
                    &self.config,
                    precord,
                    &self.predictor_malware.predictor_behavioural.mlp.timesteps,
                    &threat_info, // Pass the new struct
                );
            }

            _ => {
                Logging::debug(&format!(
                    "No kill or removal required for [{}]",
                    event.file_path
                ));
            }
        }
    }

    /// Main loop to handle queued threat events
    pub fn handle_event_loop(&self) {
        loop {
            if let Some(event) = self.event_queue.lock().unwrap().pop_front() {
                // Compute behavioural prediction
                let prediction_behavioural = self
                    .predictor_malware
                    .predictor_behavioural
                    .mlp
                    .predict(&event.features);

                // Build process record for reporting
                let precord = ProcessRecord::from_event(&event);

                // Execute threat action
                self.process_threat_action(&event, &precord, prediction_behavioural);
            }

            std::thread::sleep(std::time::Duration::from_millis(250));
        }
    }
}

/// AV -> EDR client (one-shot): connect to AV->EDR pipe and write threat event
fn send_threat_to_edr(event: AVThreatEvent) -> Result<(), String> {
    unsafe {
        let pipe_name_c =
            CString::new(PIPE_AV_TO_EDR).map_err(|e| format!("Invalid pipe name: {}", e))?;
        let pcstr = PCSTR(pipe_name_c.as_ptr() as *const u8);

        // Wait for the pipe to become available up to your timeout
        let wait_ok: BOOL =
            WaitNamedPipeA(pcstr, CONNECT_TIMEOUT_MS);
        if !wait_ok.as_bool() {
            let err = GetLastError();
            Logging::error(&format!(
                "Timed out waiting for EDR pipe '{}' ({} ms). GetLastError={:?}",
                PIPE_AV_TO_EDR, CONNECT_TIMEOUT_MS, err
            ));
            return Err(format!(
                "Timed out waiting for EDR pipe '{}' ({} ms). GetLastError={:?}",
                PIPE_AV_TO_EDR, CONNECT_TIMEOUT_MS, err
            ));
        }

        // CreateFileA returns Result<HANDLE, Error> — unwrap first
        let pipe_handle = match CreateFileA(
            pcstr,
            FILE_GENERIC_WRITE.0,
            FILE_SHARE_NONE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            HANDLE::default(),
        ) {
            Ok(h) => h,
            Err(e) => {
                let last = GetLastError();
                Logging::error(&format!(
                    "Failed to connect to EDR pipe (CreateFileA error: {:?}, GetLastError={:?})",
                    e, last
                ));
                return Err(format!(
                    "Failed to connect to EDR pipe (CreateFileA error: {:?}, GetLastError={:?})",
                    e, last
                ));
            }
        };

        if pipe_handle.is_invalid() {
            let last = GetLastError();
            Logging::error(&format!(
                "CreateFileA returned invalid handle. GetLastError={:?}",
                last
            ));
            return Err(format!("CreateFileA returned invalid handle: {:?}", last));
        }

        // serialize -> write
        let message = serde_json::to_string(&event).map_err(|e| {
            Logging::error(&format!("serialize error: {}", e));
            format!("serialize error: {}", e)
        })?;
        let message_bytes: &[u8] = message.as_bytes();

        let mut bytes_written: u32 = 0;
        // windows::Win32::Storage::FileSystem::WriteFile expects:
        //   (hfile, Option<&[u8]>, Option<*mut u32>, Option<*mut OVERLAPPED>)
        let ok: BOOL = WriteFile(
            pipe_handle,
            Some(message_bytes),
            Some(&mut bytes_written as *mut u32),
            None,
        );

        let _ = FlushFileBuffers(pipe_handle);
        let _ = CloseHandle(pipe_handle);

        if !ok.as_bool() {
            Logging::error("Failed to write to EDR pipe (WriteFile returned false)");
            return Err("Failed to write to EDR pipe".to_string());
        }

        Logging::info(&format!(
            "Successfully sent threat event to EDR: {} - {} [{}] ({} bytes)",
            event.file_path, event.virus_name, event.action_required.as_str(), bytes_written
        ));
        Ok(())
    }
}

/// Read & parse a single request from a connected pipe handle
fn read_scan_request(pipe_handle: HANDLE) -> Option<EDRScanRequest> {
    unsafe {
        let mut buffer = vec![0u8; BUFFER_SIZE as usize];
        let mut bytes_read: u32 = 0;

        // Fix 4: Better error handling and logging
        let result: BOOL = ReadFile(
            pipe_handle,
            Some(buffer.as_mut_ptr() as *mut _),
            buffer.len() as u32,
            Some(&mut bytes_read as *mut u32),
            None,
        );

        if !result.as_bool() {
            let err = GetLastError();
            Logging::error(&format!("ReadFile failed: {:?}", err));
            return None;
        }

        if bytes_read == 0 {
            Logging::warning("ReadFile returned 0 bytes");
            return None;
        }

        Logging::info(&format!("Read {} bytes from pipe", bytes_read));

        // Fix 5: Show preview of raw bytes for debugging
        let preview_len = std::cmp::min(bytes_read as usize, 100);
        Logging::info(&format!(
            "Raw bytes preview: {:?}", 
            &buffer[..preview_len]
        ));

        let data = match std::str::from_utf8(&buffer[..bytes_read as usize]) {
            Ok(s) => s,
            Err(e) => {
                Logging::error(&format!("Invalid UTF-8 in scan request: {}", e));
                Logging::error(&format!("Bytes: {:?}", &buffer[..bytes_read as usize]));
                return None;
            }
        };

        Logging::info(&format!("Received data: {}", data));

        match serde_json::from_str::<EDRScanRequest>(data) {
            Ok(request) => {
                Logging::info(&format!(
                    "Successfully parsed scan request for: {}", 
                    request.file_path
                ));
                Some(request)
            }
            Err(e) => {
                Logging::error(&format!("Failed to parse scan request JSON: {}", e));
                Logging::error(&format!("Data received: {}", data));
                None
            }
        }
    }
}

/// AV server: persistent listener for EDR -> AV requests
fn scan_request_server_loop(tx: Sender<EDRScanRequest>) {
    Logging::info(&format!("Starting pipe server: {}", PIPE_EDR_TO_AV));

    unsafe {
        let pipe_name_c = match CString::new(PIPE_EDR_TO_AV) {
            Ok(s) => s,
            Err(e) => {
                Logging::error(&format!("Invalid pipe name: {}", e));
                return;
            }
        };

        loop {
            // Fix 2: Use BYTE mode to match Python side
            let pipe_handle = match CreateNamedPipeA(
                PCSTR(pipe_name_c.as_ptr() as *const u8),
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,  // Changed to BYTE mode
                PIPE_UNLIMITED_INSTANCES,
                BUFFER_SIZE,
                BUFFER_SIZE,
                0,
                None,
            ) {
                Ok(h) => h,
                Err(e) => {
                    Logging::error(&format!("CreateNamedPipeA failed: {:?}", e));
                    thread::sleep(Duration::from_secs(1));
                    continue;
                }
            };

            if pipe_handle.is_invalid() {
                let err = GetLastError();
                Logging::error(&format!("CreateNamedPipeA returned invalid handle: {:?}", err));
                thread::sleep(Duration::from_secs(1));
                continue;
            }

            Logging::info("Waiting for EDR client to connect...");

            // ConnectNamedPipe with blocking mode (None for OVERLAPPED param)
            let connect_ok: BOOL = ConnectNamedPipe(pipe_handle, None);
            let err = GetLastError();

            // Fix 3: Add detailed logging
            Logging::info(&format!(
                "ConnectNamedPipe result: ok={}, error={:?}", 
                connect_ok.as_bool(), 
                err
            ));

            if connect_ok.as_bool() || err == ERROR_PIPE_CONNECTED {
                Logging::info("EDR client connected!");

                // Read & parse request
                if let Some(request) = read_scan_request(pipe_handle) {
                    if let Err(e) = tx.send(request) {
                        Logging::error(&format!("Failed to forward scan request: {}", e));
                    }
                } else {
                    Logging::warning("Failed to read scan request from connected client");
                }

                let _ = DisconnectNamedPipe(pipe_handle);
            } else {
                Logging::error(&format!("ConnectNamedPipe failed: {:?}", err));
            }

            let _ = CloseHandle(pipe_handle);
            thread::sleep(Duration::from_millis(50));
        }
    }
}
