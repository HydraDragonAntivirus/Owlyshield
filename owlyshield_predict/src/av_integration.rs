#![cfg(feature = "hydradragon")]

use std::ffi::CString;
use std::sync::mpsc::{channel, Receiver, Sender, TryRecvError};
use std::thread;
use std::time::Duration;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use windows::core::PCSTR;

use windows::Win32::Foundation::{
    CloseHandle, GetLastError, HANDLE, ERROR_PIPE_CONNECTED, BOOL, ERROR_IO_PENDING, WAIT_OBJECT_0,
    WAIT_TIMEOUT,
};
use windows::Win32::Storage::FileSystem::{
    CreateFileA, FlushFileBuffers, ReadFile, WriteFile, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_WRITE,
    FILE_SHARE_NONE, OPEN_EXISTING, PIPE_ACCESS_DUPLEX, FILE_FLAG_OVERLAPPED, FILE_FLAGS_AND_ATTRIBUTES,
};
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeA, DisconnectNamedPipe, PIPE_READMODE_MESSAGE, PIPE_TYPE_MESSAGE,
    PIPE_UNLIMITED_INSTANCES, PIPE_WAIT, NAMED_PIPE_MODE,
};
use windows::Win32::System::IO::OVERLAPPED;
use windows::Win32::System::Threading::{CreateEventA, WaitForSingleObject};

use crate::IOMessage;
use crate::process::ProcessRecord;
use crate::logging::Logging;

// --- Pipe names (single source of truth) ---
const PIPE_AV_TO_EDR: &str = r"\\.\pipe\Global\hydradragon_to_owlyshield";
const PIPE_EDR_TO_AV: &str = r"\\.\pipe\Global\owlyshield_to_hydradragon";

const BUFFER_SIZE: u32 = 8192;
const CONNECT_TIMEOUT_MS: u32 = 30_000; // 30s - adjust as needed

/// AV -> EDR event
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

impl AVIntegration {
    pub fn new() -> Self {
        let (scan_tx, scan_rx) = channel();
        let internal_tx = scan_tx.clone();

        // Server thread: persistent listener for EDR -> AV requests
        let scan_handle = thread::spawn(move || {
            scan_request_server_loop(scan_tx);
        });

        AVIntegration {
            scan_request_rx: scan_rx,
            internal_scan_tx: internal_tx,
            _scan_request_handle: scan_handle,
        }
    }

    pub fn send_threat_event(&self, event: AVThreatEvent) -> Result<(), String> {
        send_threat_to_edr(event)
    }

    pub fn poll_scan_requests(&mut self) -> Vec<EDRScanRequest> {
        let mut requests = Vec::new();
        loop {
            match self.scan_request_rx.try_recv() {
                Ok(request) => {
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

    pub fn send_scan_response(&self, response: AVScanResponse) -> Result<(), String> {
        // repackage as threat event and send to EDR (client role)
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

    /// Called by kernel/event handling to queue internal requests (no external client)
    pub fn queue_file_event(&mut self, iomsg: &IOMessage, precord: &ProcessRecord) {
        let request = EDRScanRequest {
            event_type: "NEW_IO_EVENT".to_string(),
            file_path: precord.exepath.to_string_lossy().to_string(),
            timestamp: Utc::now().to_rfc3339(),
            pid: Some(iomsg.pid),
            additional_context: Some(format!("Event triggered by GID: {}", precord.gid)),
        };

        if let Err(e) = self.internal_scan_tx.send(request) {
            Logging::error(&format!("Failed to send internal scan request: {}", e));
        }
    }
}

/// AV -> EDR client (one-shot): connect to AV->EDR pipe and write threat event
fn send_threat_to_edr(mut event: AVThreatEvent) -> Result<(), String> {
    unsafe {
        let pipe_name_c = CString::new(PIPE_AV_TO_EDR).map_err(|e| format!("Invalid pipe name: {}", e))?;
        event.action_required = "kill_and_remove".to_string();

        // NOTE: pass the underlying .0 integer for FILE_GENERIC_WRITE
        let pipe_handle_res = CreateFileA(
            PCSTR(pipe_name_c.as_ptr() as *const u8),
            FILE_GENERIC_WRITE.0, // <-- use .0 here
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

        // serialize -> write
        let message = serde_json::to_string(&event).map_err(|e| {
            Logging::error(&format!("serialize error: {}", e));
            format!("serialize error: {}", e)
        })?;
        let message_bytes = message.as_bytes();

        let mut bytes_written = 0u32;
        let ok = WriteFile(pipe_handle, Some(message_bytes), Some(&mut bytes_written), None);

        let _ = FlushFileBuffers(pipe_handle);
        let _ = CloseHandle(pipe_handle);

        if !ok.as_bool() {
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

/// AV server: persistent listener for EDR -> AV scan requests
/// NOTE: This is the single authoritative server for PIPE_EDR_TO_AV.
/// The EDR process must be the client that opens that pipe (CreateFileA).
fn scan_request_server_loop(tx: Sender<EDRScanRequest>) {
    Logging::novelty(&format!("Starting scan request listener: {}", PIPE_EDR_TO_AV));

    fn handle_connection(pipe_handle: HANDLE, tx: &Sender<EDRScanRequest>) {
        if let Some(request) = read_scan_request(pipe_handle) {
            if let Err(e) = tx.send(request) {
                Logging::error(&format!("Failed to forward scan request: {}", e));
            }
        }
        unsafe {
            let _ = FlushFileBuffers(pipe_handle);
            let _ = DisconnectNamedPipe(pipe_handle);
            let _ = CloseHandle(pipe_handle);
        }
    }

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

            // Build open-mode bits and wrap into expected FILE_FLAGS_AND_ATTRIBUTES
            let open_mode_bits: u32 = PIPE_ACCESS_DUPLEX.0 | FILE_FLAG_OVERLAPPED.0 as u32;
            let open_mode = FILE_FLAGS_AND_ATTRIBUTES(open_mode_bits);

            let pipe_mode = NAMED_PIPE_MODE(PIPE_TYPE_MESSAGE.0 | PIPE_READMODE_MESSAGE.0 | PIPE_WAIT.0);

            // Create the named pipe (server)
            let pipe_handle = match CreateNamedPipeA(
                pcstr,
                open_mode,
                pipe_mode,
                PIPE_UNLIMITED_INSTANCES,
                BUFFER_SIZE,
                BUFFER_SIZE,
                0,
                None,
            ) {
                Ok(h) => h,
                Err(e) => {
                    Logging::error(&format!("CreateNamedPipeA failed: {:?}, GetLastError={:?}", e, GetLastError()));
                    thread::sleep(Duration::from_secs(5));
                    continue;
                }
            };

            // Create event for overlapped ConnectNamedPipe
            let event = match CreateEventA(None, BOOL(0), BOOL(0), None) {
                Ok(h) => h,
                Err(e) => {
                    Logging::error(&format!("CreateEventA failed: {:?}", e));
                    let _ = CloseHandle(pipe_handle);
                    thread::sleep(Duration::from_millis(100));
                    continue;
                }
            };

            if event.is_invalid() {
                Logging::error("CreateEventA returned invalid handle");
                let _ = CloseHandle(pipe_handle);
                thread::sleep(Duration::from_millis(100));
                continue;
            }

            // Setup overlapped and use overlapped ConnectNamedPipe
            let mut overlapped: OVERLAPPED = std::mem::zeroed();
            overlapped.hEvent = event;

            let connect_ok: BOOL = ConnectNamedPipe(pipe_handle, Some(&mut overlapped as *mut _));

            if connect_ok.as_bool() {
                // immediate connection (rare)
                handle_connection(pipe_handle, &tx);
            } else {
                let err = GetLastError();
                if err == ERROR_IO_PENDING {
                    // Wait for event with timeout
                    let wait_res = WaitForSingleObject(event, CONNECT_TIMEOUT_MS);
                    if wait_res == WAIT_OBJECT_0 {
                        // connected
                        handle_connection(pipe_handle, &tx);
                    } else if wait_res == WAIT_TIMEOUT {
                        Logging::warning("ConnectNamedPipe timed out waiting for client; disconnecting and retrying");
                        let _ = DisconnectNamedPipe(pipe_handle);
                        let _ = CloseHandle(pipe_handle);
                    } else {
                        Logging::error(&format!("WaitForSingleObject unexpected: {:?}", wait_res));
                        let _ = DisconnectNamedPipe(pipe_handle);
                        let _ = CloseHandle(pipe_handle);
                    }
                } else if err == ERROR_PIPE_CONNECTED {
                    // client connected between CreateNamedPipe and ConnectNamedPipe
                    handle_connection(pipe_handle, &tx);
                } else {
                    Logging::error(&format!("ConnectNamedPipe failed: {:?}", err));
                    let _ = CloseHandle(pipe_handle);
                }
            }

            // cleanup
            let _ = CloseHandle(event);
        } // end unsafe

        // small throttle to avoid busy looping if something is broken
        thread::sleep(Duration::from_millis(10));
    } // end loop
}

/// Read & parse a single request from a connected pipe handle
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
