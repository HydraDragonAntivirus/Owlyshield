use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{PathBuf};
use std::collections::{HashMap, HashSet};
use chrono::{DateTime, Utc, Duration};
use md5::{Md5, Digest};

use crate::shared_def::{IOMessage, IrpMajorOp, DriveType};
use crate::process::ProcessRecord;

#[derive(Serialize, Deserialize)]
pub struct FileEventForAV {
    pub timestamp: DateTime<Utc>,
    pub event_type: String,
    pub file_path: String,
    pub process_name: String,
    pub process_id: u32,
    pub gid: u64,
    pub file_size: Option<i64>,
    pub entropy: Option<f64>,
    pub bytes_transferred: Option<u64>,
    pub extension: Option<String>,
    pub drive_type: Option<String>,
    pub metadata: EventMetadata,
    pub file_hash: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct EventMetadata {
    pub entropy_calculated: bool,
    pub file_exists: bool,
    pub operation_count: u64,
    pub directories_affected: Vec<String>,
}

pub struct AVIntegration {
    output_path: PathBuf,
    batch_size: usize,
    pending_events: Vec<FileEventForAV>,
    // Track file path -> hash mapping for modification detection
    file_hashes: HashMap<String, String>,
    // Track unique event signatures to prevent exact duplicates
    seen_events: HashSet<String>,
    // Track last cache clear time
    last_cache_clear: DateTime<Utc>,
}

impl AVIntegration {
    pub fn new(output_path: PathBuf, batch_size: usize) -> Self {
        Self {
            output_path,
            batch_size,
            pending_events: Vec::new(),
            file_hashes: HashMap::new(),
            seen_events: HashSet::new(),
            last_cache_clear: Utc::now(),
        }
    }

    pub fn queue_file_event(&mut self, iomsg: &IOMessage, process_record: &ProcessRecord) {
        // Check if an hour has passed and clear cache if needed
        self.check_and_clear_cache();
        
        let event_type = IrpMajorOp::from_byte(iomsg.irp_op);
        
        // Check for Sandbox-related paths that start with C: and contain Sandbox
        let is_sandbox_related = iomsg.filepathstr.starts_with("C:") && 
                                 iomsg.filepathstr.contains("Sandbox");

        // Only process the event if it's related to Sandbox
        if !is_sandbox_related {
            return;
        }

        // Calculate MD5 hash if file content is available
        let file_hash = self.calculate_file_hash(&iomsg.filepathstr);
        
        // Check if this is a duplicate event
        if self.is_duplicate_event(iomsg, &file_hash, &event_type) {
            return;
        }

        // Create the event object
        let mut event = self.create_file_event(iomsg, process_record, event_type);
        event.file_hash = file_hash.clone();

        // Update tracking structures
        if let Some(hash) = &file_hash {
            self.file_hashes.insert(iomsg.filepathstr.clone(), hash.clone());
        }
        
        // Add event signature to seen events
        let event_signature = self.create_event_signature(iomsg, &file_hash);
        self.seen_events.insert(event_signature);

        self.pending_events.push(event);

        // Flush the event batch if the size limit is reached.
        if self.pending_events.len() >= self.batch_size {
            self.flush_events();
        }
    }

    fn calculate_file_hash(&self, file_path: &str) -> Option<String> {
        // Attempt to read and hash the file
        match std::fs::read(file_path) {
            Ok(contents) => {
                let mut hasher = Md5::new();
                hasher.update(&contents);
                let result = hasher.finalize();
                Some(format!("{:x}", result))
            }
            Err(_) => None, // File might not exist or be accessible
        }
    }

    fn is_duplicate_event(&self, iomsg: &IOMessage, file_hash: &Option<String>, event_type: &IrpMajorOp) -> bool {
        let file_path = &iomsg.filepathstr;
        
        // For write/modify operations, ONLY check if the file hash is the same
        // This ensures we send the file again if it was actually modified
        if matches!(event_type, IrpMajorOp::IrpWrite | IrpMajorOp::IrpSetInfo) {
            if let Some(hash) = file_hash {
                // Check if we've seen this exact file path with this exact hash before
                if let Some(stored_hash) = self.file_hashes.get(file_path) {
                    if stored_hash == hash {
                        return true; // Same file, same content - duplicate write
                    }
                }
                // Different hash or new file - NOT a duplicate, send it!
                return false;
            }
            // No hash available (file might not exist yet during create) - not a duplicate
            return false;
        }
        
        // For create operations, check if this exact path+hash combo was seen
        if matches!(event_type, IrpMajorOp::IrpCreate) {
            if let Some(hash) = file_hash {
                if let Some(stored_hash) = self.file_hashes.get(file_path) {
                    if stored_hash == hash {
                        return true; // Same file created with same content - duplicate
                    }
                }
                return false; // New file or different content - send it
            }
            return false; // No hash, send it
        }
        
        // For read operations, we DON'T want to suppress duplicates completely
        // because different processes might read the same file and we want to track that
        // So we only suppress if it's the EXACT same process reading the EXACT same file
        if matches!(event_type, IrpMajorOp::IrpRead) {
            let event_signature = self.create_event_signature(iomsg, file_hash);
            return self.seen_events.contains(&event_signature);
        }
        
        false
    }

    fn create_event_signature(&self, iomsg: &IOMessage, file_hash: &Option<String>) -> String {
        // Create a unique signature combining key event attributes
        format!(
            "{}:{}:{}:{}",
            iomsg.filepathstr,
            iomsg.irp_op,
            iomsg.pid,
            file_hash.as_ref().unwrap_or(&String::from("none"))
        )
    }

    fn create_file_event(&self, iomsg: &IOMessage, process_record: &ProcessRecord, event_type: IrpMajorOp) -> FileEventForAV {
        let event_type_str = match event_type {
            IrpMajorOp::IrpRead => "file_read",
            IrpMajorOp::IrpWrite => "file_write",
            IrpMajorOp::IrpCreate => "file_create",
            IrpMajorOp::IrpSetInfo => "file_modify",
            _ => "file_other",
        }.to_string();

        FileEventForAV {
            timestamp: Utc::now(),
            event_type: event_type_str,
            file_path: iomsg.filepathstr.clone(),
            process_name: process_record.appname.clone(),
            process_id: iomsg.pid,
            gid: iomsg.gid,
            file_size: if iomsg.file_size >= 0 { Some(iomsg.file_size) } else { None },
            entropy: if iomsg.is_entropy_calc == 1 { Some(iomsg.entropy) } else { None },
            bytes_transferred: if iomsg.mem_sized_used > 0 { Some(iomsg.mem_sized_used) } else { None },
            extension: if !iomsg.extension.trim_end_matches('\0').is_empty() { 
                Some(iomsg.extension.trim_end_matches('\0').to_string()) 
            } else { 
                None 
            },
            drive_type: Some(format!("{:?}", DriveType::from_filepath(iomsg.filepathstr.clone()))),
            file_hash: None, // Will be set by queue_file_event
            metadata: EventMetadata {
                entropy_calculated: iomsg.is_entropy_calc == 1,
                file_exists: iomsg.runtime_features.exe_still_exists,
                operation_count: process_record.driver_msg_count as u64,
                directories_affected: process_record.dirs_with_files_updated.iter().cloned().collect(),
            },
        }
    }

    pub fn flush_events(&mut self) {
        if self.pending_events.is_empty() {
            return;
        }

        match self.write_events_to_file() {
            Ok(_) => {
                self.pending_events.clear();
            }
            Err(e) => {
                eprintln!("Failed to write events to file: {}", e);
            }
        }
    }

    fn write_events_to_file(&self) -> std::io::Result<()> {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.output_path)?;

        for event in &self.pending_events {
            let json_line = serde_json::to_string(event)?;
            writeln!(file, "{}", json_line)?;
        }

        file.sync_all()?;
        Ok(())
    }

    // Call this periodically or on shutdown
    pub fn force_flush(&mut self) {
        self.flush_events();
    }

    // Clear tracking data to prevent unbounded memory growth
    pub fn clear_tracking_cache(&mut self) {
        self.file_hashes.clear();
        self.seen_events.clear();
        self.last_cache_clear = Utc::now();
    }

    // Check if an hour has passed and clear cache automatically
    fn check_and_clear_cache(&mut self) {
        let now = Utc::now();
        let elapsed = now.signed_duration_since(self.last_cache_clear);
        
        // Clear cache if more than 1 hour has passed
        if elapsed >= Duration::hours(1) {
            self.clear_tracking_cache();
        }
    }
}
