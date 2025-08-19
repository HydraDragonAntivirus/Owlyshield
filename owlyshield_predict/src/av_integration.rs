use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use chrono::{DateTime, Utc};
use std::env;

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
}

impl AVIntegration {
    pub fn new(output_path: PathBuf, batch_size: usize) -> Self {
        Self {
            output_path,
            batch_size,
            pending_events: Vec::new(),
        }
    }

    pub fn queue_file_event(&mut self, iomsg: &IOMessage, process_record: &ProcessRecord) {
        let event_type = IrpMajorOp::from_byte(iomsg.irp_op);
        // Create the event object first, before any filtering logic.
        let event = self.create_file_event(iomsg, process_record, event_type);

        let is_write_op = matches!(event_type, IrpMajorOp::IrpWrite | IrpMajorOp::IrpSetInfo | IrpMajorOp::IrpCreate);

        // For write operations, check if the event's content is related to the sandbox.
        if is_write_op {
            let system_drive = env::var("SystemDrive").unwrap_or_else(|_| "C:".to_string());
            let username = env::var("USERNAME").unwrap_or_else(|_| "default".to_string());
            
            // Construct the sandbox path to check against.
            let sandbox_path = Path::new(&system_drive)
                .join("Sandbox")
                .join(username)
                .join("DefaultBox");
            
            // Perform a case-insensitive search for the sandbox path string.
            let sandbox_path_str = sandbox_path.to_string_lossy().to_lowercase();

            // Check multiple fields in the created event to see if they contain the sandbox path.
            let is_sandbox_related = event.file_path.to_lowercase().starts_with(&sandbox_path_str) ||
                                     event.metadata.directories_affected.iter().any(|dir| dir.to_lowercase().starts_with(&sandbox_path_str));

            // Only queue the event if it's related to the sandbox.
            if is_sandbox_related {
                self.pending_events.push(event);
            }
        } else {
            // For non-write events, queue them unconditionally.
            self.pending_events.push(event);
        }

        // Flush the event batch if the size limit is reached.
        if self.pending_events.len() >= self.batch_size {
            self.flush_events();
        }
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
}
