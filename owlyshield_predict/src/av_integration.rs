
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use chrono::{DateTime, Utc};

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
    pub is_suspicious: bool,
    pub metadata: EventMetadata,
}

#[derive(Serialize, Deserialize)]
pub struct EventMetadata {
    pub entropy_calculated: bool,
    pub file_exists: bool,
    pub operation_count: u64,
    pub directories_affected: Vec<String>,
    pub risk_indicators: Vec<String>,
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
        let event = self.create_file_event(iomsg, process_record);
        self.pending_events.push(event);

        if self.pending_events.len() >= self.batch_size {
            self.flush_events();
        }
    }

    fn create_file_event(&self, iomsg: &IOMessage, process_record: &ProcessRecord) -> FileEventForAV {
        let event_type = match IrpMajorOp::from_byte(iomsg.irp_op) {
            IrpMajorOp::IrpRead => "file_read",
            IrpMajorOp::IrpWrite => "file_write",
            IrpMajorOp::IrpCreate => "file_create",
            IrpMajorOp::IrpSetInfo => "file_modify",
            _ => "file_other",
        }.to_string();

        // Determine if this event looks suspicious
        let is_suspicious = self.assess_suspicion(iomsg, process_record);
        
        let risk_indicators = self.get_risk_indicators(iomsg, process_record);

        FileEventForAV {
            timestamp: Utc::now(),
            event_type,
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
            is_suspicious,
            metadata: EventMetadata {
                entropy_calculated: iomsg.is_entropy_calc == 1,
                file_exists: iomsg.runtime_features.exe_still_exists,
                operation_count: process_record.driver_msg_count as u64,
                directories_affected: process_record.dirs_with_files_updated.iter().cloned().collect(),
                risk_indicators,
            },
        }
    }

    fn assess_suspicion(&self, iomsg: &IOMessage, process_record: &ProcessRecord) -> bool {
        // High entropy writes
        if iomsg.entropy > 7.5 && iomsg.irp_op == 2 { // IrpWrite
            return true;
        }

        // Rapid file operations
        if process_record.driver_msg_count > 1000 && 
           process_record.time_started.elapsed().unwrap_or_default().as_secs() < 60 {
            return true;
        }

        // Operations on removable/remote drives
        match DriveType::from_filepath(iomsg.filepathstr.clone()) {
            DriveType::Removable | DriveType::Remote | DriveType::CDRom => return true,
            _ => {}
        }

        // Many different directories affected
        if process_record.dirs_with_files_updated.len() > 50 {
            return true;
        }

        false
    }

    fn get_risk_indicators(&self, iomsg: &IOMessage, process_record: &ProcessRecord) -> Vec<String> {
        let mut indicators = Vec::new();

        if iomsg.entropy > 7.5 {
            indicators.push("high_entropy".to_string());
        }

        if process_record.dirs_with_files_updated.len() > 20 {
            indicators.push("many_directories".to_string());
        }

        if process_record.files_deleted.len() > 10 {
            indicators.push("many_deletions".to_string());
        }

        if process_record.files_renamed.len() > 5 {
            indicators.push("many_renames".to_string());
        }

        match DriveType::from_filepath(iomsg.filepathstr.clone()) {
            DriveType::Removable => indicators.push("removable_drive".to_string()),
            DriveType::Remote => indicators.push("network_drive".to_string()),
            _ => {}
        }

        // Check for executable extensions in unexpected locations
        if iomsg.extension.trim_end_matches('\0') == "exe" && 
           (iomsg.filepathstr.contains("AppData") || iomsg.filepathstr.contains("Temp")) {
            indicators.push("suspicious_exe_location".to_string());
        }

        indicators
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
                // Keep events in buffer for retry
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