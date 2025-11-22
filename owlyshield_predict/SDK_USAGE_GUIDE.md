# OwlyShield SDK Usage Guide

## Complete Guide for Behavioral Analysis and Machine Learning Data Collection

This guide explains how to use the OwlyShield SDK for dynamic malware detection and ML model training.

## Table of Contents

1. [Overview](#overview)
2. [Basic Setup](#basic-setup)
3. [Detecting Malware Behaviors](#detecting-malware-behaviors)
4. [Machine Learning Data Collection](#machine-learning-data-collection)
5. [Specific Malware Detection Examples](#specific-malware-detection-examples)
6. [Building a Complete EDR Solution](#building-a-complete-edr-solution)

---

## Overview

The OwlyShield SDK provides:

✅ **Behavioral Signature Detection** - Identify malware based on API usage patterns
✅ **Malware Pattern Matching** - Detect specific malware families (RAT, ransomware, etc.)
✅ **ML Data Collection** - Automatically collect training data from running processes
✅ **Real-time Analysis** - Integrate with kernel driver for live threat detection

---

## Basic Setup

### 1. Initialize the SDK

```rust
use owlyshield_ransom::sdk::OwlyShieldSDK;

fn main() {
    // Basic initialization
    let mut sdk = OwlyShieldSDK::new(
        false,  // ML collection mode (false = disabled)
        "models/malapi.json"  // Path to API definitions
    );

    println!("OwlyShield SDK initialized!");
}
```

### 2. Process Kernel Driver Messages

```rust
use owlyshield_ransom::shared_def::IOMessage;
use owlyshield_ransom::process::ProcessRecord;

fn process_kernel_message(
    sdk: &mut OwlyShieldSDK,
    io_msg: &IOMessage,
    process_record: &ProcessRecord
) {
    // SDK analyzes the message and returns true if malicious
    let is_malicious = sdk.process_message(io_msg, process_record);

    if is_malicious {
        println!("⚠️ Threat detected in process: {}", process_record.appname);

        // Get detailed analysis
        if let Some(analysis) = sdk.get_analysis(io_msg.gid) {
            println!("Threat Level: {:?}", analysis.threat_level);

            for sig in &analysis.signatures_matched {
                println!("  [{}] {}", sig.threat_level, sig.signature_name);
                println!("  Confidence: {:.1}%", sig.confidence * 100.0);
            }
        }
    }
}
```

---

## Detecting Malware Behaviors

### Example 1: Detecting RAT (Remote Access Trojan)

A RAT typically exhibits:
- **Keylogging** (GetAsyncKeyState, SetWindowsHookExA)
- **Network communication** (WSAStartup, Connect, Send, Recv)
- **Process injection** (VirtualAllocEx, WriteProcessMemory, CreateRemoteThread)

```rust
fn detect_rat_behavior(sdk: &mut OwlyShieldSDK, gid: u64) {
    if let Some(analysis) = sdk.get_analysis(gid) {
        // Check for RAT pattern
        if analysis.patterns_matched.contains(&PatternType::RAT) {
            println!("🚨 RAT DETECTED!");
            println!("  Process: {}", analysis.app_name);

            // Check specific APIs used
            let api_usage = &analysis.api_usage;

            if !api_usage.spying_apis.is_empty() {
                println!("  ⚠ Keylogging APIs detected:");
                for api in &api_usage.spying_apis {
                    println!("    - {}", api);
                }
            }

            if !api_usage.internet_apis.is_empty() {
                println!("  ⚠ Network APIs detected:");
                for api in &api_usage.internet_apis {
                    println!("    - {}", api);
                }
            }

            if !api_usage.injection_apis.is_empty() {
                println!("  ⚠ Injection APIs detected:");
                for api in &api_usage.injection_apis {
                    println!("    - {}", api);
                }
            }

            // Recommended action
            println!("  Action: TERMINATE IMMEDIATELY");
        }
    }
}
```

### Example 2: Detecting Ransomware

Ransomware patterns include:
- **Mass file encryption** (high entropy writes to many files)
- **Crypto APIs** (CryptAcquireContextA, CryptEncrypt, CryptGenRandom)
- **File deletion** (deleting originals after encryption)
- **Network C2 communication**

```rust
fn detect_ransomware(sdk: &mut OwlyShieldSDK, gid: u64) {
    if let Some(analysis) = sdk.get_analysis(gid) {
        // Check for ransomware pattern
        if analysis.patterns_matched.contains(&PatternType::Ransomware) {
            println!("🚨 RANSOMWARE DETECTED!");

            // Get API tracker for detailed stats
            let api_tracker = sdk.api_trackers.get(&gid).unwrap();

            println!("  Files encrypted: {}",
                api_tracker.file_operations.files_encrypted);
            println!("  Files deleted: {}",
                api_tracker.file_operations.files_deleted);
            println!("  Mass operations: {}",
                api_tracker.file_operations.mass_file_operations);

            // List crypto APIs used
            println!("  Crypto APIs used:");
            for api in &api_tracker.ransomware_apis {
                println!("    - {}", api);
            }

            println!("  Action: SUSPEND AND QUARANTINE");
        }
    }
}
```

### Example 3: Detecting Process Injection

```rust
fn detect_injection(sdk: &mut OwlyShieldSDK, gid: u64) {
    if let Some(api_tracker) = sdk.api_trackers.get(&gid) {
        // Check for classic injection sequence
        let has_virtual_alloc = api_tracker.injection_apis.contains("VirtualAllocEx");
        let has_write_memory = api_tracker.injection_apis.contains("WriteProcessMemory");
        let has_create_thread = api_tracker.injection_apis.contains("CreateRemoteThread");

        if has_virtual_alloc && has_write_memory && has_create_thread {
            println!("🚨 PROCESS INJECTION DETECTED!");
            println!("  Classic injection pattern:");
            println!("    1. ✓ VirtualAllocEx (allocate memory in target)");
            println!("    2. ✓ WriteProcessMemory (write code to target)");
            println!("    3. ✓ CreateRemoteThread (execute code in target)");

            // Check API sequence
            if api_tracker.has_api_sequence(&[
                ("VirtualAllocEx".to_string(), "WriteProcessMemory".to_string()),
                ("WriteProcessMemory".to_string(), "CreateRemoteThread".to_string()),
            ]) {
                println!("  ⚠ Injection sequence confirmed!");
            }
        }
    }
}
```

---

## Machine Learning Data Collection

### Step 1: Enable ML Collection Mode

```rust
fn setup_ml_collection() -> OwlyShieldSDK {
    // Initialize with ML collection enabled
    let sdk = OwlyShieldSDK::new(
        true,  // Enable ML collection
        "models/malapi.json"
    );

    // Configure ML collector
    if let Some(collector) = &sdk.ml_collector {
        println!("ML Collection Mode: ACTIVE");
        println!("Output directory: ml_data/");
        println!("Auto-save threshold: 100 samples");
    }

    sdk
}
```

### Step 2: Collect Data from Malicious Applications

```rust
fn collect_malware_samples(sdk: &mut OwlyShieldSDK) {
    println!("=== Collecting Malicious Samples ===");

    // Run known malware in sandbox
    // Process messages from kernel driver
    // SDK automatically collects behavioral data

    loop {
        let io_msg = receive_from_driver();
        let process_record = get_process_record(io_msg.gid);

        // Label as malicious (you know it's malware)
        let is_malicious = true;

        // SDK collects features automatically
        sdk.process_message(&io_msg, &process_record);

        // Manually ensure ML collector knows it's malicious
        if let Some(ref mut collector) = sdk.ml_collector {
            collector.collect_sample(
                &sdk.api_trackers[&io_msg.gid],
                &process_record,
                is_malicious
            );
        }
    }
}
```

### Step 3: Collect Data from Benign Applications

```rust
fn collect_benign_samples(sdk: &mut OwlyShieldSDK) {
    println!("=== Collecting Benign Samples ===");

    // Run normal applications
    // Process messages from kernel driver
    // Label as benign

    loop {
        let io_msg = receive_from_driver();
        let process_record = get_process_record(io_msg.gid);

        // Label as benign
        let is_malicious = false;

        if let Some(ref mut collector) = sdk.ml_collector {
            collector.collect_sample(
                &sdk.api_trackers[&io_msg.gid],
                &process_record,
                is_malicious
            );
        }
    }
}
```

### Step 4: Export Training Data

```rust
fn export_training_data(sdk: &OwlyShieldSDK) {
    if let Some(ref collector) = sdk.ml_collector {
        // Get statistics
        let (malicious_count, benign_count) = collector.get_counts();
        println!("Collected samples:");
        println!("  Malicious: {}", malicious_count);
        println!("  Benign: {}", benign_count);
        println!("  Total: {}", malicious_count + benign_count);

        // Export to JSON (full dataset)
        collector.export_to_json("datasets/full_dataset.json")
            .expect("Failed to export JSON");
        println!("✓ Exported: datasets/full_dataset.json");

        // Export to CSV (for Python/scikit-learn)
        collector.export_to_csv("datasets/full_dataset.csv")
            .expect("Failed to export CSV");
        println!("✓ Exported: datasets/full_dataset.csv");

        // Export separated files
        collector.export_separated(
            "datasets/malicious_only.json",
            "datasets/benign_only.json"
        ).expect("Failed to export separated datasets");
        println!("✓ Exported: datasets/malicious_only.json");
        println!("✓ Exported: datasets/benign_only.json");
    }
}
```

### Step 5: Train ML Model in Python

```python
# train_model.py
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
import joblib

# Load the dataset
print("Loading dataset...")
data = pd.read_csv('datasets/full_dataset.csv')

# Separate features and labels
X = data.drop(['id', 'process_name', 'is_malicious'], axis=1)
y = data['is_malicious']

print(f"Total samples: {len(data)}")
print(f"Malicious: {sum(y)}")
print(f"Benign: {len(y) - sum(y)}")

# Split dataset
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# Train Random Forest model
print("\nTraining Random Forest...")
model = RandomForestClassifier(
    n_estimators=100,
    max_depth=20,
    random_state=42,
    n_jobs=-1
)
model.fit(X_train, y_train)

# Evaluate
print("\nEvaluating model...")
y_pred = model.predict(X_test)
print("\nClassification Report:")
print(classification_report(y_test, y_pred))

print("\nConfusion Matrix:")
print(confusion_matrix(y_test, y_pred))

# Save model
joblib.dump(model, 'models/malware_detector.pkl')
print("\n✓ Model saved: models/malware_detector.pkl")

# Feature importance
feature_importance = pd.DataFrame({
    'feature': X.columns,
    'importance': model.feature_importances_
}).sort_values('importance', ascending=False)

print("\nTop 10 Most Important Features:")
print(feature_importance.head(10))
```

---

## Specific Malware Detection Examples

### RAT Detection Pattern

```rust
// RAT must have: Keylogging + Network + Injection
fn is_rat(api_tracker: &ApiTracker) -> bool {
    let has_keylogging = api_tracker.spying_apis.contains("GetAsyncKeyState") ||
                         api_tracker.spying_apis.contains("SetWindowsHookExA");

    let has_network = api_tracker.internet_apis.contains("WSAStartup") &&
                      api_tracker.internet_apis.contains("Connect");

    let has_injection = api_tracker.injection_apis.contains("VirtualAllocEx") &&
                        api_tracker.injection_apis.contains("WriteProcessMemory");

    has_keylogging && has_network && has_injection
}
```

### Banking Trojan Detection

```rust
// Banking Trojan: Browser hooking + Form grabbing + Exfiltration
fn is_banking_trojan(api_tracker: &ApiTracker) -> bool {
    let has_hooks = api_tracker.spying_apis.contains("SetWindowsHookExA");
    let has_browser_apis = api_tracker.internet_apis.contains("InternetOpenA") ||
                           api_tracker.internet_apis.contains("HttpSendRequestA");
    let has_keylogging = api_tracker.spying_apis.contains("GetAsyncKeyState");

    has_hooks && has_browser_apis && has_keylogging
}
```

### Credential Stealer Detection

```rust
// Credential Stealer: Memory dumping + Process enumeration
fn is_credential_stealer(api_tracker: &ApiTracker) -> bool {
    let has_memory_read = api_tracker.helper_apis.contains("ReadProcessMemory");
    let has_process_enum = api_tracker.enumeration_apis.contains("CreateToolhelp32Snapshot");
    let has_lsass_access = api_tracker.file_operations.executable_files_accessed
        .iter()
        .any(|path| path.to_lowercase().contains("lsass"));

    has_memory_read && has_process_enum && has_lsass_access
}
```

---

## Building a Complete EDR Solution

### Full Integration Example

```rust
use owlyshield_ransom::sdk::{OwlyShieldSDK, ThreatLevel};
use owlyshield_ransom::shared_def::IOMessage;
use std::collections::HashMap;

struct EDRSystem {
    sdk: OwlyShieldSDK,
    process_records: HashMap<u64, ProcessRecord>,
}

impl EDRSystem {
    fn new(ml_enabled: bool) -> Self {
        EDRSystem {
            sdk: OwlyShieldSDK::new(ml_enabled, "models/malapi.json"),
            process_records: HashMap::new(),
        }
    }

    fn start(&mut self) {
        println!("🛡️  OwlyShield EDR Started");
        println!("Monitoring system for threats...\n");

        loop {
            // Receive message from kernel driver
            let io_msg = self.receive_driver_message();

            // Get or create process record
            let process_record = self.process_records
                .entry(io_msg.gid)
                .or_insert_with(|| ProcessRecord::new(
                    io_msg.gid,
                    "process.exe".to_string(),
                    std::path::PathBuf::new()
                ));

            // Analyze with SDK
            let is_malicious = self.sdk.process_message(&io_msg, process_record);

            if is_malicious {
                self.handle_threat(io_msg.gid);
            }
        }
    }

    fn handle_threat(&mut self, gid: u64) {
        if let Some(analysis) = self.sdk.get_analysis(gid) {
            println!("🚨 THREAT DETECTED!");
            println!("  GID: {}", gid);
            println!("  Process: {}", analysis.app_name);
            println!("  Threat Level: {:?}", analysis.threat_level);
            println!();

            // Display signatures
            for sig in &analysis.signatures_matched {
                println!("  [{}] {}", sig.threat_level, sig.signature_name);
                println!("  {}", sig.description);
                println!("  Confidence: {:.1}%", sig.confidence * 100.0);
                println!();
            }

            // Display malware patterns
            if !analysis.patterns_matched.is_empty() {
                println!("  Malware Families Detected:");
                for pattern in &analysis.patterns_matched {
                    println!("    - {:?}", pattern);
                }
                println!();
            }

            // Take action based on threat level
            match analysis.threat_level {
                ThreatLevel::Critical => {
                    println!("  ⚡ ACTION: Terminating process immediately");
                    self.terminate_process(gid);
                    self.quarantine_files(gid);
                    self.send_alert(&analysis);
                }
                ThreatLevel::High => {
                    println!("  ⚠️  ACTION: Suspending process");
                    self.suspend_process(gid);
                    self.send_alert(&analysis);
                }
                ThreatLevel::Medium => {
                    println!("  ℹ️  ACTION: Monitoring closely");
                    self.log_activity(&analysis);
                }
                ThreatLevel::Low => {
                    println!("  📝 ACTION: Logging for analysis");
                    self.log_activity(&analysis);
                }
            }
            println!();
        }
    }

    fn receive_driver_message(&self) -> IOMessage {
        // Your kernel driver communication code here
        todo!()
    }

    fn terminate_process(&self, gid: u64) {
        // Send terminate command to kernel driver
        println!("    ✓ Process {} terminated", gid);
    }

    fn suspend_process(&self, gid: u64) {
        // Send suspend command to kernel driver
        println!("    ✓ Process {} suspended", gid);
    }

    fn quarantine_files(&self, gid: u64) {
        // Move malicious files to quarantine
        println!("    ✓ Files quarantined");
    }

    fn send_alert(&self, analysis: &ThreatAnalysis) {
        // Send alert to user/admin
        println!("    ✓ Alert sent");
    }

    fn log_activity(&self, analysis: &ThreatAnalysis) {
        // Log to database/file
        println!("    ✓ Activity logged");
    }
}

fn main() {
    let mut edr = EDRSystem::new(true);  // Enable ML collection
    edr.start();
}
```

---

## Best Practices

### 1. ML Data Collection
- ✅ Collect balanced datasets (similar number of malicious/benign)
- ✅ Run malware in isolated sandbox environment
- ✅ Label samples accurately
- ✅ Export data regularly
- ✅ Review collected samples for quality

### 2. Signature Tuning
- ✅ Start with default signatures
- ✅ Monitor false positive rate
- ✅ Adjust confidence thresholds as needed
- ✅ Add custom signatures for specific threats
- ✅ Regularly update signature database

### 3. Performance
- ✅ Clear terminated process trackers
- ✅ Use auto-save for large datasets
- ✅ Optimize feature extraction
- ✅ Monitor memory usage

### 4. Security
- ✅ Validate all kernel driver messages
- ✅ Sanitize file paths
- ✅ Implement rate limiting
- ✅ Protect against evasion techniques

---

## Conclusion

The OwlyShield SDK provides a comprehensive solution for:
- Real-time malware detection
- Behavioral analysis
- ML model training
- EDR development

For more examples, see `examples/sdk_usage.rs`.

For technical details, see `SDK_README.md`.
