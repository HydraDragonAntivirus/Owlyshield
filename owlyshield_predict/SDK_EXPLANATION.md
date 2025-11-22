# OwlyShield SDK - How It Works

## 1. Is "SDK" the Right Term?

**Yes, "SDK" (Software Development Kit) is appropriate** because:
- It provides a **programmatic interface** for behavioral analysis
- It can be used as a **library** by other applications
- It offers **modular components** (API tracking, ML collection, learning engines)
- It's **feature-gated** (`#[cfg(feature = "sdk")]`) - can be enabled/disabled

However, it's more accurately a **"Behavioral Analysis & Learning Framework"** since it's primarily used internally by OwlyShield itself.

---

## 2. How the Self-Learning System Works

### Overview
The system learns **automatically** from observed process behavior - **NO user input required**. All thresholds adapt based on statistical analysis of real-world data.

### Example: Adaptive Threshold Learning

#### **Initial State (Day 1)**
```rust
// System starts with conservative defaults
threshold_drivermsgs = 50        // Start low
threshold_prediction = 0.5       // 50% confidence
min_runtime_for_benign = 60      // 1 minute
```

#### **After Observing 100 Processes (Day 7)**
```rust
// System observes:
// - Most benign processes: 200-500 driver messages
// - Most malicious detected: 50-150 driver messages
// - Average benign runtime: 300 seconds

// System adapts automatically:
threshold_drivermsgs = 375       // 75th percentile of observed benign
threshold_prediction = 0.65       // Adjusted based on false positive rate
min_runtime_for_benign = 225      // 75th percentile of observed runtime
```

#### **After Observing 1000 Processes (Day 30)**
```rust
// System has learned optimal thresholds:
threshold_drivermsgs = 420       // Fine-tuned from 1000 samples
threshold_prediction = 0.72       // Optimized for accuracy
min_runtime_for_benign = 280      // Learned from real patterns
```

### How Adaptation Works (Step-by-Step)

**1. Data Collection Phase:**
```rust
// Every time a process is analyzed:
config.adapt_thresholds(
    driver_msg_count: 250,    // Observed value
    prediction: 0.68,         // ML model output
    timesteps: 15             // System performance metric
);
```

**2. Statistical Analysis (Every 100 samples):**
```rust
// System calculates 75th percentile of observed values
let sorted_msgs = [50, 100, 150, 200, 250, 300, 400, 500];
let p75_idx = (8 * 3 / 4) = 6;  // Index 6
threshold_drivermsgs = sorted_msgs[6] = 400;  // New threshold
```

**3. Continuous Learning:**
- Keeps only last 1000 samples (sliding window)
- Adapts every 100 samples or when 50 samples collected
- Prevents overfitting by using percentiles, not extremes

---

## 3. Does It Collect Benign Data?

**YES! The system collects BOTH malicious AND benign data.**

### Real-Time Learning Engine

**Benign Collection Methods:**

1. **Auto-labeling (Automatic):**
```rust
// Process runs for 5+ minutes with no detections
// System automatically labels as BENIGN
if runtime >= min_runtime_for_benign 
   && operations >= min_operations_for_benign
   && detection_count == 0 {
    label = Benign;
    collect_sample(api_tracker, precord, false);  // false = benign
}
```

2. **Process Termination (Automatic):**
```rust
// When process terminates cleanly
if runtime >= min_runtime_for_benign / 2
   && no_detections {
    label = Benign;
    collect_sample(api_tracker, precord, false);
}
```

3. **Baseline Establishment (Autonomous Learning):**
```rust
// First 50-100 clean processes establish "normal" baseline
// These become benign training samples
if !baseline_established && sample_count < 100 {
    update_baseline(profile);  // Contributes to benign dataset
}
```

### Collection Statistics
```rust
LearningStats {
    malicious_collected: 45,      // Detected threats
    benign_collected: 892,        // Auto-labeled clean processes
    auto_labeled_benign: 892,     // All from automatic learning
    detections_count: 45,         // Malicious detections
}
```

---

## 4. Machine Learning Data Format

### JSON Format Example

```json
{
  "malicious_samples": [
    {
      "id": 12345,
      "process_name": "suspicious.exe",
      "exe_path": "C:\\Users\\AppData\\suspicious.exe",
      "is_malicious": true,
      "timestamp": "2024-01-15T10:30:00Z",
      "features": {
        "enumeration_api_count": 0.15,
        "injection_api_count": 0.35,      // HIGH - suspicious
        "evasion_api_count": 0.25,        // HIGH - suspicious
        "spying_api_count": 0.10,
        "internet_api_count": 0.45,       // HIGH - network activity
        "anti_debugging_api_count": 0.20,
        "ransomware_api_count": 0.05,
        "helper_api_count": 0.05,
        "total_api_count": 1.0,
        
        "files_read": 0.12,
        "files_written": 0.88,            // HIGH - many writes
        "files_deleted": 0.05,
        "files_renamed": 0.15,
        "files_encrypted": 0.30,          // HIGH - encryption detected
        "directories_enumerated": 0.25,
        "mass_file_operations": 1.0,      // TRUE - mass operations
        
        "executable_files_accessed": 0.40,
        "suspicious_extensions_written": 0.60,
        "avg_entropy_written": 7.8,       // HIGH entropy (encryption)
        "high_entropy_writes": 1.0,       // TRUE
        
        "registry_keys_created": 0.20,
        "registry_keys_modified": 0.35,
        "autorun_keys_modified": 1.0,      // TRUE - persistence
        
        "network_connections": 0.50,
        "data_sent_kb": 1024.5,
        "data_received_kb": 512.3,
        "suspicious_ports_used": 1.0,      // TRUE
        
        "processes_created": 0.15,
        "processes_injected": 0.45,       // HIGH - code injection
        "threads_created": 0.30,
        "memory_allocated_mb": 256.0,
        "privileges_escalated": 1.0,       // TRUE
        
        "dlls_loaded": 0.25,
        "suspicious_dlls_loaded": 0.40,
        
        "has_keylogging_pattern": 0.0,
        "has_injection_pattern": 1.0,     // TRUE
        "has_persistence_pattern": 1.0,   // TRUE
        "has_anti_analysis_pattern": 1.0, // TRUE
        "has_credential_theft_pattern": 0.0,
        
        "execution_time_seconds": 45.2,
        "operations_per_second": 12.5,
        "unique_file_extensions_read": 5.0,
        "unique_file_extensions_written": 8.0,
        "unique_directories_accessed": 15.0,
        "file_operation_diversity": 0.75,
        "api_sequence_complexity": 0.85,
        "dll_diversity": 0.60,
        "network_diversity": 0.55
      },
      "raw_data": {
        "all_apis_used": [
          "VirtualAllocEx",
          "WriteProcessMemory",
          "CreateRemoteThread",
          "NtCreateThreadEx",
          "InternetOpenA",
          "HttpSendRequestA"
        ],
        "file_paths_accessed": [
          "C:\\Users\\Documents\\*.encrypted",
          "C:\\Windows\\System32\\config\\*"
        ],
        "dlls_loaded": [
          "ws2_32.dll",
          "wininet.dll",
          "crypt32.dll"
        ],
        "api_call_sequence": [
          ["VirtualAllocEx", "Injection"],
          ["WriteProcessMemory", "Injection"],
          ["CreateRemoteThread", "Injection"],
          ["InternetOpenA", "Internet"]
        ],
        "entropy_samples": [7.2, 7.5, 7.8, 7.9, 8.1]
      }
    }
  ],
  "benign_samples": [
    {
      "id": 67890,
      "process_name": "chrome.exe",
      "exe_path": "C:\\Program Files\\Google\\Chrome\\chrome.exe",
      "is_malicious": false,
      "timestamp": "2024-01-15T10:35:00Z",
      "features": {
        "enumeration_api_count": 0.20,
        "injection_api_count": 0.0,       // LOW - no injection
        "evasion_api_count": 0.0,         // LOW - no evasion
        "spying_api_count": 0.05,
        "internet_api_count": 0.60,       // HIGH - normal for browser
        "anti_debugging_api_count": 0.0,
        "ransomware_api_count": 0.0,
        "helper_api_count": 0.15,
        "total_api_count": 1.0,
        
        "files_read": 0.65,
        "files_written": 0.25,            // LOW - mostly reads
        "files_deleted": 0.05,
        "files_renamed": 0.05,
        "files_encrypted": 0.0,           // NO encryption
        "directories_enumerated": 0.10,
        "mass_file_operations": 0.0,      // FALSE
        
        "executable_files_accessed": 0.05,
        "suspicious_extensions_written": 0.0,
        "avg_entropy_written": 4.2,       // LOW entropy (normal data)
        "high_entropy_writes": 0.0,       // FALSE
        
        "registry_keys_created": 0.0,
        "registry_keys_modified": 0.05,
        "autorun_keys_modified": 0.0,      // FALSE - no persistence
        
        "network_connections": 0.80,       // HIGH - normal for browser
        "data_sent_kb": 2048.0,
        "data_received_kb": 5120.0,
        "suspicious_ports_used": 0.0,      // FALSE
        
        "processes_created": 0.10,
        "processes_injected": 0.0,        // NO injection
        "threads_created": 0.20,
        "memory_allocated_mb": 512.0,
        "privileges_escalated": 0.0,      // FALSE
        
        "dlls_loaded": 0.30,
        "suspicious_dlls_loaded": 0.0,
        
        "has_keylogging_pattern": 0.0,
        "has_injection_pattern": 0.0,     // FALSE
        "has_persistence_pattern": 0.0,   // FALSE
        "has_anti_analysis_pattern": 0.0, // FALSE
        "has_credential_theft_pattern": 0.0,
        
        "execution_time_seconds": 3600.0,  // 1 hour - long runtime
        "operations_per_second": 2.5,      // LOW - normal activity
        "unique_file_extensions_read": 12.0,
        "unique_file_extensions_written": 3.0,
        "unique_directories_accessed": 8.0,
        "file_operation_diversity": 0.45,
        "api_sequence_complexity": 0.35,
        "dll_diversity": 0.40,
        "network_diversity": 0.70
      },
      "raw_data": {
        "all_apis_used": [
          "CreateFileW",
          "ReadFile",
          "InternetOpenA",
          "HttpSendRequestA",
          "RegQueryValueEx"
        ],
        "file_paths_accessed": [
          "C:\\Users\\AppData\\Local\\Google\\Chrome\\Cache\\*",
          "C:\\Users\\AppData\\Local\\Google\\Chrome\\User Data\\*"
        ],
        "dlls_loaded": [
          "kernel32.dll",
          "user32.dll",
          "wininet.dll"
        ],
        "api_call_sequence": [
          ["CreateFileW", "Helper"],
          ["ReadFile", "Helper"],
          ["InternetOpenA", "Internet"],
          ["HttpSendRequestA", "Internet"]
        ],
        "entropy_samples": [3.8, 4.1, 4.2, 4.0, 4.3]
      }
    }
  ],
  "collection_timestamp": "2024-01-15T11:00:00Z",
  "total_malicious": 45,
  "total_benign": 892
}
```

### CSV Format Example

```csv
id,process_name,is_malicious,enumeration_api_count,injection_api_count,evasion_api_count,spying_api_count,internet_api_count,anti_debugging_api_count,ransomware_api_count,helper_api_count,total_api_count,files_read,files_written,files_deleted,files_renamed,files_encrypted,directories_enumerated,mass_file_operations,executable_files_accessed,suspicious_extensions_written,avg_entropy_written,high_entropy_writes,registry_keys_created,registry_keys_deleted,registry_keys_modified,autorun_keys_modified,network_connections,processes_created,processes_injected,threads_created,memory_allocated_mb,dlls_loaded,has_keylogging_pattern,has_injection_pattern,has_persistence_pattern,operations_per_second
12345,suspicious.exe,1,0.15,0.35,0.25,0.10,0.45,0.20,0.05,0.05,1.0,0.12,0.88,0.05,0.15,0.30,0.25,1.0,0.40,0.60,7.8,1.0,0.20,0.0,0.35,1.0,0.50,0.15,0.45,0.30,256.0,0.25,0.0,1.0,1.0,12.5
67890,chrome.exe,0,0.20,0.0,0.0,0.05,0.60,0.0,0.0,0.15,1.0,0.65,0.25,0.05,0.05,0.0,0.10,0.0,0.05,0.0,4.2,0.0,0.0,0.0,0.05,0.0,0.80,0.10,0.0,0.20,512.0,0.30,0.0,0.0,0.0,2.5
```

---

## 5. How SDK Develops/Improves Over Time

### Development Lifecycle

**Phase 1: Initial Deployment (Week 1)**
- Starts with conservative thresholds
- Collects baseline data from first 50-100 processes
- Establishes "normal" behavior patterns

**Phase 2: Learning Phase (Week 2-4)**
- Adapts thresholds every 100 samples
- Learns optimal detection parameters
- Reduces false positives through statistical analysis

**Phase 3: Mature Phase (Month 2+)**
- Thresholds stabilize around optimal values
- Continuous adaptation based on new attack patterns
- Self-improves detection accuracy automatically

### Example Development Timeline

```
Day 1:  threshold_prediction = 0.50  (50% - conservative start)
Day 7:  threshold_prediction = 0.65  (learned from 100 samples)
Day 30: threshold_prediction = 0.72  (optimized from 1000 samples)
Day 90: threshold_prediction = 0.75  (fine-tuned, stable)
```

### Key Features

1. **No Manual Tuning Required** - All parameters adapt automatically
2. **Environment-Specific Learning** - Adapts to each deployment's normal behavior
3. **Attack Pattern Evolution** - Learns new attack techniques automatically
4. **False Positive Reduction** - Continuously improves accuracy

---

## Summary

- ✅ **"SDK" is appropriate** - it's a modular, feature-gated framework
- ✅ **Collects BOTH benign and malicious data** - automatic labeling
- ✅ **Fully self-learning** - no user input needed
- ✅ **Rich ML data format** - 40+ features per sample in JSON/CSV
- ✅ **Continuous improvement** - adapts over time automatically

The system is designed to be **fully autonomous** - it learns, adapts, and improves without any manual intervention!

