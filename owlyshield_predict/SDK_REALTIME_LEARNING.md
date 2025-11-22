# OwlyShield SDK - Real-Time Learning Module

## 🧠 Automatic Learning from Running Processes

The Real-Time Learning module automatically learns from your EDR deployment, collecting labeled samples based on detection results and user feedback.

## How It Works

### **Automatic Labeling System**

```
┌─────────────────────────────────────────────────────────────┐
│                    Process Running                          │
└───────────────────┬─────────────────────────────────────────┘
                    │
        ┌───────────▼────────────┐
        │  SDK Detects Malware?  │
        └───────────┬────────────┘
                    │
        ┌───────────▼────────────┐
        │         YES            │────────► Label: MALICIOUS
        │                        │          Collect immediately
        └────────────────────────┘
                    │
        ┌───────────▼────────────┐
        │         NO             │
        │  Running for 5+ min?   │
        │  1000+ operations?     │
        │  No detections?        │
        └───────────┬────────────┘
                    │
        ┌───────────▼────────────┐
        │         YES            │────────► Label: BENIGN
        │                        │          Collect automatically
        └────────────────────────┘
                    │
        ┌───────────▼────────────┐
        │  Process Terminated    │────────► Final check
        └────────────────────────┘          Maybe benign?
```

## 🎯 Three Ways Processes Are Labeled

### 1. **Automatic Detection** (Malicious)
When SDK detects malware behavior:
- ✅ Signatures matched
- ✅ Malware patterns detected
- 🏷️ **Automatically labeled as MALICIOUS**
- 💾 **Sample collected immediately**

### 2. **User Feedback** (Malicious or Benign)
User explicitly flags process:
- ⚠️ User: "This is malware!" → **Labeled MALICIOUS**
- ✅ User: "This is safe!" → **Labeled BENIGN**
- 💾 **Sample collected immediately**

### 3. **Automatic Benign Detection**
Process runs without issues:
- ⏱️ Running > 5 minutes
- 📊 Performed > 1000 operations
- ✅ Zero detections
- 🏷️ **Automatically labeled as BENIGN**
- 💾 **Sample collected automatically**

## 💻 Basic Usage

### Initialize with Real-Time Learning

```rust
use owlyshield_ransom::sdk::OwlyShieldSDK;

// Enable both ML collection AND real-time learning
let mut sdk = OwlyShieldSDK::with_realtime_learning(
    true,   // ML collection enabled
    true,   // Real-time learning enabled
    "models/malapi.json"
);

println!("Real-time learning: ACTIVE ✅");
```

### Processing Messages (Automatic)

```rust
// Normal message processing
let is_malicious = sdk.process_message(&io_msg, &process_record);

// Real-time learning happens automatically:
// - Tracks the process
// - Updates activity counters
// - If malicious detected → collects immediately
if is_malicious {
    println!("Malware detected and sample collected!");
}
```

### User Feedback (Manual Labeling)

```rust
// User confirms it's malware
sdk.user_flag_malware(gid);
// → Sample collected with label: MALICIOUS

// User confirms it's safe (false positive)
sdk.user_mark_benign(gid);
// → Sample collected with label: BENIGN
```

### Periodic Benign Check

```rust
// Call this every 5 minutes to auto-label benign processes
let process_records = get_all_process_records();
sdk.check_benign_processes(&process_records);

// Prints:
// [Real-Time Learning] 📗 Auto-labeled BENIGN: chrome.exe (GID: 1234, Runtime: 302s, Ops: 1523)
// [Real-Time Learning] 📗 Auto-labeled BENIGN: notepad.exe (GID: 5678, Runtime: 450s, Ops: 2100)
```

### Export Collected Samples

```rust
// Export when ready
sdk.export_realtime_samples()?;

// Prints:
// [Real-Time Learning] 💾 Exported 150 samples (Malicious: 50, Benign: 100)
//   JSON: ./ml_data/realtime/realtime_learning_1234567890.json
//   CSV: ./ml_data/realtime/realtime_learning_1234567890.csv
```

### View Statistics

```rust
sdk.get_realtime_stats();

// Prints:
// ╔════════════════════════════════════════════════════════╗
// ║        Real-Time Learning Statistics                  ║
// ╠════════════════════════════════════════════════════════╣
// ║  Total Processes Tracked:    250                      ║
// ║  ─────────────────────────────────────────────────     ║
// ║  Malicious Collected:         50                      ║
// ║    - By Detection:            35                      ║
// ║    - By User:                 15                      ║
// ║  ─────────────────────────────────────────────────     ║
// ║  Benign Collected:           100                      ║
// ║    - Auto-labeled:            80                      ║
// ║    - By User:                 20                      ║
// ║  ─────────────────────────────────────────────────     ║
// ║  Total Samples:              150                      ║
// ║  Samples Exported:           150                      ║
// ╚════════════════════════════════════════════════════════╝
```

## 🔧 Configuration

### Custom Learning Parameters

```rust
use owlyshield_ransom::sdk::realtime_learning::LearningConfig;

let mut config = LearningConfig {
    min_runtime_for_benign: 300,      // 5 minutes (in seconds)
    min_operations_for_benign: 1000,  // Minimum I/O operations
    auto_save_interval: 100,           // Auto-save every 100 samples
    max_samples_buffer: 1000,          // Max samples before forced export
    auto_label_benign: true,           // Enable automatic benign labeling
    benign_confidence_threshold: 0.9,  // Confidence threshold
};

// Apply configuration
if let Some(ref mut rt_learning) = sdk.realtime_learning {
    rt_learning.update_config(config);
}
```

## 📊 Complete Integration Example

```rust
use owlyshield_ransom::sdk::OwlyShieldSDK;
use owlyshield_ransom::shared_def::IOMessage;
use std::collections::HashMap;
use std::time::Duration;

struct EDRWithLearning {
    sdk: OwlyShieldSDK,
    process_records: HashMap<u64, ProcessRecord>,
    last_benign_check: SystemTime,
}

impl EDRWithLearning {
    fn new() -> Self {
        EDRWithLearning {
            // Enable real-time learning
            sdk: OwlyShieldSDK::with_realtime_learning(
                true,  // ML collection
                true,  // Real-time learning
                "models/malapi.json"
            ),
            process_records: HashMap::new(),
            last_benign_check: SystemTime::now(),
        }
    }

    fn run(&mut self) {
        loop {
            // 1. Process kernel driver messages
            let io_msg = receive_from_driver();
            let gid = io_msg.gid;

            let precord = self.process_records
                .entry(gid)
                .or_insert_with(|| ProcessRecord::new(gid, "app.exe".to_string(), PathBuf::new()));

            // 2. Detect malware (real-time learning happens automatically)
            let is_malicious = self.sdk.process_message(&io_msg, precord);

            if is_malicious {
                self.handle_malware_detected(gid);
            }

            // 3. Check for user feedback
            self.check_user_feedback();

            // 4. Periodically check for benign processes (every 5 minutes)
            if self.last_benign_check.elapsed().unwrap() > Duration::from_secs(300) {
                self.sdk.check_benign_processes(&self.process_records);
                self.last_benign_check = SystemTime::now();
            }

            // 5. Print stats periodically
            if should_print_stats() {
                self.sdk.get_realtime_stats();
            }
        }
    }

    fn handle_malware_detected(&mut self, gid: u64) {
        println!("🚨 Malware detected: GID {}", gid);

        // Terminate process
        terminate_process(gid);

        // Sample already collected automatically by SDK!
    }

    fn check_user_feedback(&mut self) {
        // Check if user flagged any process
        if let Some((gid, is_malware)) = check_user_input() {
            if is_malware {
                println!("User flagged GID {} as MALWARE", gid);
                self.sdk.user_flag_malware(gid);
            } else {
                println!("User marked GID {} as BENIGN", gid);
                self.sdk.user_mark_benign(gid);
            }
        }
    }
}

fn main() {
    let mut edr = EDRWithLearning::new();
    edr.run();
}
```

## 🎯 Integration with Existing EDR

### Option 1: Add to Existing Code

```rust
// In your existing run.rs or main loop

#[cfg(feature = "sdk")]
use crate::sdk::OwlyShieldSDK;

#[cfg(feature = "sdk")]
static mut SDK: Option<OwlyShieldSDK> = None;

fn initialize_sdk() {
    #[cfg(feature = "sdk")]
    unsafe {
        SDK = Some(OwlyShieldSDK::with_realtime_learning(
            true,  // ML enabled
            true,  // Real-time learning enabled
            "models/malapi.json"
        ));
        println!("SDK with real-time learning initialized!");
    }
}

fn process_driver_message(io_msg: &IOMessage, precord: &ProcessRecord) {
    #[cfg(feature = "sdk")]
    unsafe {
        if let Some(ref mut sdk) = SDK {
            let is_malicious = sdk.process_message(io_msg, precord);

            if is_malicious {
                // Handle threat
                handle_threat(io_msg.gid);
            }
        }
    }

    // Your existing processing logic...
}
```

### Option 2: Integration with HydraDragon

```rust
#[cfg(all(feature = "sdk", feature = "hydradragon"))]
fn integrate_with_hydradragon() {
    // Initialize SDK with real-time learning
    let mut sdk = OwlyShieldSDK::with_realtime_learning(
        true, true, "models/malapi.json"
    );

    // When HydraDragon detects malware
    if hydradragon_detected_malware(gid) {
        // User confirmation: "Is this malware?"
        sdk.user_flag_malware(gid);
        // SDK learns from HydraDragon's detection!
    }

    // When HydraDragon says it's safe
    if hydradragon_says_safe(gid) {
        sdk.user_mark_benign(gid);
        // SDK learns it's a false positive
    }
}
```

## 📈 Example Output

```
[Real-Time Learning] 🦠 Collected MALICIOUS sample: malware.exe (GID: 1234)
[Real-Time Learning] 🦠 Collected MALICIOUS sample: trojan.exe (GID: 2345)
[Real-Time Learning] ⚠️  User flagged MALICIOUS: suspicious.exe (GID: 3456)
[Real-Time Learning] 📗 Auto-labeled BENIGN: chrome.exe (GID: 4567, Runtime: 305s, Ops: 1024)
[Real-Time Learning] 📗 Auto-labeled BENIGN: notepad.exe (GID: 5678, Runtime: 450s, Ops: 1500)
[Real-Time Learning] ✅ User marked BENIGN: myapp.exe (GID: 6789)

[Real-Time Learning] 💾 Exported 50 samples (Malicious: 15, Benign: 35)
  JSON: ./ml_data/realtime/realtime_learning_1700000000.json
  CSV: ./ml_data/realtime/realtime_learning_1700000000.csv
```

## 🔄 Data Flow

```
Kernel Driver Message
        ↓
SDK.process_message()
        ↓
    ┌───────────────┐
    │ Is Malicious? │
    └───┬───────┬───┘
        │       │
       YES      NO
        │       │
        ↓       ↓
  Collect as  Track
  MALICIOUS  Process
        ↓       ↓
              Running
              5+ min?
                ↓
               YES
                ↓
          Collect as
           BENIGN
```

## ✅ Benefits

1. **Zero Manual Effort** - Learns automatically from detections
2. **Balanced Datasets** - Collects both malicious and benign samples
3. **User Feedback** - Incorporates user corrections
4. **Continuous Learning** - Always improving
5. **Production Ready** - Learns from real-world usage

## 🎓 Best Practices

1. **Enable in Production** - Learn from real threats
2. **Review Samples** - Periodically check collected data
3. **User Feedback** - Let users correct false positives
4. **Regular Export** - Export samples weekly
5. **Train Models** - Use collected data to improve detection

## 🚀 Quick Start

```rust
// 1. Initialize with real-time learning
let mut sdk = OwlyShieldSDK::with_realtime_learning(true, true, "models/malapi.json");

// 2. Process messages (automatic learning)
sdk.process_message(&io_msg, &process_record);

// 3. User feedback (when needed)
sdk.user_flag_malware(gid);  // User says: "This is malware!"
sdk.user_mark_benign(gid);   // User says: "This is safe!"

// 4. Periodic benign check (every 5 min)
sdk.check_benign_processes(&process_records);

// 5. Export samples
sdk.export_realtime_samples()?;

// 6. View stats
sdk.get_realtime_stats();
```

---

**Real-time learning is now part of your EDR! 🧠✅**

Every process is a learning opportunity!
