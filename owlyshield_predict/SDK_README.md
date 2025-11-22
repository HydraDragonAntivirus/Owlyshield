# OwlyShield SDK - Behavioral Analysis & Malware Detection

A comprehensive EDR/AV SDK for dynamic behavioral analysis, signature-based detection, and machine learning data collection.

## Features

### 🎯 Core Capabilities

1. **Behavioral Signature Detection**
   - Pre-defined signatures for common malware behaviors
   - Custom signature creation and loading
   - Confidence-based threat scoring
   - Automatic threat level classification

2. **Malware Pattern Matching**
   - RAT (Remote Access Trojan) detection
   - Ransomware behavior detection
   - Keylogger identification
   - Banking Trojan patterns
   - Credential Stealer detection
   - Process Hollowing techniques
   - Cryptominer identification
   - Botnet client detection

3. **Machine Learning Data Collection**
   - Automatic feature extraction from behavioral data
   - Support for both malicious and benign sample collection
   - Export to JSON and CSV formats
   - Comprehensive feature vectors (60+ features)
   - Ready for ML model training

4. **API Usage Tracking**
   - Tracks Windows API calls across 8 categories:
     - Enumeration APIs
     - Injection APIs
     - Evasion techniques
     - Spying/Keylogging APIs
     - Internet/Network APIs
     - Anti-debugging techniques
     - Ransomware APIs
     - Helper/Utility APIs
   - Sequence tracking for pattern detection
   - DLL usage monitoring

## Quick Start

### Basic Usage

```rust
use owlyshield_ransom::sdk::OwlyShieldSDK;

// Initialize SDK without ML collection
let mut sdk = OwlyShieldSDK::new(false, "models/malapi.json");

// Process kernel driver messages
let is_malicious = sdk.process_message(&io_msg, &process_record);

if is_malicious {
    println!("⚠️ Malicious behavior detected!");

    // Get detailed analysis
    if let Some(analysis) = sdk.get_analysis(gid) {
        println!("Threat Level: {:?}", analysis.threat_level);
        println!("Matched Signatures: {:?}", analysis.signatures_matched);
        println!("Malware Patterns: {:?}", analysis.patterns_matched);
    }
}
```

### Machine Learning Mode

```rust
use owlyshield_ransom::sdk::{OwlyShieldSDK, CollectionMode};

// Initialize SDK with ML collection enabled
let mut sdk = OwlyShieldSDK::new(true, "models/malapi.json");

// Process messages - SDK automatically collects training data
sdk.process_message(&io_msg, &process_record);

// Export collected data
sdk.export_ml_data("datasets/training_data.json").unwrap();

// Get collection statistics
if let Some(collector) = &sdk.ml_collector {
    let (malicious, benign) = collector.get_counts();
    println!("Collected: {} malicious, {} benign samples", malicious, benign);
}
```

## Architecture

```
OwlyShield SDK
├── Signature Engine (behavioral_signature.rs)
│   ├── Pre-defined behavioral signatures
│   ├── Confidence scoring
│   └── Custom signature support
│
├── Pattern Matcher (malware_patterns.rs)
│   ├── RAT detection
│   ├── Ransomware detection
│   ├── Keylogger detection
│   └── 8+ malware family patterns
│
├── API Tracker (api_tracker.rs)
│   ├── API call monitoring
│   ├── DLL usage tracking
│   ├── Sequence analysis
│   └── Behavioral statistics
│
└── ML Collector (ml_collector.rs)
    ├── Feature extraction
    ├── Dataset management
    └── Export functionality
```

## Behavioral Signatures

The SDK includes pre-defined signatures for:

### 1. Ransomware
- **Indicators**: Mass file encryption, high entropy writes, deletion patterns
- **APIs**: `CryptAcquireContextA`, `CryptEncrypt`, `CryptGenRandom`
- **Threat Level**: Critical

### 2. RAT (Remote Access Trojan)
- **Indicators**: Keylogging + Network communication + Process injection
- **APIs**: `GetAsyncKeyState`, `SetWindowsHookExA`, `CreateRemoteThread`
- **Threat Level**: Critical

### 3. Process Injection
- **Indicators**: Memory allocation in remote process, code injection
- **APIs**: `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`
- **Threat Level**: High

### 4. Banking Trojan
- **Indicators**: Browser hooking, form grabbing, credential theft
- **APIs**: `SetWindowsHookExA`, `HttpSendRequestA`, `GetForegroundWindow`
- **Threat Level**: Critical

### 5. Credential Stealer
- **Indicators**: Memory dumping, LSASS access, privilege escalation
- **APIs**: `OpenProcess`, `ReadProcessMemory`, `AdjustTokenPrivileges`
- **Threat Level**: Critical

### 6. Backdoor Installation
- **Indicators**: Persistence mechanisms, network listeners
- **APIs**: `RegCreateKeyExA`, `CreateServiceA`, `Bind`, `Listen`
- **Threat Level**: Critical

### 7. Rootkit Behavior
- **Indicators**: Driver installation, system modification
- **APIs**: Service APIs, driver loading
- **Threat Level**: Critical

### 8. Anti-Analysis Techniques
- **Indicators**: Anti-debugging, anti-VM, obfuscation
- **APIs**: `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`
- **Threat Level**: High

## Malware Pattern Detection

Each pattern includes:

- **Mandatory APIs**: Must all be present
- **Required APIs**: N of M must be present
- **Behavioral Indicators**: File operations, network activity, etc.
- **Network Indicators**: C2 communication, suspicious ports
- **DLL Requirements**: Specific system DLLs

Example RAT Pattern:
```rust
MalwarePattern {
    pattern_type: PatternType::RAT,
    mandatory_apis: vec!["WSAStartup", "Connect"],
    required_apis: (3, vec![
        "GetAsyncKeyState",
        "SetWindowsHookExA",
        "BitBlt",
        "VirtualAllocEx",
        "WriteProcessMemory",
        "CreateRemoteThread",
    ]),
    required_categories: vec!["spying", "internet", "injection"],
    // ... behavioral indicators
}
```

## Machine Learning Features

The SDK extracts 60+ features for ML training:

### API Usage Features (9)
- Count of APIs per category (enumeration, injection, evasion, etc.)
- Total API count

### File Operation Features (11)
- Files read/written/deleted/renamed/encrypted
- Directory enumeration
- Mass file operations flag
- Executable access patterns
- Suspicious extensions
- Entropy statistics

### Registry Features (5)
- Keys created/deleted/modified
- Autorun key modifications
- Security key access

### Network Features (6)
- Connection count
- Data transfer (KB)
- DNS queries
- HTTP requests
- Suspicious ports

### Process Features (5)
- Process creation/injection
- Thread creation
- Memory allocation
- Privilege escalation

### Behavioral Patterns (5)
- Keylogging detection
- Injection detection
- Persistence detection
- Anti-analysis detection
- Credential theft detection

### Statistical Features (8)
- Execution time
- Operations per second
- File extension diversity
- Directory access patterns
- API sequence complexity

## Data Export Formats

### JSON Format
Full dataset with all features, raw data, and metadata:
```json
{
  "malicious_samples": [...],
  "benign_samples": [...],
  "collection_timestamp": "2025-11-22T...",
  "total_malicious": 150,
  "total_benign": 250
}
```

### CSV Format
Flat feature vectors ready for ML frameworks:
```csv
id,process_name,is_malicious,enumeration_api_count,injection_api_count,...
12345,malware.exe,1,0.05,0.12,0.08,...
```

## Integration Example

```rust
use owlyshield_ransom::sdk::OwlyShieldSDK;
use owlyshield_ransom::shared_def::IOMessage;

fn main() {
    // Initialize SDK
    let mut sdk = OwlyShieldSDK::new(
        true,  // Enable ML collection
        "models/malapi.json"
    );

    // Main event loop - receive messages from kernel driver
    loop {
        // Get message from kernel driver
        let io_msg = receive_from_driver();
        let process_record = get_process_record(io_msg.gid);

        // Process through SDK
        let is_malicious = sdk.process_message(&io_msg, &process_record);

        if is_malicious {
            // Get detailed analysis
            if let Some(analysis) = sdk.get_analysis(io_msg.gid) {
                handle_threat(analysis);
            }
        }
    }
}

fn handle_threat(analysis: ThreatAnalysis) {
    match analysis.threat_level {
        ThreatLevel::Critical => {
            // Terminate process immediately
            terminate_process(analysis.gid);
            send_alert(&analysis);
        }
        ThreatLevel::High => {
            // Suspend and alert
            suspend_process(analysis.gid);
            send_alert(&analysis);
        }
        ThreatLevel::Medium => {
            // Monitor and log
            log_suspicious_activity(&analysis);
        }
        ThreatLevel::Low => {
            // Just log
            log_activity(&analysis);
        }
    }
}
```

## Custom Signatures

Create your own behavioral signatures:

```rust
use owlyshield_ransom::sdk::behavioral_signature::{
    BehavioralSignature, ThreatLevel
};

let custom_sig = BehavioralSignature {
    name: "My Custom Threat".to_string(),
    description: "Detects specific malware family".to_string(),
    threat_level: ThreatLevel::Critical,
    required_api_categories: vec!["injection".to_string()],
    required_apis: vec![
        "CreateRemoteThread".to_string(),
        "WriteProcessMemory".to_string(),
    ],
    min_files_written: Some(10),
    requires_network_activity: Some(true),
    min_confidence: 0.75,
    // ... other fields
};

sdk.signature_engine.add_signature(custom_sig);
```

## API Categories (from malapi.json)

The SDK uses the following API categories:

1. **Enumeration**: Process/file/system enumeration
2. **Injection**: Code/DLL injection techniques
3. **Evasion**: Anti-analysis, obfuscation
4. **Spying**: Keylogging, screen capture
5. **Internet**: Network communication
6. **Anti-Debugging**: Debugger detection
7. **Ransomware**: Encryption APIs
8. **Helper**: Registry, services, file operations

## Training ML Models

After collecting data:

1. **Export datasets**:
   ```rust
   sdk.export_ml_data("datasets/training_data.json")?;
   collector.export_to_csv("datasets/training_data.csv")?;
   ```

2. **Load in Python**:
   ```python
   import pandas as pd
   data = pd.read_csv('datasets/training_data.csv')
   X = data.drop(['id', 'process_name', 'is_malicious'], axis=1)
   y = data['is_malicious']
   ```

3. **Train your model**:
   ```python
   from sklearn.ensemble import RandomForestClassifier
   model = RandomForestClassifier(n_estimators=100)
   model.fit(X_train, y_train)
   ```

## Best Practices

1. **ML Collection Mode**:
   - Enable only during controlled testing
   - Label samples accurately
   - Collect balanced datasets (malicious + benign)

2. **Signature Tuning**:
   - Adjust `min_confidence` thresholds
   - Add custom signatures for specific threats
   - Monitor false positive rates

3. **Performance**:
   - Use auto-save for large datasets
   - Clear API trackers for terminated processes
   - Tune normalization parameters

4. **Integration**:
   - Process messages in real-time
   - Handle thread safety for concurrent access
   - Implement proper error handling

## File Structure

```
src/sdk/
├── mod.rs                    # Main SDK interface
├── api_tracker.rs            # API usage tracking
├── behavioral_signature.rs   # Signature detection engine
├── malware_patterns.rs       # Malware family patterns
└── ml_collector.rs           # ML data collection

examples/
└── sdk_usage.rs              # Usage examples

models/
└── malapi.json               # API category definitions
```

## Requirements

- Rust 2021 edition
- Dependencies: `serde`, `serde_json`, `num`
- Windows API access (for full functionality)
- Kernel driver integration (for real-time monitoring)

## License

Same as OwlyShield project

## Contributing

Contributions welcome! Please submit:
- New behavioral signatures
- Malware pattern definitions
- Feature extraction improvements
- ML model integrations

## Support

For issues and questions:
- GitHub Issues
- Project Documentation
- Community Forums
