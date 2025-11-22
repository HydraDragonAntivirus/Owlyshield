# OwlyShield SDK - Quick Reference Card

## Initialization

```rust
// Without ML collection
let mut sdk = OwlyShieldSDK::new(false, "models/malapi.json");

// With ML collection
let mut sdk = OwlyShieldSDK::new(true, "models/malapi.json");
```

## Process Messages

```rust
// Check if message indicates malicious behavior
let is_malicious = sdk.process_message(&io_msg, &process_record);
```

## Get Analysis

```rust
if let Some(analysis) = sdk.get_analysis(gid) {
    println!("Threat Level: {:?}", analysis.threat_level);
    println!("Signatures: {:?}", analysis.signatures_matched);
    println!("Patterns: {:?}", analysis.patterns_matched);
}
```

## Threat Levels

- **Critical** - Terminate immediately
- **High** - Suspend and alert
- **Medium** - Monitor closely
- **Low** - Log activity

## Malware Patterns Detected

| Pattern | Description | Key APIs |
|---------|-------------|----------|
| **RAT** | Remote Access Trojan | GetAsyncKeyState, WSAStartup, CreateRemoteThread |
| **Ransomware** | File encryption | CryptEncrypt, CryptGenRandom, FindFirstFileA |
| **Keylogger** | Keystroke capture | GetAsyncKeyState, SetWindowsHookExA |
| **Banking Trojan** | Credential theft | SetWindowsHookExA, HttpSendRequestA |
| **Credential Stealer** | Memory dumping | ReadProcessMemory, CreateToolhelp32Snapshot |
| **Process Hollowing** | Code injection | CreateProcessA, NtUnmapViewOfSection, SetThreadContext |
| **Cryptominer** | Resource abuse | CreateThread, Connect, SetThreadPriority |
| **Botnet** | C2 communication | Socket, Connect, Send, Recv |

## API Categories (8)

1. **Enumeration** - Process/file enumeration
2. **Injection** - Code/DLL injection
3. **Evasion** - Anti-analysis techniques
4. **Spying** - Keylogging, screen capture
5. **Internet** - Network operations
6. **Anti-Debugging** - Debugger detection
7. **Ransomware** - Encryption APIs
8. **Helper** - Registry, services, files

## ML Data Collection

```rust
// Collect sample
if let Some(ref mut collector) = sdk.ml_collector {
    collector.collect_sample(&api_tracker, &process_record, is_malicious);
}

// Export data
sdk.export_ml_data("datasets/data.json")?;
collector.export_to_csv("datasets/data.csv")?;

// Get counts
let (malicious, benign) = collector.get_counts();
```

## Feature Vector (60+ features)

### API Usage (9)
- enumeration_api_count, injection_api_count, evasion_api_count
- spying_api_count, internet_api_count, anti_debugging_api_count
- ransomware_api_count, helper_api_count, total_api_count

### File Operations (11)
- files_read, files_written, files_deleted, files_renamed
- files_encrypted, directories_enumerated, mass_file_operations
- executable_files_accessed, suspicious_extensions_written
- avg_entropy_written, high_entropy_writes

### Registry (5)
- registry_keys_created, registry_keys_deleted, registry_keys_modified
- autorun_keys_modified, security_keys_accessed

### Network (6)
- network_connections, data_sent_kb, data_received_kb
- dns_queries, http_requests, suspicious_ports_used

### Process (5)
- processes_created, processes_injected, threads_created
- memory_allocated_mb, privileges_escalated

### Patterns (5)
- has_keylogging_pattern, has_injection_pattern
- has_persistence_pattern, has_anti_analysis_pattern
- has_credential_theft_pattern

## Common Detection Patterns

### RAT Detection
```rust
has_keylogging + network_activity + process_injection
```

### Ransomware Detection
```rust
files_encrypted > 20 + crypto_apis + mass_file_operations
```

### Process Injection Detection
```rust
VirtualAllocEx + WriteProcessMemory + CreateRemoteThread
```

### Credential Theft Detection
```rust
ReadProcessMemory + Process32First + lsass_access
```

## Custom Signatures

```rust
use owlyshield_ransom::sdk::behavioral_signature::{
    BehavioralSignature, ThreatLevel
};

let sig = BehavioralSignature {
    name: "Custom Threat".to_string(),
    description: "Specific malware family".to_string(),
    threat_level: ThreatLevel::Critical,
    required_api_categories: vec!["injection".to_string()],
    required_apis: vec!["CreateRemoteThread".to_string()],
    min_files_written: Some(10),
    requires_network_activity: Some(true),
    min_confidence: 0.75,
    // ... other fields
};

sdk.signature_engine.add_signature(sig);
```

## Typical Workflow

1. **Initialize SDK** with malapi.json
2. **Receive IOMessage** from kernel driver
3. **Process message** through SDK
4. **Check if malicious**
5. **Get detailed analysis**
6. **Take action** based on threat level
7. **Export ML data** periodically

## File Structure

```
src/sdk/
├── mod.rs                    # Main SDK interface
├── api_tracker.rs            # API usage tracking
├── behavioral_signature.rs   # Signature detection
├── malware_patterns.rs       # Pattern matching
└── ml_collector.rs           # ML data collection

models/
└── malapi.json               # API definitions

datasets/
├── full_dataset.json         # Exported training data
├── full_dataset.csv          # CSV format
├── malicious_only.json       # Malicious samples
└── benign_only.json          # Benign samples
```

## Important Notes

⚠️ **ML Mode**: Only enable during controlled testing
⚠️ **Labeling**: Accurately label malicious vs benign samples
⚠️ **Balance**: Collect similar amounts of both types
⚠️ **Cleanup**: Clear terminated process trackers
⚠️ **Export**: Save datasets regularly

## Performance Tips

✅ Process messages in batches
✅ Use auto-save threshold
✅ Clear old trackers
✅ Optimize feature extraction
✅ Monitor memory usage

## Example Output

```
🚨 THREAT DETECTED!
  GID: 12345
  Process: malware.exe
  Threat Level: Critical

  [Critical] RAT Behavior
  Remote Access Trojan: keylogging, screen capture, and injection
  Confidence: 92.5%

  Malware Families Detected:
    - RAT

  ⚡ ACTION: Terminating process immediately
    ✓ Process 12345 terminated
    ✓ Files quarantined
    ✓ Alert sent
```

## Need Help?

- Full Documentation: `SDK_README.md`
- Usage Guide: `SDK_USAGE_GUIDE.md`
- Examples: `examples/sdk_usage.rs`
- API Reference: See source code comments
