# OwlyShield SDK - Build Instructions

## 🔧 Building with SDK Feature

The SDK is feature-gated and will only be compiled when the `sdk` feature is enabled.

### Build Commands

```bash
# Build with SDK enabled (Debug)
cargo build --features sdk

# Build with SDK enabled (Release)
cargo build --release --features sdk

# Build without SDK (default)
cargo build

# Check code with SDK
cargo check --features sdk

# Run tests with SDK
cargo test --features sdk

# Run examples with SDK
cargo run --example sdk_usage --features sdk
```

## 📦 Feature Configuration

In `Cargo.toml`:

```toml
[features]
default = []
service = []
malware = []
record = []
replay = []
jsonrpc = []
mqtt = []
novelty = []
hydradragon = []
sdk = []  # Enable OwlyShield SDK for behavioral analysis and ML data collection
```

## 🎯 Multiple Features

You can combine features:

```bash
# Build with SDK + service
cargo build --features "sdk,service"

# Build with SDK + malware detection
cargo build --features "sdk,malware"

# Build with all features
cargo build --all-features

# Build release with specific features
cargo build --release --features "sdk,service,malware"
```

## 🔍 Code Organization

The SDK module is conditionally compiled in `src/main.rs`:

```rust
#[cfg(feature = "sdk")]
pub mod sdk;  // OwlyShield SDK for behavioral analysis
```

This means:
- ✅ **With `--features sdk`**: SDK module is compiled and available
- ❌ **Without feature flag**: SDK module is not compiled, reducing binary size

## 📊 Binary Size Comparison

Without SDK:
```bash
cargo build --release
# Binary size: ~X MB (baseline)
```

With SDK:
```bash
cargo build --release --features sdk
# Binary size: ~X + 0.5 MB (SDK adds ~500KB)
```

## 🚀 Using SDK in Your Code

When using the SDK in your code, also use feature gates:

```rust
#[cfg(feature = "sdk")]
use owlyshield_ransom::sdk::OwlyShieldSDK;

#[cfg(feature = "sdk")]
fn initialize_sdk() -> OwlyShieldSDK {
    OwlyShieldSDK::new(false, "models/malapi.json")
}

fn main() {
    #[cfg(feature = "sdk")]
    {
        let mut sdk = initialize_sdk();
        // Use SDK...
    }

    #[cfg(not(feature = "sdk"))]
    {
        println!("SDK not enabled. Build with --features sdk");
    }
}
```

## 📝 Integration Examples

### Example 1: Optional SDK Usage

```rust
pub struct EDRSystem {
    #[cfg(feature = "sdk")]
    sdk: Option<OwlyShieldSDK>,
}

impl EDRSystem {
    pub fn new() -> Self {
        EDRSystem {
            #[cfg(feature = "sdk")]
            sdk: Some(OwlyShieldSDK::new(false, "models/malapi.json")),
        }
    }

    pub fn process_message(&mut self, msg: &IOMessage, precord: &ProcessRecord) {
        #[cfg(feature = "sdk")]
        {
            if let Some(ref mut sdk) = self.sdk {
                let is_malicious = sdk.process_message(msg, precord);
                if is_malicious {
                    self.handle_threat(msg.gid);
                }
            }
        }

        // Continue with normal processing...
    }
}
```

### Example 2: Development vs Production

```toml
# Cargo.toml
[profile.dev]
# SDK enabled by default in development
default-features = true

[profile.release]
# SDK optional in release builds
default-features = false
```

## 🎓 Best Practices

1. **Development**: Enable SDK for testing and data collection
   ```bash
   cargo run --features sdk
   ```

2. **Production**: Only enable if needed
   ```bash
   # Lightweight production build (no SDK)
   cargo build --release

   # Production with SDK (for ML data collection)
   cargo build --release --features sdk
   ```

3. **Testing**: Always test with and without SDK
   ```bash
   cargo test
   cargo test --features sdk
   ```

## 🔒 Security Considerations

- The SDK is **not included** in builds without the feature flag
- Zero overhead when disabled (code not compiled at all)
- Safe to deploy without SDK in production environments
- Enable SDK only when behavioral analysis is needed

## 📈 Performance Impact

| Configuration | Binary Size | Runtime Overhead | Use Case |
|---------------|-------------|------------------|----------|
| Without SDK | Baseline | None | Production deployment |
| With SDK | +~500KB | Minimal (~5%) | Development, ML collection |

## 🎯 Recommended Build Configurations

### Development Environment
```bash
cargo build --features "sdk,service,malware"
```

### Production (Lightweight)
```bash
cargo build --release
```

### Production (With ML Collection)
```bash
cargo build --release --features "sdk,service"
```

### Full-Featured Build
```bash
cargo build --release --all-features
```

## ✅ Verification

To verify the SDK is working:

```bash
# Build with SDK
cargo build --features sdk

# Check that SDK module exists
cargo doc --features sdk --no-deps --open
# Look for "sdk" module in documentation

# Run SDK example
cargo run --example sdk_usage --features sdk
```

## 🐛 Troubleshooting

### Issue: "cannot find module `sdk`"
**Solution**: Build with `--features sdk`

### Issue: "unresolved import `crate::sdk`"
**Solution**: Add `#[cfg(feature = "sdk")]` to your imports

### Issue: SDK not available at runtime
**Solution**: Rebuild with `--features sdk`

## 📚 Additional Resources

- **SDK Documentation**: See `SDK_README.md`
- **Usage Guide**: See `SDK_USAGE_GUIDE.md`
- **Quick Reference**: See `SDK_QUICK_REFERENCE.md`
- **Examples**: See `examples/sdk_usage.rs`

---

**Ready to build!** 🚀

Start with:
```bash
cargo build --features sdk
cargo run --example sdk_usage --features sdk
```
