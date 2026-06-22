# Barzakh Test Suite

## Scanner Tests (Rust)

The primary test suite lives in the Rust workspace at `src/barzakh-scanner-rs/`.

### Running Tests

```bash
cd src/barzakh-scanner-rs

# Run all tests
cargo test

# Check formatting & lint
cargo fmt --check
cargo clippy -- -D warnings

# Security audit
cargo audit
```

The Rust scanner has 22 integration tests covering all 18 detectors, baseline comparison, report generation, and corpus validation.

## E2E Tests

End-to-end testing runs via QEMU with a software TPM:

```bash
./scripts/qemu-e2e.sh ./binaries
```

This boots the bootkit in QEMU, extracts memory dumps and PCR values, then runs the scanner against them.

## Test Corpus

The `corpus/` directory contains synthetic firmware samples used for TPR/FPR validation:
- Files named `*malicious*` or `*infected*` are treated as positive samples
- All others are treated as negative (benign) samples

## CI/CD Integration

Tests run automatically via `.github/workflows/barzakh-ci.yml`:
- `test-scanner-rs`: fmt check, clippy, cargo test
- `security-audit-rs`: cargo audit
- `qemu-e2e`: full end-to-end with QEMU + swtpm
