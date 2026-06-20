use std::path::Path;

use crate::baseline::Baseline;
use crate::detector::{Detector, DetectorError, Finding, Severity};

#[allow(dead_code)]
const EFI_VARIABLE_GUID: &[u8] =
    b"\x61\xdf\xe4\x8b\xca\x93\xd2\x11\xaa\x0d\x00\xe0\x98\x03\x2b\x8c";
const SECURE_BOOT_ENABLED: u8 = 1;

pub struct SecureBootDetector {
    #[allow(dead_code)]
    baseline: Option<Baseline>,
}

impl SecureBootDetector {
    pub fn new(baseline: Option<Baseline>) -> Self {
        Self { baseline }
    }

    fn check_secure_boot_state(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Search for SecureBoot variable
        let sb_var_name = b"S\x00e\x00c\x00u\x00r\x00e\x00B\x00o\x00o\x00t\x00";
        if let Some(pos) = data
            .windows(sb_var_name.len())
            .position(|w| w == sb_var_name)
        {
            // Check if Secure Boot is disabled
            let value_offset = pos + sb_var_name.len() + 8; // skip past attributes
            if value_offset < data.len() && data[value_offset] != SECURE_BOOT_ENABLED {
                findings.push(
                    Finding::new(
                        "secureboot",
                        Severity::High,
                        "Secure Boot is disabled",
                        "The SecureBoot UEFI variable indicates Secure Boot is disabled. \
                         This allows unsigned code execution during boot.",
                    )
                    .with_confidence(0.90)
                    .with_details(serde_json::json!({
                        "variable": "SecureBoot",
                        "value": data.get(value_offset).unwrap_or(&0),
                        "offset": format!("0x{:08X}", pos),
                    }))
                    .with_recommendation("Enable Secure Boot in firmware settings."),
                );
            }
        }

        // Search for SetupMode variable
        let setup_var_name = b"S\x00e\x00t\x00u\x00p\x00M\x00o\x00d\x00e\x00";
        if let Some(pos) = data
            .windows(setup_var_name.len())
            .position(|w| w == setup_var_name)
        {
            let value_offset = pos + setup_var_name.len() + 8;
            if value_offset < data.len() && data[value_offset] == 1 {
                findings.push(
                    Finding::new(
                        "secureboot",
                        Severity::Critical,
                        "Platform in Setup Mode",
                        "SetupMode is enabled, meaning Platform Key (PK) can be enrolled \
                         by anyone. An attacker can install their own keys.",
                    )
                    .with_confidence(0.95)
                    .with_details(serde_json::json!({
                        "variable": "SetupMode",
                        "value": 1,
                        "offset": format!("0x{:08X}", pos),
                    }))
                    .with_recommendation("Enroll a Platform Key to exit Setup Mode immediately."),
                );
            }
        }

        findings
    }
}

impl Detector for SecureBootDetector {
    fn name(&self) -> &str {
        "secureboot"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        let data = std::fs::read(target_path).map_err(DetectorError::Io)?;
        let findings = self.check_secure_boot_state(&data);
        Ok(findings)
    }
}
