use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct SecurebootReloaderPayload;

impl Payload for SecurebootReloaderPayload {
    fn name(&self) -> &str {
        "secureboot_reloader"
    }

    fn arch(&self) -> Arch {
        Arch::X86_64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x4000);
        let mut data = vec![0u8; size];

        // Outer PE (signed loader) at offset 0
        data[0] = b'M';
        data[1] = b'Z';
        // e_lfanew points to PE header at 0x80
        data[60..64].copy_from_slice(&0x80u32.to_le_bytes());
        data[0x80..0x84].copy_from_slice(b"PE\x00\x00");
        // Machine: x86_64
        data[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());

        // Microsoft UEFI CA marker in certificate table area
        let ca_marker = b"Microsoft Corporation UEFI CA";
        let ca_offset = 0x200;
        data[ca_offset..ca_offset + ca_marker.len()].copy_from_slice(ca_marker);

        // Embedded unsigned PE (inner payload) at 0x1000
        let inner_pe_offset = 0x1000;
        data[inner_pe_offset] = b'M';
        data[inner_pe_offset + 1] = b'Z';
        data[inner_pe_offset + 60..inner_pe_offset + 64].copy_from_slice(&0x80u32.to_le_bytes());
        data[inner_pe_offset + 0x80..inner_pe_offset + 0x84].copy_from_slice(b"PE\x00\x00");
        data[inner_pe_offset + 0x84..inner_pe_offset + 0x86]
            .copy_from_slice(&0x8664u16.to_le_bytes());

        // reloader.efi path reference
        let reloader_path = b"reloader.efi";
        let path_offset = 0x2000;
        data[path_offset..path_offset + reloader_path.len()].copy_from_slice(reloader_path);

        // cloak.dat payload file reference
        let cloak_path = b"cloak.dat";
        let cloak_offset = 0x2100;
        data[cloak_offset..cloak_offset + cloak_path.len()].copy_from_slice(cloak_path);

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "reloader".to_string(),
            min_severity: Severity::Critical,
        }]
    }
}
