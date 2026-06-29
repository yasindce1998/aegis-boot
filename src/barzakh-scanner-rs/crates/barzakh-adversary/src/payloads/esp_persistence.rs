use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct EspPersistencePayload;

impl Payload for EspPersistencePayload {
    fn name(&self) -> &str {
        "esp_persistence"
    }

    fn arch(&self) -> Arch {
        Arch::X86_64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x4000);
        let mut data = vec![0u8; size];

        // FAT32 boot sector with non-standard jump (indicates modification)
        data[0] = 0x90; // NOP instead of standard JMP (0xEB)
        data[510] = 0x55;
        data[511] = 0xAA; // Boot signature

        // Multiple EFI boot path references (ESP persistence pattern)
        let efi_path = b"\\EFI\\Boot\\";
        let paths = [0x200, 0x400, 0x600, 0x800];
        for &offset in &paths {
            if offset + efi_path.len() < size {
                data[offset..offset + efi_path.len()].copy_from_slice(efi_path);
            }
        }

        // bootx64.efi reference followed by injected PE
        let bootx64 = b"bootx64.efi";
        let boot_offset = 0x1000;
        data[boot_offset..boot_offset + bootx64.len()].copy_from_slice(bootx64);

        // Injected DXE loader PE at offset after bootx64 reference
        let pe_offset = boot_offset + bootx64.len() + 32;
        data[pe_offset] = b'M';
        data[pe_offset + 1] = b'Z';
        data[pe_offset + 60..pe_offset + 64].copy_from_slice(&0x80u32.to_le_bytes());
        data[pe_offset + 0x80..pe_offset + 0x84].copy_from_slice(b"PE\x00\x00");

        // Windows Boot Manager GUID
        let win_guid = b"\x04\x06\x97\x9D\x21\x41\xB6\x40\xA2\x71\x12\x82\x88\x72\x67\x98";
        let guid_offset = 0x2000;
        data[guid_offset..guid_offset + win_guid.len()].copy_from_slice(win_guid);

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "esp_integrity".to_string(),
            min_severity: Severity::Critical,
        }]
    }
}
