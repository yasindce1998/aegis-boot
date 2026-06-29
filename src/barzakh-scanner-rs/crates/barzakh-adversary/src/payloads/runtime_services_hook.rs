use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct RuntimeServicesHookPayload;

impl Payload for RuntimeServicesHookPayload {
    fn name(&self) -> &str {
        "runtime_services_hook"
    }

    fn arch(&self) -> Arch {
        Arch::X86_64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x4000);
        let mut data = vec![0u8; size];

        // RUNTSERV signature (EFI Runtime Services Table)
        let runtserv_sig: u64 = 0x56524553_544E5552;
        let table_offset = 0x1000;
        data[table_offset..table_offset + 8].copy_from_slice(&runtserv_sig.to_le_bytes());

        // Table revision
        data[table_offset + 8..table_offset + 12].copy_from_slice(&0x0002_0046u32.to_le_bytes());

        // Header size (72 bytes for EFI_TABLE_HEADER)
        data[table_offset + 12..table_offset + 16].copy_from_slice(&72u32.to_le_bytes());

        // Deliberately invalid CRC32 (mismatch triggers detection)
        data[table_offset + 16..table_offset + 20].copy_from_slice(&0xDEADBEEFu32.to_le_bytes());

        // GetVariable pointer — redirect to suspicious address range
        // (pointing to runtime memory area outside normal UEFI space)
        let get_variable_offset = table_offset + 72;
        let suspicious_addr: u64 = 0x0000_7FFF_DEAD_0000;
        data[get_variable_offset..get_variable_offset + 8]
            .copy_from_slice(&suspicious_addr.to_le_bytes());

        // SetVariable pointer — also redirected
        let set_variable_offset = table_offset + 72 + 32;
        let suspicious_addr2: u64 = 0x0000_7FFF_DEAD_1000;
        data[set_variable_offset..set_variable_offset + 8]
            .copy_from_slice(&suspicious_addr2.to_le_bytes());

        // Covert channel GUID marker
        let covert_guid = b"\xAA\xBB\xCC\xDD\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC";
        let guid_offset = 0x2000;
        data[guid_offset..guid_offset + covert_guid.len()].copy_from_slice(covert_guid);

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "runtime".to_string(),
            min_severity: Severity::Critical,
        }]
    }
}
