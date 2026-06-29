use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct SbatRollbackPayload;

impl Payload for SbatRollbackPayload {
    fn name(&self) -> &str {
        "sbat_rollback"
    }

    fn arch(&self) -> Arch {
        Arch::X86_64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x2000);
        let mut data = vec![0u8; size];

        // UEFI variable: SbatLevel (UTF-16LE name)
        let sbat_var_name = b"S\x00b\x00a\x00t\x00L\x00e\x00v\x00e\x00l\x00";
        let var_offset = 0x100;
        data[var_offset..var_offset + sbat_var_name.len()].copy_from_slice(sbat_var_name);

        // Two bytes padding (null terminator)
        let attrs_offset = var_offset + sbat_var_name.len() + 2;

        // Variable attributes: BS+RT+AT (0x27)
        let attrs: u32 = 0x27;
        data[attrs_offset..attrs_offset + 4].copy_from_slice(&attrs.to_le_bytes());

        // 4 bytes data size, then value starts
        let value_offset = attrs_offset + 8;
        let sbat_value = b"sbat,1,2021030218\n";
        data[value_offset..value_offset + sbat_value.len()].copy_from_slice(sbat_value);

        // Multiple sbat headers to trigger metadata tampering detection
        let sbat_header = b"sbat,";
        for i in 0..5 {
            let offset = 0x800 + i * 0x100;
            if offset + sbat_header.len() < size {
                data[offset..offset + sbat_header.len()].copy_from_slice(sbat_header);
                data[offset + sbat_header.len()] = b'1'; // Rolled-back generation
            }
        }

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "sbat".to_string(),
            min_severity: Severity::High,
        }]
    }
}
