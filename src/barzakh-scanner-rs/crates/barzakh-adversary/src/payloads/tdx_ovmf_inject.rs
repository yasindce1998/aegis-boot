use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct TdxOvmfInjectPayload;

impl Payload for TdxOvmfInjectPayload {
    fn name(&self) -> &str {
        "tdx_ovmf_inject"
    }

    fn arch(&self) -> Arch {
        Arch::X86_64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x4000);
        let mut data = vec![0u8; size];

        // TDVF_DESCRIPTOR magic
        let tdvf_magic = b"TDVF";
        let tdvf_offset = 0x100;
        data[tdvf_offset..tdvf_offset + tdvf_magic.len()].copy_from_slice(tdvf_magic);

        // Zeroed measurement fields (where MRTD hashes should be)
        // Leave 32-byte blocks at offsets +16 and +48 as zeros
        // (already zero from vec initialization, but explicit for clarity)

        // CFV marker within descriptor region
        let cfv_marker = b"CFV_";
        let cfv_offset = tdvf_offset + 64;
        data[cfv_offset..cfv_offset + cfv_marker.len()].copy_from_slice(cfv_marker);

        // TD-Shim handoff table markers
        let td_shim_marker = b"TD_SHIM_HOB";
        let shim_offset = 0x400;
        data[shim_offset..shim_offset + td_shim_marker.len()].copy_from_slice(td_shim_marker);

        // Injected OVMF section with tampered GUID
        let ovmf_guid = b"\x96\xB5\x82\x2B\xAB\x2D\x9E\x40\xA7\x71\x2E\x27\xB2\xF1\x37\x6D";
        let ovmf_offset = 0x800;
        data[ovmf_offset..ovmf_offset + ovmf_guid.len()].copy_from_slice(ovmf_guid);

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "confidential_vm".to_string(),
            min_severity: Severity::Critical,
        }]
    }
}
