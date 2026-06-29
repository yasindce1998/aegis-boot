use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct BootkittyGrubPatchPayload;

impl Payload for BootkittyGrubPatchPayload {
    fn name(&self) -> &str {
        "bootkitty_grub_patch"
    }

    fn arch(&self) -> Arch {
        Arch::X86_64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x4000);
        let mut data = vec![0u8; size];

        // ELF header stub
        data[0..4].copy_from_slice(b"\x7fELF");
        data[4] = 2; // 64-bit
        data[5] = 1; // little-endian

        // Place "grub_verifiers_open" function name at offset 0x200
        let grub_pattern = b"grub_verifiers_open";
        let grub_offset = 0x200;
        data[grub_offset..grub_offset + grub_pattern.len()].copy_from_slice(grub_pattern);

        // NOP sled surrounding the function (simulates patched verification)
        let nop_start = grub_offset - 32;
        for byte in data.iter_mut().take(grub_offset).skip(nop_start) {
            *byte = 0x90;
        }

        // RET + NOP padding pattern (function replaced with immediate return)
        let ret_offset = grub_offset + grub_pattern.len() + 4;
        data[ret_offset] = 0xC3; // RET
        data[ret_offset + 1] = 0x90;
        data[ret_offset + 2] = 0x90;
        data[ret_offset + 3] = 0x90;

        // vmlinuz reference with disabled module signature check
        let vmlinuz_offset = 0x800;
        data[vmlinuz_offset..vmlinuz_offset + 7].copy_from_slice(b"vmlinuz");

        let sig_enforce = b"module.sig_enforce";
        let sig_offset = vmlinuz_offset + 32;
        data[sig_offset..sig_offset + sig_enforce.len()].copy_from_slice(sig_enforce);
        data[sig_offset + sig_enforce.len()] = 0x00; // disabled marker

        // Shim lock GUID with zeroed verification data
        let shim_guid = b"\x67\x2b\x1e\x30\x99\xcd\x5e\x9e";
        let shim_offset = 0x1000;
        data[shim_offset..shim_offset + shim_guid.len()].copy_from_slice(shim_guid);
        // Leave 128 bytes after GUID as all-zero (zeroed verification tables)

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "linux_bootchain".to_string(),
            min_severity: Severity::Critical,
        }]
    }
}
