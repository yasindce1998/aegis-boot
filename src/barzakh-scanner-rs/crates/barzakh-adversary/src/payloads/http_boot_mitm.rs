use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct HttpBootMitmPayload;

impl Payload for HttpBootMitmPayload {
    fn name(&self) -> &str {
        "http_boot_mitm"
    }

    fn arch(&self) -> Arch {
        Arch::X86_64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x4000);
        let mut data = vec![0u8; size];

        // HTTP response header with EFI content type
        let http_resp = b"HTTP/1.1 200 OK\r\nContent-Type: application/efi\r\n\r\n";
        data[0..http_resp.len()].copy_from_slice(http_resp);

        // Embedded PE right after HTTP headers
        let pe_offset = http_resp.len();
        data[pe_offset] = b'M';
        data[pe_offset + 1] = b'Z';
        data[pe_offset + 60..pe_offset + 64].copy_from_slice(&0x80u32.to_le_bytes());
        data[pe_offset + 0x80..pe_offset + 0x84].copy_from_slice(b"PE\x00\x00");
        data[pe_offset + 0x84..pe_offset + 0x86].copy_from_slice(&0x8664u16.to_le_bytes());

        // HTTPBoot UEFI variable name (UTF-16LE)
        let httpboot_var = b"H\x00T\x00T\x00P\x00B\x00o\x00o\x00t\x00";
        let var_offset = 0x1000;
        data[var_offset..var_offset + httpboot_var.len()].copy_from_slice(httpboot_var);

        // TlsVerify=FALSE marker (certificate validation disabled)
        let tls_verify = b"TlsVerify";
        let tls_offset = var_offset + httpboot_var.len() + 8;
        data[tls_offset..tls_offset + tls_verify.len()].copy_from_slice(tls_verify);
        // FALSE value (0x00)
        data[tls_offset + tls_verify.len() + 1] = 0x00;

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "http_boot".to_string(),
            min_severity: Severity::High,
        }]
    }
}
