use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

const EFI_FV_SIGNATURE: &[u8] = b"_FVH";
#[allow(dead_code)]
const EFI_FFS_HEADER_SIZE: usize = 24;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
#[allow(dead_code)]
enum FfsFileType {
    Raw = 0x01,
    Freeform = 0x02,
    SecurityCore = 0x03,
    PeiCore = 0x04,
    DxeCore = 0x05,
    Peim = 0x06,
    Driver = 0x07,
    Application = 0x09,
    FirmwareVolumeImage = 0x0B,
    Unknown = 0xFF,
}

impl From<u8> for FfsFileType {
    fn from(val: u8) -> Self {
        match val {
            0x01 => Self::Raw,
            0x02 => Self::Freeform,
            0x03 => Self::SecurityCore,
            0x04 => Self::PeiCore,
            0x05 => Self::DxeCore,
            0x06 => Self::Peim,
            0x07 => Self::Driver,
            0x09 => Self::Application,
            0x0B => Self::FirmwareVolumeImage,
            _ => Self::Unknown,
        }
    }
}

pub struct FirmwareVolumeDetector;

impl Default for FirmwareVolumeDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl FirmwareVolumeDetector {
    pub fn new() -> Self {
        Self
    }

    fn find_firmware_volumes(&self, data: &[u8]) -> Vec<usize> {
        let mut offsets = Vec::new();
        let mut pos = 0;
        while pos + 4 <= data.len() {
            if let Some(offset) = data[pos..].windows(4).position(|w| w == EFI_FV_SIGNATURE) {
                let fv_start = pos + offset.saturating_sub(40); // FV header starts before _FVH
                offsets.push(fv_start);
                pos = pos + offset + 4;
            } else {
                break;
            }
        }
        offsets
    }

    fn check_fv_integrity(&self, data: &[u8], fv_offset: usize) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Check FV header checksum
        if fv_offset + 56 > data.len() {
            return findings;
        }

        let fv_length = u64::from_le_bytes(
            data[fv_offset + 32..fv_offset + 40]
                .try_into()
                .unwrap_or([0; 8]),
        ) as usize;

        if fv_length == 0 || fv_offset + fv_length > data.len() {
            return findings;
        }

        // Header checksum (16-bit sum should be 0)
        let header_length = u16::from_le_bytes(
            data[fv_offset + 48..fv_offset + 50]
                .try_into()
                .unwrap_or([0; 2]),
        ) as usize;

        if header_length > 0 && fv_offset + header_length <= data.len() {
            let mut sum: u16 = 0;
            for chunk in data[fv_offset..fv_offset + header_length].chunks(2) {
                let word = if chunk.len() == 2 {
                    u16::from_le_bytes([chunk[0], chunk[1]])
                } else {
                    chunk[0] as u16
                };
                sum = sum.wrapping_add(word);
            }

            if sum != 0 {
                findings.push(
                    Finding::new(
                        "firmware_volume",
                        Severity::High,
                        "Firmware Volume header checksum failure",
                        &format!(
                            "FV at offset 0x{:08X} has invalid header checksum (0x{:04X}). \
                             Volume may have been tampered with.",
                            fv_offset, sum
                        ),
                    )
                    .with_confidence(0.85)
                    .with_details(serde_json::json!({
                        "fv_offset": format!("0x{:08X}", fv_offset),
                        "fv_length": fv_length,
                        "checksum": format!("0x{:04X}", sum),
                    })),
                );
            }
        }

        findings
    }
}

impl Detector for FirmwareVolumeDetector {
    fn name(&self) -> &str {
        "firmware_volume"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        let data = std::fs::read(target_path).map_err(DetectorError::Io)?;
        let mut findings = Vec::new();

        let fv_offsets = self.find_firmware_volumes(&data);

        if fv_offsets.is_empty() && data.len() > 0x10000 {
            findings.push(Finding::new(
                "firmware_volume",
                Severity::Medium,
                "No firmware volumes found",
                "No EFI Firmware Volume headers found in image. \
                 May indicate the image is corrupted or not a valid UEFI firmware.",
            ));
            return Ok(findings);
        }

        for &offset in &fv_offsets {
            findings.extend(self.check_fv_integrity(&data, offset));
        }

        Ok(findings)
    }
}
