use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct BmcSpiLateralPayload;

impl Payload for BmcSpiLateralPayload {
    fn name(&self) -> &str {
        "bmc_spi_lateral"
    }

    fn arch(&self) -> Arch {
        Arch::X86_64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x4000);
        let mut data = vec![0u8; size];

        // IPMI KCS command: NetFn=0x06 (App), OEM Cmd=0xC0
        let ipmi_offset = 0x100;
        data[ipmi_offset] = 0x06; // NetFn App
        data[ipmi_offset + 1] = 0xC0; // OEM command

        // SPI flash descriptor magic within command payload
        let spi_magic = &[0x5A, 0xA5, 0xF0, 0x0F];
        data[ipmi_offset + 4..ipmi_offset + 8].copy_from_slice(spi_magic);

        // Redfish UpdateService URI
        let redfish_path = b"/redfish/v1/UpdateService";
        let redfish_offset = 0x400;
        data[redfish_offset..redfish_offset + redfish_path.len()].copy_from_slice(redfish_path);

        // SPI descriptor near Redfish path
        let spi_near_redfish = redfish_offset + redfish_path.len() + 16;
        data[spi_near_redfish..spi_near_redfish + 4].copy_from_slice(spi_magic);

        // BMC_SPI master grant pattern
        let bmc_grant = b"BMC_SPI";
        let grant_offset = 0x800;
        data[grant_offset..grant_offset + bmc_grant.len()].copy_from_slice(bmc_grant);

        // SPI write enable (0x06) and sector erase (0xD8) commands after grant
        data[grant_offset + bmc_grant.len() + 2] = 0x06; // Write Enable
        data[grant_offset + bmc_grant.len() + 4] = 0xD8; // Sector Erase

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "bmc_spi".to_string(),
            min_severity: Severity::Critical,
        }]
    }
}
