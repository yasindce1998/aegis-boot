pub mod attestation;
pub mod differ;
pub mod entropy;
pub mod eventlog;
pub mod firmware_volume;
pub mod hook;
pub mod introspection;
pub mod mbr;
pub mod memory;
pub mod pcr;
pub mod pcr_oracle;
pub mod pcr_replay;
pub mod runtime;
pub mod secureboot;
pub mod self_erasure;
pub mod smm;
pub mod spi_integrity;
pub mod symexec;
pub mod timetravel;

use crate::baseline::Baseline;
use crate::detector::Detector;

pub fn create_all_detectors(baseline: Option<Baseline>) -> Vec<Box<dyn Detector>> {
    vec![
        Box::new(pcr::PcrDetector::new(baseline.clone())),
        Box::new(memory::MemoryDetector::new(baseline.clone())),
        Box::new(hook::HookDetector::new(baseline.clone())),
        Box::new(eventlog::EventLogDetector::new()),
        Box::new(entropy::EntropyAnalyzer::new()),
        Box::new(secureboot::SecureBootDetector::new(baseline.clone())),
        Box::new(runtime::RuntimeHookDetector::new(baseline.clone())),
        Box::new(smm::SmmDetector::new()),
        Box::new(firmware_volume::FirmwareVolumeDetector::new()),
        Box::new(spi_integrity::SpiIntegrityDetector::new(baseline.clone())),
        Box::new(self_erasure::SelfErasureDetector::new()),
        Box::new(mbr::MbrDetector::new()),
        Box::new(pcr_oracle::PcrOracleDetector::new(baseline.clone())),
        Box::new(differ::FirmwareDifferDetector::new(baseline.clone())),
        Box::new(attestation::AttestationDetector::new()),
        Box::new(introspection::LiveDetector::new()),
        Box::new(timetravel::TimeTravelDetector::new()),
        Box::new(symexec::SymExecDetector::new()),
    ]
}
