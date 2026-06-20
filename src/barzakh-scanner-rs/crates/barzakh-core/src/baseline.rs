use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Baseline {
    #[serde(default)]
    pub pcr_values: Option<HashMap<String, String>>,
    #[serde(default)]
    pub memory_map: Option<Vec<MemoryMapEntry>>,
    #[serde(default)]
    pub boot_services_table: Option<serde_json::Value>,
    #[serde(default)]
    pub event_log: Option<Vec<serde_json::Value>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryMapEntry {
    pub address: u64,
    pub size: u64,
    #[serde(default)]
    pub mem_type: Option<String>,
}

impl Baseline {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let baseline: Baseline = serde_json::from_str(&content)?;
        Ok(baseline)
    }
}
