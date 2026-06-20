use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Info => write!(f, "info"),
            Self::Low => write!(f, "low"),
            Self::Medium => write!(f, "medium"),
            Self::High => write!(f, "high"),
            Self::Critical => write!(f, "critical"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub detector: String,
    pub severity: Severity,
    pub title: String,
    pub description: String,
    #[serde(default = "default_confidence")]
    pub confidence: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recommendation: Option<String>,
}

fn default_confidence() -> f64 {
    0.5
}

impl Finding {
    pub fn new(detector: &str, severity: Severity, title: &str, description: &str) -> Self {
        Self {
            detector: detector.to_string(),
            severity,
            title: title.to_string(),
            description: description.to_string(),
            confidence: default_confidence(),
            details: None,
            recommendation: None,
        }
    }

    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = Some(details);
        self
    }

    pub fn with_recommendation(mut self, rec: &str) -> Self {
        self.recommendation = Some(rec.to_string());
        self
    }

    pub fn with_confidence(mut self, confidence: f64) -> Self {
        self.confidence = confidence;
        self
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DetectorError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("parse error: {0}")]
    Parse(String),

    #[error("configuration error: {0}")]
    Config(String),

    #[error("{0}")]
    Other(String),
}

pub trait Detector: Send + Sync {
    fn name(&self) -> &str;
    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError>;
}
