//! Bounded, public catalogue comparison DTOs. No account or device credentials.
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CatalogueFieldChange {
    pub key: String,
    pub label: String,
    pub before: String,
    pub after: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub added: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub removed: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub added_count: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub removed_count: Option<usize>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CatalogueRelayChange {
    pub relay: Option<String>,
    pub state: String,
    pub fields: Vec<CatalogueFieldChange>,
    pub ss_before_count: Option<usize>,
    pub ss_after_count: Option<usize>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CatalogueChanges {
    pub checked_at: u64,
    pub baseline_available: bool,
    pub catalogue_changed: Option<bool>,
    pub added_count: usize,
    pub removed_count: usize,
    pub changed_count: usize,
    pub shared_changes: Vec<CatalogueFieldChange>,
    pub current_relay: CatalogueRelayChange,
    pub changed_relays: Vec<CatalogueRelayChange>,
    pub truncated_count: usize,
}
