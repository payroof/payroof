use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Permission {
    References,
    Paths,
    Webhooks,
    Access,
}
pub const ALL: [Permission; 4] = [
    Permission::References,
    Permission::Paths,
    Permission::Webhooks,
    Permission::Access,
];
pub fn validate(p: &[Permission]) -> anyhow::Result<()> {
    anyhow::ensure!(!p.is_empty() && p.len() <= ALL.len(), "invalid permissions");
    for (i, a) in p.iter().enumerate() {
        anyhow::ensure!(!p[..i].contains(a), "duplicate permission");
    }
    Ok(())
}
