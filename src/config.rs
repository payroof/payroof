use serde::Deserialize;
use std::net::SocketAddr;
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub bind: SocketAddr,
    pub origin: String,
    /// Other origins this server is reached at (for example its loopback address next
    /// to a LAN one in local development). Recovery signatures may name any of them.
    #[serde(default)]
    pub origin_aliases: Vec<String>,
    pub database: String,
    #[serde(default)]
    pub development: bool,
    pub chains: Vec<Chain>,
    #[serde(default)]
    pub limits: Limits,
    #[serde(default)]
    pub trusted_proxies: Vec<crate::security::trusted_proxy::Cidr>,
}
#[derive(Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Limits {
    pub project_per_minute: i64,
    pub pairing_per_minute: i64,
    pub recovery_per_minute: i64,
    pub challenge_per_minute: i64,
    pub public_per_day: i64,
    pub reads_per_minute: i64,
    pub mutations_per_minute: i64,
    pub allocations_per_minute: i64,
    pub paths_per_minute: i64,
    pub general_body: usize,
    pub pairing_body: usize,
    pub project_body: usize,
    pub concurrency: usize,
    pub project_concurrency: usize,
    pub pairing_concurrency: usize,
    pub allocation_concurrency: usize,
    pub pairing_capacity: i64,
    pub path_page: u32,
    pub rate_limit_entries: i64,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            project_per_minute: 3,
            pairing_per_minute: 5,
            recovery_per_minute: 5,
            challenge_per_minute: 10,
            public_per_day: 30,
            reads_per_minute: 300,
            mutations_per_minute: 30,
            allocations_per_minute: 120,
            paths_per_minute: 30,
            general_body: 16384,
            pairing_body: 2048,
            project_body: 32768,
            concurrency: 64,
            project_concurrency: 8,
            pairing_concurrency: 8,
            allocation_concurrency: 32,
            pairing_capacity: 10000,
            path_page: 1000,
            rate_limit_entries: 100000,
        }
    }
}
impl Limits {
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            [
                self.project_per_minute,
                self.pairing_per_minute,
                self.recovery_per_minute,
                self.challenge_per_minute,
                self.public_per_day,
                self.reads_per_minute,
                self.mutations_per_minute,
                self.allocations_per_minute,
                self.paths_per_minute,
                self.pairing_capacity,
                self.rate_limit_entries
            ]
            .iter()
            .all(|v| *v > 0 && *v <= 1_000_000),
            "invalid rate or capacity limit"
        );
        anyhow::ensure!(
            [self.general_body, self.pairing_body, self.project_body]
                .iter()
                .all(|v| *v > 0 && *v <= 1_048_576)
                && (1..=1024).contains(&self.concurrency)
                && [
                    self.project_concurrency,
                    self.pairing_concurrency,
                    self.allocation_concurrency
                ]
                .iter()
                .all(|v| (1..=1024).contains(v))
                && (1..=1000).contains(&self.path_page),
            "invalid body/concurrency/page limit"
        );
        Ok(())
    }
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Chain {
    pub id: String,
    /// Display name shown to integrations, e.g. "Ethereum".
    pub name: String,
    pub rpc: String,
    pub confirmations: u32,
    /// First block to scan. Omitted: the chain's head when Payroof first runs.
    pub start_height: Option<u64>,
    pub assets: Vec<Asset>,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Asset {
    pub id: String,
    pub kind: String,
    pub symbol: String,
    pub decimals: u8,
}
/// An origin (scheme, host, port and nothing else), HTTPS unless in development.
fn check_origin(raw: &str, development: bool) -> anyhow::Result<()> {
    let url = url::Url::parse(raw)?;
    anyhow::ensure!(
        url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none()
            && url.path() == "/",
        "origin must be an origin"
    );
    anyhow::ensure!(
        url.scheme() == "https"
            || (development && url.scheme() == "http" && url.host_str().is_some()),
        "HTTPS required"
    );
    Ok(())
}
impl Config {
    /// The server's origin, then its aliases, without trailing slashes.
    pub fn origins(&self) -> impl Iterator<Item = &str> {
        std::iter::once(&self.origin)
            .chain(&self.origin_aliases)
            .map(|origin| origin.trim_end_matches('/'))
    }
    pub fn load(path: &str) -> anyhow::Result<Self> {
        let c: Self = toml::from_str(&std::fs::read_to_string(path)?)?;
        for origin in std::iter::once(&c.origin).chain(&c.origin_aliases) {
            check_origin(origin, c.development)?;
        }
        c.limits.validate()?;
        anyhow::ensure!(!c.chains.is_empty(), "configure at least one chain");
        let mut chains = std::collections::BTreeSet::new();
        for chain in &c.chains {
            anyhow::ensure!(
                chains.insert(&chain.id)
                    && (1..=40).contains(&chain.name.chars().count())
                    && chain.name.trim() == chain.name
                    && !chain.name.chars().any(char::is_control)
                    && chain.confirmations > 0
                    && chain.start_height.is_none_or(|h| h <= i64::MAX as u64),
                "invalid chain config"
            );
            let id: u64 = chain
                .id
                .strip_prefix("eip155:")
                .ok_or_else(|| anyhow::anyhow!("unsupported family"))?
                .parse()?;
            anyhow::ensure!(
                id > 0 && chain.id == format!("eip155:{id}"),
                "invalid chain id"
            );
            let rpc = url::Url::parse(&chain.rpc)?;
            anyhow::ensure!(
                rpc.username().is_empty() && rpc.password().is_none() && rpc.fragment().is_none(),
                "invalid RPC"
            );
            anyhow::ensure!(
                rpc.scheme() == "https"
                    || (c.development && rpc.scheme() == "http" && rpc.host_str().is_some()),
                "HTTPS RPC required"
            );
            let mut assets = std::collections::BTreeSet::new();
            for a in &chain.assets {
                anyhow::ensure!(
                    assets.insert(&a.id)
                        && crate::domain::asset::classify(&a.id)
                            == Some((chain.id.as_str(), a.kind.as_str()))
                        && a.decimals <= 36
                        && a.symbol.len() <= 16,
                    "invalid asset {}",
                    a.id
                );
            }
        }
        Ok(c)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn container_http_is_explicitly_development_only() {
        let source = include_str!("../config/payroof.local.toml")
            .replace("127.0.0.1:8080\"", "0.0.0.0:8080\"")
            .replace("http://0.0.0.0:8080", "http://payroof:8080")
            .replace("http://127.0.0.1:8545", "http://anvil:8545");
        let path = std::env::temp_dir().join(format!(
            "payroof-config-{}.toml",
            crate::security::secret::id("test_").unwrap()
        ));
        std::fs::write(&path, &source).unwrap();
        assert!(Config::load(path.to_str().unwrap()).is_ok());
        std::fs::write(
            &path,
            source.replace("development = true", "development = false"),
        )
        .unwrap();
        assert!(Config::load(path.to_str().unwrap()).is_err());
        std::fs::remove_file(path).unwrap();
    }
    #[test]
    fn the_deployment_example_is_valid_and_https_only() {
        let source = include_str!("../config/payroof.example.toml");
        let path = std::env::temp_dir().join(format!(
            "payroof-example-{}.toml",
            crate::security::secret::id("test_").unwrap()
        ));
        std::fs::write(&path, source).unwrap();
        let config = Config::load(path.to_str().unwrap()).unwrap();
        assert!(!config.development && config.chains.len() > 1);
        assert!(config.chains.iter().all(|c| c.start_height.is_none()));
        std::fs::write(&path, source.replacen("https://", "http://", 2)).unwrap();
        assert!(Config::load(path.to_str().unwrap()).is_err());
        std::fs::remove_file(path).unwrap();
    }
    #[test]
    fn limits_are_typed_and_bounded() {
        assert!(Limits::default().validate().is_ok());
        let l = Limits {
            concurrency: 0,
            ..Limits::default()
        };
        assert!(l.validate().is_err());
        let l = Limits {
            path_page: 1001,
            ..Limits::default()
        };
        assert!(l.validate().is_err());
        let l = Limits {
            project_per_minute: -1,
            ..Limits::default()
        };
        assert!(l.validate().is_err());
        assert!(toml::from_str::<Limits>("unknown=1").is_err());
        assert!(toml::from_str::<Limits>("pairing_body='huge'").is_err());
    }
    #[test]
    fn asset_kind_and_contract_must_match_canonical_identity() {
        let source = include_str!("../config/payroof.local.toml");
        let path = std::env::temp_dir().join(format!(
            "payroof-assets-{}.toml",
            crate::security::secret::id("test_").unwrap()
        ));
        for invalid in [
            source.replace("kind = \"native\"", "kind = \"erc20\""),
            source.replace("slip44:60", "slip44:060"),
            source.replace("slip44:60", "erc20:0xabc"),
        ] {
            std::fs::write(&path, invalid).unwrap();
            assert!(Config::load(path.to_str().unwrap()).is_err());
        }
        let valid = source
            .replace(
                "slip44:60",
                "erc20:0x1111111111111111111111111111111111111111",
            )
            .replace("kind = \"native\"", "kind = \"erc20\"");
        std::fs::write(&path, valid).unwrap();
        assert!(Config::load(path.to_str().unwrap()).is_ok());
        std::fs::remove_file(path).unwrap();
    }
}
