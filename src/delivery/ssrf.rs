//! SSRF protection: validate and pin the exact IP that reqwest will connect to.
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};
use url::Url;

pub async fn webhook_client(
    raw: &str,
    allow_private: bool,
    timeout: Duration,
) -> anyhow::Result<reqwest::Client> {
    let url = Url::parse(raw)?;
    anyhow::ensure!(
        url.scheme() == "https" || (allow_private && url.scheme() == "http"),
        "webhook URL must be HTTPS"
    );
    anyhow::ensure!(
        url.username().is_empty() && url.password().is_none() && url.fragment().is_none(),
        "webhook URL credentials/fragments not allowed"
    );
    let host = url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("missing webhook host"))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| anyhow::anyhow!("missing webhook port"))?;
    anyhow::ensure!(allow_private || port == 443, "unsafe webhook port");
    let addresses: Vec<SocketAddr> = tokio::time::timeout(
        Duration::from_secs(3),
        tokio::net::lookup_host((host, port)),
    )
    .await??
    .collect();
    anyhow::ensure!(!addresses.is_empty(), "webhook hostname did not resolve");
    if !allow_private {
        for address in &addresses {
            anyhow::ensure!(
                !forbidden_ip(address.ip()),
                "webhook resolves to forbidden IP"
            );
        }
    }
    // Pin validated DNS addresses in a fresh client for each delivery attempt.
    // TLS verification and SNI still use the original hostname, never an attacker-provided IP.
    // Webhook receivers' responses are not read: no need to advertise compression.
    Ok(reqwest::Client::builder()
        .no_gzip()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .timeout(timeout)
        .connect_timeout(Duration::from_secs(3))
        .resolve_to_addrs(host, &addresses)
        .build()?)
}

pub async fn validate_webhook(raw: &str, allow_private: bool) -> anyhow::Result<()> {
    webhook_client(raw, allow_private, Duration::from_secs(3))
        .await
        .map(|_| ())
}
fn forbidden_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => forbidden_v4(v),
        IpAddr::V6(v) => forbidden_v6(v),
    }
}
fn forbidden_v4(v: Ipv4Addr) -> bool {
    let o = v.octets();
    v.is_private()
        || v.is_loopback()
        || v.is_link_local()
        || o[0] == 0
        || o[0] >= 224
        || (o[0] == 100 && (64..=127).contains(&o[1]))
        || (o[0] == 192 && o[1] == 0)
        || (o[0] == 198 && (18..=19).contains(&o[1]))
        || (o[0] == 198 && o[1] == 51 && o[2] == 100)
        || (o[0] == 203 && o[1] == 0 && o[2] == 113)
}
fn forbidden_v6(v: Ipv6Addr) -> bool {
    (v.segments()[0] & 0xe000) != 0x2000
        || (v.segments()[0] == 0x2001 && (v.segments()[1] <= 0x1ff || v.segments()[1] == 0xdb8))
        || (v.segments()[0] == 0x2002)
        || v.is_loopback()
        || v.is_multicast()
        || v.is_unspecified()
        || v.to_ipv4_mapped().is_some_and(forbidden_v4)
        || (v.segments()[0] & 0xfe00) == 0xfc00
        || (v.segments()[0] & 0xffc0) == 0xfe80
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reject_private_destinations() {
        assert!(forbidden_ip("127.0.0.1".parse().unwrap()));
        assert!(forbidden_ip("169.254.169.254".parse().unwrap()));
        assert!(forbidden_ip("::1".parse().unwrap()));
        assert!(forbidden_ip("::ffff:127.0.0.1".parse().unwrap()));
        assert!(!forbidden_ip("8.8.8.8".parse().unwrap()));
    }
}
