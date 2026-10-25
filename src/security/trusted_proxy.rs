use serde::{Deserialize, Deserializer};
use std::{net::IpAddr, str::FromStr};
#[derive(Clone, Debug)]
pub struct Cidr {
    ip: IpAddr,
    prefix: u8,
}
impl FromStr for Cidr {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (ip, prefix) = s
            .split_once('/')
            .ok_or_else(|| anyhow::anyhow!("proxy requires CIDR"))?;
        let ip: IpAddr = ip.parse()?;
        let prefix: u8 = prefix.parse()?;
        anyhow::ensure!(
            prefix <= if ip.is_ipv4() { 32 } else { 128 },
            "invalid CIDR prefix"
        );
        Ok(Self { ip, prefix })
    }
}
impl<'de> Deserialize<'de> for Cidr {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        String::deserialize(d)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}
impl Cidr {
    fn contains(&self, ip: IpAddr) -> bool {
        match (self.ip, ip) {
            (IpAddr::V4(a), IpAddr::V4(b)) => {
                self.prefix == 0
                    || (u32::from(a) >> (32 - self.prefix)) == (u32::from(b) >> (32 - self.prefix))
            }
            (IpAddr::V6(a), IpAddr::V6(b)) => {
                self.prefix == 0
                    || (u128::from(a) >> (128 - self.prefix))
                        == (u128::from(b) >> (128 - self.prefix))
            }
            _ => false,
        }
    }
}
/// Walk from the socket boundary, never trust the attacker-controlled leftmost hop.
/// Malformed, duplicate, or ambiguous forwarding headers fail back to the socket IP.
pub fn client_ip(peer: IpAddr, h: &axum::http::HeaderMap, trusted: &[Cidr]) -> IpAddr {
    let is_trusted = |ip| trusted.iter().any(|c| c.contains(ip));
    if !is_trusted(peer) {
        return peer;
    }
    let forwarded = h.contains_key("forwarded");
    let key = if forwarded {
        "forwarded"
    } else {
        "x-forwarded-for"
    };
    if (forwarded && h.contains_key("x-forwarded-for")) || h.get_all(key).iter().count() != 1 {
        return peer;
    }
    let Some(raw) = h.get(key).and_then(|v| v.to_str().ok()) else {
        return peer;
    };
    let hops: Option<Vec<IpAddr>> = raw
        .split(',')
        .map(|s| {
            if forwarded {
                forwarded_ip(s)
            } else {
                s.trim().parse().ok()
            }
        })
        .collect();
    let Some(hops) = hops else {
        return peer;
    };
    if hops.is_empty() || hops.len() > 32 {
        return peer;
    }
    let mut current = peer;
    for ip in hops.into_iter().rev() {
        if !is_trusted(current) {
            break;
        }
        current = ip;
    }
    current
}
fn forwarded_ip(hop: &str) -> Option<IpAddr> {
    let mut found = None;
    for param in hop.split(';') {
        let (key, value) = param.trim().split_once('=')?;
        if !key.eq_ignore_ascii_case("for") {
            continue;
        }
        if found.is_some() {
            return None;
        }
        let value = if value.starts_with('"') {
            value.strip_prefix('"')?.strip_suffix('"')?
        } else {
            value
        };
        let ip = if value.starts_with('[') {
            let (ip, tail) = value.strip_prefix('[')?.split_once(']')?;
            if !tail.is_empty() {
                tail.strip_prefix(':')?.parse::<u16>().ok()?;
            }
            IpAddr::V6(ip.parse().ok()?)
        } else {
            value
                .parse()
                .ok()
                .or_else(|| value.parse::<std::net::SocketAddr>().ok().map(|a| a.ip()))?
        };
        found = Some(ip);
    }
    found
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn forwarded_and_ambiguous_headers() {
        let trusted = vec!["10.0.0.0/24".parse().unwrap()];
        let peer = "10.0.0.1".parse().unwrap();
        let mut h = axum::http::HeaderMap::new();
        h.insert(
            "forwarded",
            "for=\"[2001:4860::1]:1234\";proto=https, for=10.0.0.2"
                .parse()
                .unwrap(),
        );
        assert_eq!(
            client_ip(peer, &h, &trusted),
            "2001:4860::1".parse::<IpAddr>().unwrap()
        );
        for value in [
            "for=unknown",
            "for=_hidden",
            "for=1.1.1.1;for=8.8.8.8",
            "for=\"[::1]:bad\"",
            "for=\"unterminated",
        ] {
            h.insert("forwarded", value.parse().unwrap());
            assert_eq!(client_ip(peer, &h, &trusted), peer);
        }
        h.insert("forwarded", "for=8.8.8.8".parse().unwrap());
        h.append("forwarded", "for=1.1.1.1".parse().unwrap());
        assert_eq!(client_ip(peer, &h, &trusted), peer);
        h.remove("forwarded");
        h.insert("forwarded", "for=8.8.8.8".parse().unwrap());
        h.insert("x-forwarded-for", "1.1.1.1".parse().unwrap());
        assert_eq!(client_ip(peer, &h, &trusted), peer);
    }
    #[test]
    fn boundaries_and_multihop() {
        let trusted: Vec<Cidr> = vec![
            "10.0.0.0/24".parse().unwrap(),
            "2001:db8::/64".parse().unwrap(),
        ];
        let mut h = axum::http::HeaderMap::new();
        h.insert(
            "x-forwarded-for",
            "1.1.1.1, 8.8.8.8, 10.0.0.2".parse().unwrap(),
        );
        assert_eq!(
            client_ip("10.0.0.1".parse().unwrap(), &h, &trusted),
            "8.8.8.8".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            client_ip("10.0.1.1".parse().unwrap(), &h, &trusted),
            "10.0.1.1".parse::<IpAddr>().unwrap()
        );
        h.insert("x-forwarded-for", "2001:4860::1".parse().unwrap());
        assert_eq!(
            client_ip("2001:db8::ffff".parse().unwrap(), &h, &trusted),
            "2001:4860::1".parse::<IpAddr>().unwrap()
        );
        for malformed in ["bad", "8.8.8.8,", "unknown", "[::1]:80", "8.8.8.8, garbage"] {
            h.insert("x-forwarded-for", malformed.parse().unwrap());
            assert_eq!(
                client_ip("10.0.0.1".parse().unwrap(), &h, &trusted),
                "10.0.0.1".parse::<IpAddr>().unwrap()
            );
        }
        assert!("10.0.0.0/33".parse::<Cidr>().is_err());
        assert!("::/129".parse::<Cidr>().is_err());
    }
}
