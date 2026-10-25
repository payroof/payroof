/// Splits a CAIP-19 asset id, `eip155:N/erc20:0x…` or `eip155:N/slip44:N`, into its
/// chain and kind. Only canonical, lowercase ids are accepted.
pub fn classify(id: &str) -> Option<(&str, &'static str)> {
    let (chain, reference) = id.split_once('/')?;
    let number: u64 = chain.strip_prefix("eip155:")?.parse().ok()?;
    if number == 0 || chain != format!("eip155:{number}") {
        return None;
    }
    if let Some(contract) = reference.strip_prefix("erc20:0x") {
        (contract.len() == 40
            && contract
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && contract.bytes().any(|b| b != b'0'))
        .then_some((chain, "erc20"))
    } else {
        let coin = reference.strip_prefix("slip44:")?;
        let number: u32 = coin.parse().ok()?;
        (coin == number.to_string()).then_some((chain, "native"))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn canonical_ids() {
        assert_eq!(classify("eip155:1/slip44:60"), Some(("eip155:1", "native")));
        assert_eq!(
            classify("eip155:1/erc20:0x1111111111111111111111111111111111111111"),
            Some(("eip155:1", "erc20"))
        );
        for id in [
            "eip155:0/slip44:60",
            "eip155:01/slip44:60",
            "eip155:1/slip44:060",
            "eip155:1/erc20:0xabc",
            "eip155:1/erc20:0x0000000000000000000000000000000000000000",
            "eip155:1/erc20:0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "solana:1/slip44:501",
        ] {
            assert_eq!(classify(id), None, "{id}");
        }
    }
}
