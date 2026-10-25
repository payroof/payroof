pub fn project(s: &str) -> bool {
    (1..=63).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && s.as_bytes().first().is_some_and(u8::is_ascii_alphanumeric)
        && s.as_bytes().last().is_some_and(u8::is_ascii_alphanumeric)
}
pub fn reference(s: &str) -> bool {
    (1..=128).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn opaque() {
        assert!(reference("Paths.ORDER~42"));
        assert!(reference("_"));
        for s in ["", "a/b", "é", "a b"] {
            assert!(!reference(s));
        }
    }
    #[test]
    fn project_names() {
        assert!(project("a"));
        assert!(project("my-store"));
        assert!(project("projects"));
        for s in ["A", "a-", "-a", "", "_"] {
            assert!(!project(s));
        }
    }
}
