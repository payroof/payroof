pub fn now() -> i64 {
    chrono::Utc::now().timestamp()
}
pub fn rfc(t: i64) -> String {
    chrono::DateTime::from_timestamp(t, 0)
        .unwrap_or_default()
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}
