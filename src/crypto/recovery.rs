/// What a recovery signature covers: the server origin and the one-time challenge. The
/// challenge was issued for exactly one project (the recovery key's), so the project is
/// bound through it and never chosen by the signer.
pub fn recovery_message(origin: &str, id: &str, challenge: &str) -> String {
    format!("payroof-recovery-v2\n{origin}\n{id}\n{challenge}\n")
}
