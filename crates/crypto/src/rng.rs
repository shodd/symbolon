/// The OS CSPRNG (`getrandom`). It panics if the OS fails to provide
/// randomness, which is the only safe reaction for key generation.
///
/// On `wasm32-unknown-unknown` this is `crypto.getRandomValues` (see the
/// crate README).
pub type OsRng = rand_core::UnwrapErr<getrandom::SysRng>;

/// Returns the OS CSPRNG. Pass `&mut os_rng()` wherever an RNG is required.
pub fn os_rng() -> OsRng {
    rand_core::UnwrapErr(getrandom::SysRng)
}

#[cfg(test)]
mod tests {
    use rand_core::Rng;

    #[test]
    fn os_rng_produces_bytes() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        super::os_rng().fill_bytes(&mut a);
        super::os_rng().fill_bytes(&mut b);
        assert_ne!(a, b);
    }
}
