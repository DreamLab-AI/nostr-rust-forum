//! The migrator's own key, read from the environment.
//!
//! The key is a relay admin's secret. It is taken only from
//! [`IDENTITY_ENV`], never from a command-line flag (flags land in shell
//! history and `ps` output), and no error message ever echoes it.

use nostr_bbs_core::keys::SecretKey;
use thiserror::Error;
use zeroize::Zeroizing;

/// Environment variable holding the migrator's secret key, as 64 hex
/// characters or an `nsec1…` string.
pub const IDENTITY_ENV: &str = "NOSTR_BBS_MIGRATE_KEY";

/// Why the migrator key could not be loaded. The messages never contain any
/// part of the key.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum IdentityError {
    /// [`IDENTITY_ENV`] is unset or empty.
    #[error("{IDENTITY_ENV} is not set")]
    Missing,
    /// The value is neither 64 hex characters nor a valid `nsec1…` string.
    #[error("{IDENTITY_ENV} is not a 64-hex secret key or an nsec")]
    Malformed,
    /// The value decodes to 32 bytes that are not a valid secp256k1 scalar.
    #[error("{IDENTITY_ENV} is not a valid secp256k1 secret key")]
    InvalidScalar,
}

/// Parse a secret key given as 64 hex characters or as `nsec1…`.
///
/// Surrounding whitespace is ignored. Intermediate copies of the key are
/// zeroised before returning.
///
/// ```
/// use nostr_bbs_zone_migrate::identity::parse_identity;
/// let sk = parse_identity(&"11".repeat(32)).unwrap();
/// assert_eq!(sk.as_bytes(), &[0x11; 32]);
/// assert!(parse_identity("not a key").is_err());
/// ```
pub fn parse_identity(raw: &str) -> Result<SecretKey, IdentityError> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err(IdentityError::Missing);
    }
    let hex_form: Zeroizing<String> = if raw.starts_with("nsec1") {
        Zeroizing::new(
            nostr_bbs_core::nip19::decode_nsec(raw).map_err(|_| IdentityError::Malformed)?,
        )
    } else {
        Zeroizing::new(raw.to_string())
    };
    if hex_form.len() != 64 {
        return Err(IdentityError::Malformed);
    }
    let mut bytes = Zeroizing::new([0u8; 32]);
    hex::decode_to_slice(hex_form.as_str(), bytes.as_mut())
        .map_err(|_| IdentityError::Malformed)?;
    SecretKey::from_bytes(*bytes).map_err(|_| IdentityError::InvalidScalar)
}

/// Read and parse [`IDENTITY_ENV`] from the process environment.
pub fn identity_from_env() -> Result<SecretKey, IdentityError> {
    let raw = Zeroizing::new(std::env::var(IDENTITY_ENV).map_err(|_| IdentityError::Missing)?);
    parse_identity(&raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_and_nsec_parse_to_the_same_key() {
        let hex_key = "7f".repeat(32);
        let nsec = nostr_bbs_core::nip19::encode_nsec(&hex_key).unwrap();
        let a = parse_identity(&hex_key).unwrap();
        let b = parse_identity(&format!("  {nsec}\n")).unwrap();
        assert_eq!(a.as_bytes(), b.as_bytes());
        assert_eq!(
            parse_identity(&hex_key.to_ascii_uppercase())
                .unwrap()
                .as_bytes(),
            a.as_bytes()
        );
    }

    fn err(raw: &str) -> IdentityError {
        match parse_identity(raw) {
            Ok(_) => panic!("expected an error"),
            Err(e) => e,
        }
    }

    #[test]
    fn malformed_inputs_are_rejected_without_echo() {
        assert_eq!(err(""), IdentityError::Missing);
        assert_eq!(err("abc"), IdentityError::Malformed);
        assert_eq!(err("nsec1qqqq"), IdentityError::Malformed);
        let bad = "zz".repeat(32);
        assert!(!err(&bad).to_string().contains("zz"));
        assert_eq!(err(&"00".repeat(32)), IdentityError::InvalidScalar);
    }
}
