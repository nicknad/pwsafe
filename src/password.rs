//! Password generation and credential naming rules.

use std::sync::LazyLock;

use anyhow::{Result, bail};
use rand::{RngExt, rng};
use zeroize::Zeroizing;

pub(crate) const MIN_LENGTH: usize = 8;
pub(crate) const MAX_LENGTH: usize = 256;
pub(crate) const DEFAULT_LENGTH: usize = 16;
pub(crate) const MAX_KEY_CHARS: usize = 128;

const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &[u8] = b"0123456789";
const SYMBOLS: &[u8] = b"!@#$%^&*()_+-=";
static ALPHABET: LazyLock<Vec<u8>> = LazyLock::new(|| [LOWER, UPPER, DIGITS, SYMBOLS].concat());

pub(crate) fn generate(length: usize) -> Zeroizing<String> {
    assert!(length >= 4, "length must fit one character of each class");
    let mut rng = rng();
    let mut bytes = Vec::with_capacity(length);

    for class in [LOWER, UPPER, DIGITS, SYMBOLS] {
        bytes.push(class[rng.random_range(0..class.len())]);
    }
    while bytes.len() < length {
        bytes.push(ALPHABET[rng.random_range(0..ALPHABET.len())]);
    }
    for i in (1..bytes.len()).rev() {
        let j = rng.random_range(0..=i);
        bytes.swap(i, j);
    }

    Zeroizing::new(String::from_utf8(bytes).expect("alphabet is ASCII"))
}

pub(crate) fn validate_key(key: &str) -> Result<()> {
    let chars = key.chars().count();
    if chars == 0 || chars > MAX_KEY_CHARS {
        bail!("key must be 1-{MAX_KEY_CHARS} characters");
    }
    if !key.bytes().all(|byte| byte.is_ascii_graphic()) {
        bail!("key must contain only printable ASCII characters (no spaces or control characters)");
    }
    Ok(())
}

pub(crate) fn validate_length(length: usize) -> Result<()> {
    if !(MIN_LENGTH..=MAX_LENGTH).contains(&length) {
        bail!("length must be between {MIN_LENGTH} and {MAX_LENGTH}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use proptest::prelude::*;

    use super::*;

    #[test]
    fn generated_password_has_length_and_all_classes() {
        for length in [MIN_LENGTH, 16, MAX_LENGTH] {
            for _ in 0..32 {
                let password = generate(length);
                assert_eq!(password.len(), length);
                assert!(password.bytes().any(|byte| LOWER.contains(&byte)));
                assert!(password.bytes().any(|byte| UPPER.contains(&byte)));
                assert!(password.bytes().any(|byte| DIGITS.contains(&byte)));
                assert!(password.bytes().any(|byte| SYMBOLS.contains(&byte)));
            }
        }
    }

    #[test]
    fn generated_passwords_are_unique() {
        let passwords: HashSet<String> = (0..64).map(|_| generate(32).to_string()).collect();
        assert_eq!(passwords.len(), 64);
    }

    #[test]
    fn validate_key_accepts_printable_ascii() {
        assert!(validate_key("github").is_ok());
        assert!(validate_key("github.com/user-name_1").is_ok());
        assert!(validate_key(&"a".repeat(MAX_KEY_CHARS)).is_ok());
    }

    #[test]
    fn validate_key_rejects_bad_input() {
        assert!(validate_key("").is_err());
        assert!(validate_key("has space").is_err());
        assert!(validate_key("ansi\u{1b}[31m").is_err());
        assert!(validate_key("bidi\u{202e}spoof").is_err());
        assert!(validate_key("caf\u{e9}").is_err());
        assert!(validate_key("bell\u{0007}").is_err());
        assert!(validate_key(&"a".repeat(MAX_KEY_CHARS + 1)).is_err());
    }

    #[test]
    fn validate_length_is_bounded() {
        assert!(validate_length(MIN_LENGTH).is_ok());
        assert!(validate_length(MAX_LENGTH).is_ok());
        assert!(validate_length(MIN_LENGTH - 1).is_err());
        assert!(validate_length(MAX_LENGTH + 1).is_err());
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        /// `validate_key` accepts exactly 1-128 ASCII graphic characters.
        #[test]
        fn validate_key_matches_model(
            s in prop::collection::vec(any::<char>(), 0..200)
                .prop_map(|chars| chars.into_iter().collect::<String>()),
        ) {
            let char_count = s.chars().count();
            let expected = char_count > 0
                && char_count <= MAX_KEY_CHARS
                && s.bytes().all(|byte| byte.is_ascii_graphic());
            prop_assert_eq!(validate_key(&s).is_ok(), expected);
        }

        /// Any run of graphic-ASCII bytes within the length bound is a valid key.
        #[test]
        fn validate_key_accepts_graphic_runs(
            bytes in prop::collection::vec(0x21u8..=0x7eu8, 1..=MAX_KEY_CHARS),
        ) {
            let key = String::from_utf8(bytes).expect("graphic ASCII is valid UTF-8");
            prop_assert!(validate_key(&key).is_ok());
            // ASCII keys count bytes and chars identically.
            prop_assert_eq!(key.len(), key.chars().count());
        }

        /// The length boundary is exact: `a` repeated `n` is valid iff `1 <= n <= 128`.
        #[test]
        fn validate_key_length_boundary(n in 0usize..300) {
            let key = "a".repeat(n);
            prop_assert_eq!(
                validate_key(&key).is_ok(),
                (1..=MAX_KEY_CHARS).contains(&n)
            );
        }
    }
}
