//! Reading a secret from the user. Secrets are never accepted as command-line
//! arguments (those are visible to other processes and end up in shell
//! history): they come from a hidden interactive prompt or from piped stdin.

use std::io::{self, BufRead, IsTerminal};
use std::sync::atomic::{AtomicU32, Ordering};

use anyhow::{Context, Result, bail};
use zeroize::Zeroizing;

use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::System::Console::{
    GetConsoleMode, GetStdHandle, STD_INPUT_HANDLE, SetConsoleCtrlHandler, SetConsoleMode,
};

const MAX_SECRET_CHARS: usize = 4096;
const MAX_SECRET_BYTES: usize = MAX_SECRET_CHARS * 4;
const BOM: char = '\u{feff}';

static SAVED_CONSOLE_MODE: AtomicU32 = AtomicU32::new(0);

pub(crate) fn read_new_secret(key: &str) -> Result<Zeroizing<String>> {
    let secret = if io::stdin().is_terminal() {
        let _guard = ConsoleModeGuard::install();
        read_interactive(key)?
    } else {
        read_piped(&mut io::stdin().lock())?
    };
    validate_secret(&secret)?;
    Ok(secret)
}

fn read_interactive(key: &str) -> Result<Zeroizing<String>> {
    let first = rpassword::prompt_password(format!("Password for '{key}': "))
        .context("cannot read the password from the terminal")?;
    let first = Zeroizing::new(first);

    let second = rpassword::prompt_password("Repeat password: ")
        .context("cannot read the password from the terminal")?;
    let second = Zeroizing::new(second);

    if first.as_str() != second.as_str() {
        bail!("passwords do not match; nothing was stored");
    }
    Ok(first)
}

fn read_piped<R: BufRead>(reader: &mut R) -> Result<Zeroizing<String>> {
    let mut bytes = Zeroizing::new(Vec::new());

    loop {
        let buf = reader
            .fill_buf()
            .context("cannot read the password from stdin")?;
        if buf.is_empty() {
            break;
        }
        let (chunk_len, terminated) =
            match buf.iter().position(|byte| *byte == b'\n' || *byte == b'\r') {
                Some(stop) => (stop, true),
                None => (buf.len(), false),
            };
        if bytes.len() + chunk_len > MAX_SECRET_BYTES {
            bail!("piped password must be at most {MAX_SECRET_BYTES} bytes");
        }
        bytes.extend_from_slice(&buf[..chunk_len]);
        reader.consume(chunk_len + usize::from(terminated));
        if terminated {
            break;
        }
    }

    if has_more_input(reader)? {
        bail!("stdin contains more than one line; pipe exactly one password");
    }
    finish(&bytes)
}

fn has_more_input<R: BufRead>(reader: &mut R) -> Result<bool> {
    loop {
        let buf = reader
            .fill_buf()
            .context("cannot read the password from stdin")?;
        if buf.is_empty() {
            return Ok(false);
        }
        let only_line_breaks = buf.iter().all(|byte| *byte == b'\n' || *byte == b'\r');
        let len = buf.len();
        if !only_line_breaks {
            return Ok(true);
        }
        reader.consume(len);
    }
}

fn finish(bytes: &[u8]) -> Result<Zeroizing<String>> {
    let text = std::str::from_utf8(bytes).context("password must be valid UTF-8")?;
    let mut text = Zeroizing::new(text.to_owned());
    if text.starts_with(BOM) {
        text.drain(..BOM.len_utf8());
    }
    Ok(text)
}

fn validate_secret(secret: &str) -> Result<()> {
    if secret.is_empty() {
        bail!("password must not be empty; nothing was stored");
    }
    if secret.contains('\0') {
        bail!("password must not contain NUL characters");
    }
    if secret.chars().count() > MAX_SECRET_CHARS {
        bail!("password must be at most {MAX_SECRET_CHARS} characters");
    }
    Ok(())
}

struct ConsoleModeGuard {
    handle: HANDLE,
    saved: u32,
}

impl ConsoleModeGuard {
    fn install() -> Option<Self> {
        // SAFETY: GetStdHandle takes a constant selector and returns the process's standard
        // input handle; no memory is accessed.
        let handle = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
        let mut mode: u32 = 0;
        // SAFETY: `handle` is the process's standard input handle and `mode` is a valid
        // out-pointer for GetConsoleMode; failure is handled by returning None.
        let ok = unsafe { GetConsoleMode(handle, &raw mut mode) };
        if ok == 0 {
            return None;
        }
        SAVED_CONSOLE_MODE.store(mode, Ordering::SeqCst);
        // SAFETY: `restore_console_mode` matches the PHANDLER_ROUTINE signature and is safe to
        // register; it only reads an atomic and restores a previously captured console mode.
        unsafe { SetConsoleCtrlHandler(Some(restore_console_mode), 1) };
        Some(Self {
            handle,
            saved: mode,
        })
    }
}

impl Drop for ConsoleModeGuard {
    fn drop(&mut self) {
        set_mode(self.handle, self.saved);
    }
}

unsafe extern "system" fn restore_console_mode(_ctrl_type: u32) -> i32 {
    // SAFETY: this handler runs on a system thread; GetStdHandle and SetConsoleMode are console
    // API calls that take the standard input selector and a mode captured from GetConsoleMode.
    let handle = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
    set_mode(handle, SAVED_CONSOLE_MODE.load(Ordering::SeqCst));
    0
}

fn set_mode(handle: HANDLE, mode: u32) {
    // SAFETY: `handle` is the process's standard input console handle and `mode` was previously
    // returned by GetConsoleMode for it; failure is ignored because there is no recovery path.
    let _ = unsafe { SetConsoleMode(handle, mode) };
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    use proptest::prelude::*;

    fn read(input: &[u8]) -> Result<String> {
        read_piped(&mut Cursor::new(input)).map(|secret| secret.to_string())
    }

    #[test]
    fn piped_input_handles_line_endings_and_bom() {
        assert_eq!(read(b"secret\n").unwrap(), "secret");
        assert_eq!(read(b"secret\r\n").unwrap(), "secret");
        assert_eq!(read(b"secret\r").unwrap(), "secret");
        assert_eq!(read(b"secret").unwrap(), "secret");
        assert_eq!(read("\u{feff}secret\r\n".as_bytes()).unwrap(), "secret");
        assert_eq!(read("\u{feff}".as_bytes()).unwrap(), "");
        assert_eq!(read(b"  pass phrase  \n").unwrap(), "  pass phrase  ");
    }

    #[test]
    fn piped_input_rejects_multiple_lines() {
        assert!(read(b"one\ntwo\n").is_err());
        assert!(read(b"one\ntwo").is_err());
        assert_eq!(read(b"one\n\n").unwrap(), "one");
    }

    #[test]
    fn piped_input_is_bounded() {
        let at_limit = format!("{}\n", "a".repeat(MAX_SECRET_CHARS));
        let secret = read(at_limit.as_bytes()).unwrap();
        assert_eq!(secret.chars().count(), MAX_SECRET_CHARS);
        assert!(validate_secret(&secret).is_ok());

        let over_limit = format!("{}\n", "a".repeat(MAX_SECRET_CHARS + 1));
        assert!(validate_secret(&read(over_limit.as_bytes()).unwrap()).is_err());

        let huge = "a".repeat(1024 * 1024);
        assert!(read(huge.as_bytes()).is_err());
    }

    #[test]
    fn piped_input_rejects_invalid_utf8() {
        assert!(read(&[0x61, 0xff, 0x0a]).is_err());
    }

    #[test]
    fn validation_rejects_empty_nul_and_oversized_secrets() {
        assert!(validate_secret("").is_err());
        assert!(validate_secret("a\0b").is_err());
        assert!(validate_secret("a").is_ok());
        assert!(validate_secret(&"a".repeat(MAX_SECRET_CHARS)).is_ok());
        assert!(validate_secret(&"a".repeat(MAX_SECRET_CHARS + 1)).is_err());
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        /// `read_piped` never panics, and every accepted secret carries no line
        /// breaks and fits the byte budget.
        #[test]
        fn piped_never_panics_and_ok_implies_invariants(
            input in prop::collection::vec(any::<u8>(), 0..17_000),
        ) {
            let result = read(&input);
            if let Ok(secret) = result {
                prop_assert!(!secret.contains('\n'), "secret must not contain LF");
                prop_assert!(!secret.contains('\r'), "secret must not contain CR");
                prop_assert!(
                    secret.len() <= MAX_SECRET_BYTES,
                    "secret must fit the byte budget"
                );
                if validate_secret(&secret).is_ok() {
                    prop_assert!(!secret.is_empty());
                    prop_assert!(!secret.contains('\0'));
                    prop_assert!(secret.chars().count() <= MAX_SECRET_CHARS);
                }
            }
        }

        /// A single line with an optional BOM, terminator, and trailing blank
        /// lines round-trips to the bare body.
        #[test]
        fn piped_single_line_roundtrip(
            body in "[ -~]{0,64}",
            bom in prop::bool::ANY,
            term in prop_oneof!["", "\n", "\r", "\r\n"],
            trailing in prop_oneof!["", "\n", "\r\n", "\n\n", "\r\r\n"],
        ) {
            let mut input = String::new();
            if bom {
                input.push(BOM);
            }
            input.push_str(&body);
            input.push_str(&term);
            input.push_str(&trailing);
            prop_assert_eq!(read(input.as_bytes()).unwrap(), body);
        }

        /// A second line carrying any non-break content is rejected.
        #[test]
        fn piped_rejects_second_content_line(
            first in "[ -~]{0,32}",
            second in "[ -~]{1,32}",
            sep in prop_oneof!["\n", "\r", "\r\n"],
        ) {
            let input = format!("{first}{sep}{second}");
            prop_assert!(
                read(input.as_bytes()).is_err(),
                "two content lines must be rejected: {input:?}"
            );
        }

        /// The byte gate (`read_piped`, 16 KiB) and the char gate
        /// (`validate_secret`, 4096 chars) stay distinct for pure-ASCII input.
        #[test]
        fn piped_byte_limit_is_distinct_from_char_limit(n in 0usize..20_000) {
            let input = format!("{}\n", "a".repeat(n));
            let result = read(input.as_bytes());
            if n <= MAX_SECRET_BYTES {
                let secret = result.unwrap();
                prop_assert_eq!(
                    validate_secret(&secret).is_ok(),
                    (1..=MAX_SECRET_CHARS).contains(&n)
                );
            } else {
                prop_assert!(result.is_err(), "over the byte budget: n = {n}");
            }
        }
    }
}
