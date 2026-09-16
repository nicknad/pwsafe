//! Clipboard delivery with a guarded auto-wipe: the clipboard is only cleared
//! if it still contains the secret that was copied, and the secret is excluded
//! from Windows clipboard history and cloud sync.

use std::thread;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use arboard::{Clipboard, SetExtWindows};
use zeroize::Zeroizing;

use windows_sys::Win32::System::DataExchange::GetClipboardSequenceNumber;

use crate::output::say;

pub(crate) const DEFAULT_CLEAR_SECS: u64 = 15;
pub(crate) const MAX_CLEAR_SECS: u64 = 86_400;

enum ClipboardState {
    Unchanged,
    Changed,
    Unknown,
}

pub(crate) fn validate_delay(clear_secs: u64) -> Result<()> {
    if clear_secs > MAX_CLEAR_SECS {
        bail!("--clear-secs must be between 0 and {MAX_CLEAR_SECS}");
    }
    Ok(())
}

pub(crate) fn deliver(key: &str, secret: &str, clear_secs: u64) -> Result<()> {
    let mut clipboard = Clipboard::new().context("clipboard unavailable")?;
    clipboard
        .set()
        .exclude_from_history()
        .exclude_from_cloud()
        .text(secret)
        .context("failed to write to the clipboard")?;

    if clear_secs == 0 {
        say!("copied '{key}' to clipboard (auto-clear disabled)");
        return Ok(());
    }

    let sequence = clipboard_sequence();
    say!("copied '{key}' to clipboard, wiping it in {clear_secs}s (Ctrl+C to keep)");
    thread::sleep(Duration::from_secs(clear_secs));

    match clipboard_state(&mut clipboard, sequence, secret) {
        ClipboardState::Unchanged => {
            clipboard
                .clear()
                .context("failed to wipe the clipboard; the secret may still be on it")?;
            say!("clipboard wiped");
            Ok(())
        }
        ClipboardState::Changed => {
            say!("clipboard changed, left untouched");
            Ok(())
        }
        ClipboardState::Unknown => {
            bail!("could not verify the clipboard state; it was NOT wiped")
        }
    }
}

fn clipboard_sequence() -> u32 {
    // SAFETY: GetClipboardSequenceNumber takes no arguments and cannot fail; it reads the
    // current window station's clipboard sequence counter.
    unsafe { GetClipboardSequenceNumber() }
}

fn clipboard_state(clipboard: &mut Clipboard, sequence: u32, secret: &str) -> ClipboardState {
    let current = clipboard_sequence();
    if sequence != 0 && current != 0 {
        return if current == sequence {
            ClipboardState::Unchanged
        } else {
            ClipboardState::Changed
        };
    }

    match clipboard.get_text() {
        Ok(text) => {
            let text = Zeroizing::new(text);
            if text.as_str() == secret {
                ClipboardState::Unchanged
            } else {
                ClipboardState::Changed
            }
        }
        Err(_) => ClipboardState::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delay_is_bounded() {
        assert!(validate_delay(0).is_ok());
        assert!(validate_delay(MAX_CLEAR_SECS).is_ok());
        assert!(validate_delay(MAX_CLEAR_SECS + 1).is_err());
    }
}
