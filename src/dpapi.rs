//! Thin wrapper around the Windows Data Protection API (DPAPI). Secrets are
//! encrypted for the current Windows user and are never written anywhere by
//! this module; the caller owns all storage.

use std::ffi::c_void;
use std::io;
use std::ptr::{null, null_mut};

use anyhow::{Context, Result};
use zeroize::{Zeroize, Zeroizing};

use windows_sys::Win32::Foundation::{HLOCAL, LocalFree};
use windows_sys::Win32::Security::Cryptography::{
    CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
};

const ENTROPY: &[u8] = b"pwsafe-rs/dpapi/v1";

#[derive(Clone, Copy)]
enum Mode {
    Protect,
    Unprotect,
}

pub(crate) fn protect(data: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    crypt(Mode::Protect, data, ENTROPY)
}

pub(crate) fn unprotect(data: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    crypt(Mode::Unprotect, data, ENTROPY)
}

fn crypt(mode: Mode, data: &[u8], entropy: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let input = blob(data)?;
    let entropy = blob(entropy)?;
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: null_mut(),
    };

    // SAFETY: `input` and `entropy` point to valid buffers that outlive the call, `output` is a
    // valid out-pointer, the description/prompt/reserved pointers are null as the API allows,
    // and CRYPTPROTECT_UI_FORBIDDEN suppresses any UI. DPAPI does not mutate the inputs.
    let ok = unsafe {
        match mode {
            Mode::Protect => CryptProtectData(
                &raw const input,
                null(),
                &raw const entropy,
                null::<c_void>(),
                null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &raw mut output,
            ),
            Mode::Unprotect => CryptUnprotectData(
                &raw const input,
                null_mut(),
                &raw const entropy,
                null::<c_void>(),
                null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &raw mut output,
            ),
        }
    };
    if ok == 0 {
        let err = io::Error::last_os_error();
        return Err(err).context("DPAPI operation failed");
    }

    let len = output.cbData as usize;
    let mut result = Zeroizing::new(vec![0u8; len]);
    // SAFETY: on success DPAPI allocated `output.pbData` with `output.cbData` readable bytes,
    // valid until it is passed to LocalFree below; `result` has exactly `len` writable bytes.
    unsafe {
        if len > 0 && !output.pbData.is_null() {
            std::ptr::copy_nonoverlapping(output.pbData, result.as_mut_ptr(), len);
            std::slice::from_raw_parts_mut(output.pbData, len).zeroize();
        }
    }
    // SAFETY: `output.pbData` was allocated by DPAPI with LocalAlloc and must be released with
    // LocalFree exactly once; it is not used again afterwards.
    unsafe {
        let _ = LocalFree(output.pbData as HLOCAL);
    }
    Ok(result)
}

fn blob(bytes: &[u8]) -> Result<CRYPT_INTEGER_BLOB> {
    Ok(CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(bytes.len()).context("input too large for DPAPI")?,
        pbData: bytes.as_ptr().cast_mut(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let secret = b"correct horse battery staple";
        let encrypted = protect(secret).unwrap();
        assert_ne!(&encrypted[..], &secret[..]);
        let decrypted = unprotect(&encrypted).unwrap();
        assert_eq!(&decrypted[..], &secret[..]);
    }

    #[test]
    fn rejects_tampered_ciphertext() {
        let mut encrypted = protect(b"tamper me").unwrap().to_vec();
        let last = encrypted.len() - 1;
        encrypted[last] ^= 0x01;
        assert!(unprotect(&encrypted).is_err());
    }

    #[test]
    fn rejects_wrong_entropy() {
        let encrypted = crypt(Mode::Protect, b"entropy bound", b"right").unwrap();
        assert!(crypt(Mode::Unprotect, &encrypted, b"wrong").is_err());
    }
}
