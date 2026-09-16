//! The on-disk vault: DPAPI-encrypted JSON, atomic writes, and an exclusive
//! cross-process lock for read-modify-write cycles.

use std::collections::HashMap;
use std::ffi::{OsStr, OsString, c_void};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::AsRawHandle;
use std::path::{Component, Path, PathBuf, Prefix};
use std::ptr::null;

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Storage::FileSystem::{
    LOCKFILE_EXCLUSIVE_LOCK, LockFileEx, REPLACEFILE_IGNORE_MERGE_ERRORS, ReplaceFileW,
};
use windows_sys::Win32::System::IO::OVERLAPPED;

use crate::dpapi;

pub(crate) const VAULT_VERSION: u32 = 1;

#[derive(Serialize, Deserialize)]
pub(crate) struct Vault {
    pub(crate) version: u32,
    pub(crate) entries: HashMap<String, Zeroizing<String>>,
}

impl Vault {
    fn new() -> Self {
        Self {
            version: VAULT_VERSION,
            entries: HashMap::new(),
        }
    }
}

pub(crate) fn default_path() -> Result<PathBuf> {
    path_from(
        std::env::var_os("PWSAFE_VAULT"),
        std::env::var_os("APPDATA"),
    )
}

fn path_from(vault_env: Option<OsString>, appdata: Option<OsString>) -> Result<PathBuf> {
    let path = match vault_env {
        Some(path) if !path.is_empty() => PathBuf::from(path),
        _ => {
            let appdata = appdata.ok_or_else(|| {
                anyhow!("APPDATA is not set; set PWSAFE_VAULT to choose a vault location")
            })?;
            PathBuf::from(appdata).join("pwsafe-rs").join("vault.dat")
        }
    };
    validate_path(&path)?;
    Ok(path)
}

fn validate_path(path: &Path) -> Result<()> {
    if !path.is_absolute() {
        bail!("vault path must be absolute: {}", path.display());
    }
    if let Some(Component::Prefix(prefix)) = path.components().next() {
        match prefix.kind() {
            Prefix::UNC(..) | Prefix::VerbatimUNC(..) | Prefix::DeviceNS(..) => {
                bail!("vault path must be on a local drive: {}", path.display());
            }
            _ => {}
        }
    }
    if is_reserved_name(path) {
        bail!("vault path uses a reserved device name: {}", path.display());
    }
    Ok(())
}

fn is_reserved_name(path: &Path) -> bool {
    let Some(stem) = path.file_stem().and_then(|stem| stem.to_str()) else {
        return false;
    };
    let name = stem.trim_end_matches(['.', ' ']).to_ascii_uppercase();
    matches!(
        name.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
    ) || (name.len() == 4
        && (name.starts_with("COM") || name.starts_with("LPT"))
        && name.as_bytes()[3].is_ascii_digit()
        && name.as_bytes()[3] != b'0')
}

fn ensure_parent_dir(path: &Path) -> Result<()> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).with_context(|| format!("cannot create {}", dir.display()))?;
    }
    Ok(())
}

fn file_name_of(path: &Path) -> Result<&OsStr> {
    path.file_name()
        .ok_or_else(|| anyhow!("invalid vault path: {}", path.display()))
}

pub(crate) fn ensure_writable(path: &Path) -> Result<()> {
    ensure_parent_dir(path)?;
    if path.exists()
        && fs::metadata(path)
            .with_context(|| format!("cannot inspect {}", path.display()))?
            .permissions()
            .readonly()
    {
        bail!("vault is read-only: {}", path.display());
    }
    Ok(())
}

pub(crate) fn load() -> Result<Vault> {
    load_from(&default_path()?)
}

pub(crate) fn load_from(path: &Path) -> Result<Vault> {
    if !path.exists() {
        return Ok(Vault::new());
    }

    let encrypted =
        fs::read(path).with_context(|| format!("cannot read vault at {}", path.display()))?;
    let plaintext = dpapi::unprotect(&encrypted).context(
        "cannot decrypt vault: it was created by a different Windows user, or the file is corrupt or tampered",
    )?;
    let vault: Vault = serde_json::from_slice(&plaintext)
        .context("vault content is corrupt or from a newer pwsafe")?;

    if vault.version != VAULT_VERSION {
        bail!(
            "unsupported vault version {} (this build supports {VAULT_VERSION})",
            vault.version
        );
    }
    Ok(vault)
}

pub(crate) fn save_to(path: &Path, vault: &Vault) -> Result<()> {
    ensure_parent_dir(path)?;

    let plaintext = Zeroizing::new(serde_json::to_vec(vault).context("cannot serialize vault")?);
    let encrypted = dpapi::protect(&plaintext)?;

    let file_name = file_name_of(path)?.to_string_lossy().into_owned();
    let tmp = path.with_file_name(format!(
        "{file_name}.{}.{:016x}.tmp",
        std::process::id(),
        rand::random::<u64>()
    ));

    if let Err(err) = write_synced_file(&tmp, &encrypted) {
        let _ = fs::remove_file(&tmp);
        return Err(err);
    }

    let result = if path.exists() {
        replace_file(path, &tmp)
    } else {
        fs::rename(&tmp, path).with_context(|| format!("cannot create {}", path.display()))
    };
    if let Err(err) = result {
        let _ = fs::remove_file(&tmp);
        return Err(err);
    }
    Ok(())
}

pub(crate) struct Lock {
    _file: File,
}

pub(crate) fn lock(path: &Path) -> Result<Lock> {
    ensure_parent_dir(path)?;
    let lock_path = lock_path(path)?;
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(&lock_path)
        .with_context(|| format!("cannot open {}", lock_path.display()))?;

    // SAFETY: OVERLAPPED is a plain data structure for which an all-zero bit pattern is a
    // valid initialized value.
    let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
    // SAFETY: `file` keeps the handle valid for the duration of the call, `overlapped` is a
    // zeroed, aligned, live OVERLAPPED, the lock is blocking with no completion routine, and
    // Windows releases the lock automatically when the handle is dropped.
    let ok = unsafe {
        LockFileEx(
            file.as_raw_handle() as HANDLE,
            LOCKFILE_EXCLUSIVE_LOCK,
            0,
            u32::MAX,
            u32::MAX,
            &raw mut overlapped,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error()).context("cannot lock the vault");
    }
    Ok(Lock { _file: file })
}

fn lock_path(path: &Path) -> Result<PathBuf> {
    let mut name = file_name_of(path)?.to_os_string();
    name.push(".lock");
    Ok(path.with_file_name(name))
}

fn write_synced_file(path: &Path, data: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("cannot create {}", path.display()))?;
    file.write_all(data)
        .with_context(|| format!("cannot write {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("cannot flush {}", path.display()))?;
    Ok(())
}

fn replace_file(dst: &Path, src: &Path) -> Result<()> {
    let dst_wide: Vec<u16> = dst
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let src_wide: Vec<u16> = src
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    // SAFETY: both paths are valid NUL-terminated UTF-16 buffers that outlive the call, and the
    // backup, exclude, and preserved pointers are null as permitted by the API. ReplaceFileW
    // preserves the destination's ACLs and attributes while taking the source's contents.
    let ok = unsafe {
        ReplaceFileW(
            dst_wide.as_ptr(),
            src_wide.as_ptr(),
            null(),
            REPLACEFILE_IGNORE_MERGE_ERRORS,
            null::<c_void>(),
            null::<c_void>(),
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error()).context("cannot replace the vault");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("pwsafe-test-{}-{name}.dat", std::process::id()))
    }

    #[test]
    fn path_from_prefers_override_and_rejects_bad_paths() {
        let explicit = PathBuf::from(r"C:\vaults\test.dat");
        let from_override = path_from(Some(explicit.clone().into_os_string()), None).unwrap();
        assert_eq!(from_override, explicit);

        let fallback =
            path_from(None, Some(OsString::from(r"C:\Users\x\AppData\Roaming"))).unwrap();
        assert!(fallback.ends_with(Path::new("pwsafe-rs").join("vault.dat")));

        assert!(path_from(None, None).is_err());
        assert!(path_from(Some(OsString::new()), None).is_err());
        assert!(path_from(Some(OsString::from("relative.dat")), None).is_err());
        assert!(path_from(Some(OsString::from(r"\\server\share\v.dat")), None).is_err());
        assert!(path_from(Some(OsString::from(r"\\.\NUL")), None).is_err());
        assert!(path_from(Some(OsString::from(r"C:\tmp\NUL")), None).is_err());
        assert!(path_from(Some(OsString::from(r"C:\tmp\com1.dat")), None).is_err());
        assert!(path_from(Some(OsString::from(r"C:\tmp\vault.dat")), None).is_ok());
    }

    #[test]
    fn lock_path_does_not_collide_with_vault_name() {
        assert_eq!(
            lock_path(Path::new(r"C:\data\v.lock")).unwrap(),
            PathBuf::from(r"C:\data\v.lock.lock")
        );
        assert_eq!(
            lock_path(Path::new(r"C:\data\a.dat")).unwrap(),
            PathBuf::from(r"C:\data\a.dat.lock")
        );
    }

    #[test]
    fn roundtrip_through_storage() {
        let path = temp_path("roundtrip");
        let mut vault = Vault::new();
        vault
            .entries
            .insert("github".to_string(), Zeroizing::new("s3cret!".to_string()));

        save_to(&path, &vault).unwrap();
        let raw = fs::read(&path).unwrap();
        assert_ne!(raw[0], b'{');

        let restored = load_from(&path).unwrap();
        assert_eq!(restored.version, VAULT_VERSION);
        assert_eq!(restored.entries["github"].as_str(), "s3cret!");

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn rejects_unknown_version_without_touching_file() {
        let path = temp_path("version");
        let mut entries = HashMap::new();
        entries.insert("k".to_string(), Zeroizing::new("v".to_string()));
        let future = Vault {
            version: VAULT_VERSION + 1,
            entries,
        };
        let json = serde_json::to_vec(&future).unwrap();
        fs::write(&path, dpapi::protect(&json).unwrap()).unwrap();

        let before = fs::read(&path).unwrap();
        assert!(load_from(&path).is_err());
        assert_eq!(fs::read(&path).unwrap(), before);

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn rejects_corruption_without_touching_file() {
        let path = temp_path("corrupt");
        fs::write(&path, b"not a dpapi blob").unwrap();

        let before = fs::read(&path).unwrap();
        assert!(load_from(&path).is_err());
        assert_eq!(fs::read(&path).unwrap(), before);

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn lock_is_released_on_drop() {
        let path = temp_path("lock");
        drop(lock(&path).unwrap());
        drop(lock(&path).unwrap());
        let _ = fs::remove_file(lock_path(&path).unwrap());
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        /// Path validation never panics, and every accepted path is absolute,
        /// local, and free of reserved device names.
        #[test]
        fn validate_path_never_panics(
            s in prop::collection::vec(any::<char>(), 0..128)
                .prop_map(|chars| chars.into_iter().collect::<String>()),
        ) {
            let path = PathBuf::from(s);
            let result = validate_path(&path);
            if result.is_ok() {
                prop_assert!(path.is_absolute(), "accepted path must be absolute");
                prop_assert!(
                    !is_reserved_name(&path),
                    "accepted path must not use a reserved name"
                );
                if let Some(Component::Prefix(prefix)) = path.components().next() {
                    prop_assert!(
                        !matches!(
                            prefix.kind(),
                            Prefix::UNC(..) | Prefix::VerbatimUNC(..) | Prefix::DeviceNS(..)
                        ),
                        "accepted path must be on a local drive"
                    );
                }
            }
        }

        /// Arbitrary UTF-16 (including unpaired surrogates) never panics.
        #[test]
        fn validate_path_never_panics_on_wide(
            wide in prop::collection::vec(any::<u16>(), 0..128),
        ) {
            use std::os::windows::ffi::OsStringExt as _;
            let path = PathBuf::from(OsString::from_wide(&wide));
            let _ = validate_path(&path);
            let _ = is_reserved_name(&path);
        }

        /// UNC and device prefixes are always rejected.
        #[test]
        fn unc_and_device_prefixes_always_rejected(
            suffix in "[A-Za-z0-9_.]{1,16}",
            base in prop_oneof![
                Just(r"\\server\share"),
                Just(r"\\.\C:\tmp"),
                Just(r"\\?\UNC\server\share"),
            ],
        ) {
            let path = PathBuf::from(format!(r"{base}\{suffix}"));
            prop_assert!(
                validate_path(&path).is_err(),
                "UNC/device path must be rejected: {}",
                path.display()
            );
        }

        /// Reserved device names are rejected regardless of case, trailing
        /// dots/spaces, or extension.
        #[test]
        fn reserved_names_always_rejected(
            stem in prop_oneof![
                Just("CON"),
                Just("con"),
                Just("Con"),
                Just("PRN"),
                Just("prn"),
                Just("AUX"),
                Just("aux"),
                Just("NUL"),
                Just("nul"),
                Just("NuL"),
                Just("CONIN$"),
                Just("conin$"),
                Just("CONOUT$"),
                Just("conout$"),
                Just("COM1"),
                Just("com1"),
                Just("COM9"),
                Just("LPT1"),
                Just("lpt1"),
                Just("LPT9"),
            ],
            trailer in "[. ]{0,3}",
            ext in prop_oneof![Just(""), Just(".dat"), Just(".txt"), Just(".lock")],
        ) {
            let path = PathBuf::from(format!(r"C:\tmp\{stem}{trailer}{ext}"));
            prop_assert!(
                is_reserved_name(&path),
                "must detect reserved name: {}",
                path.display()
            );
            prop_assert!(
                validate_path(&path).is_err(),
                "must reject reserved name: {}",
                path.display()
            );
        }

        /// Near-misses (`COM0`, `COM10`, `NULL`, `console`, …) are not reserved
        /// and validate as ordinary local paths.
        #[test]
        fn near_miss_names_never_reserved(
            safe in prop_oneof![
                Just("console"),
                Just("contact"),
                Just("null"),
                Just("nulx"),
                Just("com"),
                Just("lpt"),
                Just("com0"),
                Just("lpt0"),
                Just("com10"),
                Just("lpt10"),
                Just("com1a"),
                Just("auxx"),
                Just("prn_"),
                Just("vault"),
                Just("NULNUL"),
                Just("CCOM1"),
            ],
        ) {
            let path = PathBuf::from(format!(r"C:\tmp\{safe}.dat"));
            prop_assert!(
                !is_reserved_name(&path),
                "must not flag near-miss: {}",
                path.display()
            );
            prop_assert!(
                validate_path(&path).is_ok(),
                "must accept near-miss: {}",
                path.display()
            );
        }

        /// Generated `vault-<alnum>` names can never collide with the reserved set.
        #[test]
        fn generated_safe_names_accepted(suffix in "[A-Za-z0-9]{1,16}") {
            let path = PathBuf::from(format!(r"C:\tmp\vault-{suffix}.dat"));
            prop_assert!(!is_reserved_name(&path));
            prop_assert!(validate_path(&path).is_ok());
        }
    }
}
