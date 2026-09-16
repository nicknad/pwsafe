//! The five user-facing operations, independent of argument parsing.

use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};

use crate::output::say;
use crate::{clipboard, password, prompt, vault};

pub(crate) fn add(key: &str, length: usize, force: bool, clear_secs: u64) -> Result<()> {
    password::validate_key(key)?;
    password::validate_length(length)?;
    clipboard::validate_delay(clear_secs)?;

    let path = vault::default_path()?;
    vault::ensure_writable(&path)?;
    let secret = update_vault(&path, |vault| {
        ensure_absent(vault, key, force)?;
        let secret = password::generate(length);
        vault.entries.insert(key.to_string(), secret.clone());
        Ok(secret)
    })?;

    say!("stored '{key}' ({length} chars)");
    clipboard::deliver(key, secret.as_str(), clear_secs).with_context(|| {
        format!("the password was stored, but the clipboard was not updated; retrieve it with `pwsafe get {key}`")
    })
}

pub(crate) fn set(key: &str, force: bool) -> Result<()> {
    password::validate_key(key)?;

    let path = vault::default_path()?;
    check_absent(&path, key, force)?;
    vault::ensure_writable(&path)?;

    let secret = prompt::read_new_secret(key)?;
    let length = secret.chars().count();
    update_vault(&path, |vault| {
        ensure_absent(vault, key, force)?;
        vault.entries.insert(key.to_string(), secret);
        Ok(())
    })?;

    say!("stored '{key}' ({length} chars)");
    Ok(())
}

pub(crate) fn get(key: &str, clear_secs: u64) -> Result<()> {
    password::validate_key(key)?;
    clipboard::validate_delay(clear_secs)?;

    let secret = {
        let vault = vault::load()?;
        vault
            .entries
            .get(key)
            .ok_or_else(|| anyhow!("key '{key}' not found"))?
            .clone()
    };
    clipboard::deliver(key, secret.as_str(), clear_secs)
}

pub(crate) fn list() -> Result<()> {
    let vault = vault::load()?;
    let mut keys: Vec<&str> = vault.entries.keys().map(String::as_str).collect();
    keys.sort_unstable();

    if keys.is_empty() {
        say!("vault is empty");
        return Ok(());
    }
    for key in keys {
        say!("{key}");
    }
    Ok(())
}

pub(crate) fn rm(key: &str) -> Result<()> {
    password::validate_key(key)?;

    let path = vault::default_path()?;
    vault::ensure_writable(&path)?;
    update_vault(&path, |vault| {
        if vault.entries.remove(key).is_none() {
            bail!("key '{key}' not found");
        }
        Ok(())
    })?;
    say!("removed '{key}'");
    Ok(())
}

fn ensure_absent(vault: &vault::Vault, key: &str, force: bool) -> Result<()> {
    if !force && vault.entries.contains_key(key) {
        bail!("key '{key}' already exists (pass --force to overwrite)");
    }
    Ok(())
}

fn check_absent(path: &Path, key: &str, force: bool) -> Result<()> {
    let _lock = vault::lock(path)?;
    let vault = vault::load_from(path)?;
    ensure_absent(&vault, key, force)
}

fn update_vault<T>(path: &Path, mutate: impl FnOnce(&mut vault::Vault) -> Result<T>) -> Result<T> {
    let _lock = vault::lock(path)?;
    let mut vault = vault::load_from(path)?;
    let result = mutate(&mut vault)?;
    vault::save_to(path, &vault)?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use zeroize::Zeroizing;

    use super::*;

    fn vault_with(key: &str) -> vault::Vault {
        let mut entries = HashMap::new();
        entries.insert(key.to_string(), Zeroizing::new("value".to_string()));
        vault::Vault {
            version: vault::VAULT_VERSION,
            entries,
        }
    }

    #[test]
    fn ensure_absent_respects_force() {
        let vault = vault_with("github");
        assert!(ensure_absent(&vault, "github", true).is_ok());
        assert!(ensure_absent(&vault, "github", false).is_err());
        assert!(ensure_absent(&vault, "gitlab", false).is_ok());
    }
}
