//! Key material at rest.
//!
//! On Windows a secret is stored as `dpapi:<base64>`: a DPAPI blob bound to
//! the current Windows user, so a copy of the file read by another account or
//! on another machine opens nothing. Elsewhere the value stays plaintext hex,
//! as before, and the file's own permissions are the only protection.
//!
//! A stored value without the prefix was written before this existed. It
//! still loads, and the caller rewrites it protected.

use anyhow::Result;

#[cfg(windows)]
const PREFIX: &str = "dpapi:";

/// Encode `plain` for storage. Empty stays empty, and a value that is already
/// protected passes through, so one that failed to unprotect is written back
/// as it was instead of being wrapped twice.
#[cfg(windows)]
pub fn conceal(plain: &str) -> Result<String> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    if !needs_protection(plain) {
        return Ok(plain.to_string());
    }
    let failed = || anyhow::anyhow!(crate::errcode::code("keyStore.protectFailed"));
    let blob = protect(plain.as_bytes()).ok_or_else(failed)?;
    // Never write a value this account cannot read back: a key lost here is
    // lost for good.
    if unprotect(&blob).as_deref() != Some(plain.as_bytes()) {
        return Err(failed());
    }
    Ok(format!("{PREFIX}{}", STANDARD.encode(blob)))
}

/// Decode a stored value. One that cannot be unprotected (another account's
/// or another machine's) comes back unchanged: it then fails as a corrupt key
/// instead of reading as "no key" and being overwritten.
#[cfg(windows)]
pub fn reveal(stored: &str) -> String {
    use base64::{engine::general_purpose::STANDARD, Engine};
    stored
        .strip_prefix(PREFIX)
        .and_then(|b64| STANDARD.decode(b64).ok())
        .and_then(|blob| unprotect(&blob))
        .and_then(|plain| String::from_utf8(plain).ok())
        .unwrap_or_else(|| stored.to_string())
}

/// Whether a stored value is plaintext this platform would protect.
#[cfg(windows)]
pub fn needs_protection(stored: &str) -> bool {
    !stored.is_empty() && !stored.starts_with(PREFIX)
}

#[cfg(not(windows))]
pub fn conceal(plain: &str) -> Result<String> {
    Ok(plain.to_string())
}

#[cfg(not(windows))]
pub fn reveal(stored: &str) -> String {
    stored.to_string()
}

#[cfg(not(windows))]
pub fn needs_protection(_stored: &str) -> bool {
    false
}

/// Encrypt `input` for the current Windows user. `None` when Windows refuses.
#[cfg(windows)]
pub fn protect(input: &[u8]) -> Option<Vec<u8>> {
    // SAFETY: `call` only reads `input` and frees the blob Windows allocated.
    unsafe { call(input, true) }
}

/// Decrypt a blob `protect` produced for this Windows user.
#[cfg(windows)]
pub fn unprotect(input: &[u8]) -> Option<Vec<u8>> {
    // SAFETY: as for `protect`.
    unsafe { call(input, false) }
}

#[cfg(windows)]
unsafe fn call(input: &[u8], protect: bool) -> Option<Vec<u8>> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CryptProtectData, CryptUnprotectData, CRYPT_INTEGER_BLOB,
    };
    let in_blob = CRYPT_INTEGER_BLOB {
        cbData: input.len() as u32,
        pbData: input.as_ptr() as *mut u8,
    };
    let mut out_blob = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };
    let ok = if protect {
        CryptProtectData(
            &in_blob,
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            0,
            &mut out_blob,
        )
    } else {
        CryptUnprotectData(
            &in_blob,
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            0,
            &mut out_blob,
        )
    };
    if ok == 0 {
        return None;
    }
    let out = std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize).to_vec();
    LocalFree(out_blob.pbData as _);
    Some(out)
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn a_secret_round_trips_and_is_not_stored_in_the_clear() {
        let plain = "ab".repeat(32);
        let stored = conceal(&plain).unwrap();
        assert!(stored.starts_with(PREFIX), "stored as a DPAPI blob");
        assert!(
            !stored.contains(&plain),
            "the hex must not survive in the file"
        );
        assert_eq!(reveal(&stored), plain);
    }

    #[test]
    fn plaintext_and_empty_values_load_unchanged() {
        assert_eq!(reveal("00ff"), "00ff", "a pre-DPAPI value still loads");
        assert!(needs_protection("00ff"));
        assert!(!needs_protection(""), "nothing to protect");
        assert_eq!(conceal("").unwrap(), "");
    }

    #[test]
    fn an_unreadable_blob_is_kept_rather_than_dropped() {
        let junk = format!("{PREFIX}AAAA");
        assert_eq!(reveal(&junk), junk);
        assert_eq!(
            conceal(&junk).unwrap(),
            junk,
            "an already protected value is not wrapped twice"
        );
    }
}
