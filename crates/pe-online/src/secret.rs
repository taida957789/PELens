//! Where the VirusTotal API key lives: the Windows Credential Manager (per user, never written to
//! settings.xml), the `VT_API_KEY` environment variable, or a legacy plaintext `<score key>`.

use std::sync::Mutex;

/// Credential Manager target name of the VirusTotal key.
pub const VT_TARGET: &str = "PELens/VirusTotal";

/// Storage for one secret.
pub trait KeyStore: Send + Sync {
    fn get(&self) -> Option<String>;
    fn set(&self, key: &str) -> Result<(), String>;
    fn delete(&self) -> Result<(), String>;
}

/// A shared store (several users of one key, e.g. successive CLI runs in tests).
impl<T: KeyStore + ?Sized> KeyStore for std::sync::Arc<T> {
    fn get(&self) -> Option<String> {
        (**self).get()
    }
    fn set(&self, key: &str) -> Result<(), String> {
        (**self).set(key)
    }
    fn delete(&self) -> Result<(), String> {
        (**self).delete()
    }
}

/// Secret kept in memory only (tests, and platforms without a credential store).
#[derive(Debug, Default)]
pub struct MemoryStore(Mutex<Option<String>>);

impl MemoryStore {
    pub fn with(key: &str) -> Self {
        MemoryStore(Mutex::new(Some(key.to_string())))
    }
}

impl KeyStore for MemoryStore {
    fn get(&self) -> Option<String> {
        self.0.lock().ok()?.clone()
    }
    fn set(&self, key: &str) -> Result<(), String> {
        *self.0.lock().map_err(|e| e.to_string())? = Some(key.to_string());
        Ok(())
    }
    fn delete(&self) -> Result<(), String> {
        *self.0.lock().map_err(|e| e.to_string())? = None;
        Ok(())
    }
}

/// A generic credential of the Windows Credential Manager ("Windows Credentials" in the control
/// panel), readable only by the current user.
#[derive(Debug, Clone)]
pub struct CredentialStore {
    pub target: String,
}

impl CredentialStore {
    pub fn new(target: &str) -> Self {
        CredentialStore { target: target.to_string() }
    }

    /// The store of the VirusTotal key.
    pub fn vt() -> Self {
        Self::new(VT_TARGET)
    }
}

#[cfg(windows)]
mod win {
    use windows_sys::Win32::Security::Credentials::*;

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn last_error() -> String {
        std::io::Error::last_os_error().to_string()
    }

    pub fn read(target: &str) -> Option<String> {
        let t = wide(target);
        let mut p: *mut CREDENTIALW = std::ptr::null_mut();
        // SAFETY: `t` is a NUL-terminated UTF-16 string; on success `p` points to a credential
        // allocated by the API, released with CredFree below.
        if unsafe { CredReadW(t.as_ptr(), CRED_TYPE_GENERIC, 0, &mut p) } == 0 || p.is_null() {
            return None;
        }
        // SAFETY: `p` is valid until CredFree; the blob is CredentialBlobSize bytes long.
        let blob = unsafe {
            let c = &*p;
            let b = if c.CredentialBlob.is_null() {
                Vec::new()
            } else {
                std::slice::from_raw_parts(c.CredentialBlob, c.CredentialBlobSize as usize).to_vec()
            };
            CredFree(p as *const core::ffi::c_void);
            b
        };
        String::from_utf8(blob).ok().filter(|s| !s.is_empty())
    }

    pub fn write(target: &str, secret: &str) -> Result<(), String> {
        let mut t = wide(target);
        let mut user = wide("virustotal");
        let mut blob = secret.as_bytes().to_vec();
        // SAFETY: CREDENTIALW is a plain C struct; all-zero is a valid initial state.
        let mut c: CREDENTIALW = unsafe { std::mem::zeroed() };
        c.Type = CRED_TYPE_GENERIC;
        c.TargetName = t.as_mut_ptr();
        c.UserName = user.as_mut_ptr();
        c.CredentialBlobSize = blob.len() as u32;
        c.CredentialBlob = blob.as_mut_ptr();
        c.Persist = CRED_PERSIST_LOCAL_MACHINE;
        // SAFETY: every pointer references a live local buffer for the duration of the call.
        if unsafe { CredWriteW(&c, 0) } == 0 { Err(last_error()) } else { Ok(()) }
    }

    pub fn delete(target: &str) -> Result<(), String> {
        let t = wide(target);
        // SAFETY: `t` is a NUL-terminated UTF-16 string.
        if unsafe { CredDeleteW(t.as_ptr(), CRED_TYPE_GENERIC, 0) } != 0 {
            return Ok(());
        }
        let e = std::io::Error::last_os_error();
        // ERROR_NOT_FOUND (1168): nothing to delete
        if e.raw_os_error() == Some(1168) { Ok(()) } else { Err(e.to_string()) }
    }
}

#[cfg(windows)]
impl KeyStore for CredentialStore {
    fn get(&self) -> Option<String> {
        win::read(&self.target)
    }
    fn set(&self, key: &str) -> Result<(), String> {
        if key.is_empty() { win::delete(&self.target) } else { win::write(&self.target, key) }
    }
    fn delete(&self) -> Result<(), String> {
        win::delete(&self.target)
    }
}

#[cfg(not(windows))]
impl KeyStore for CredentialStore {
    fn get(&self) -> Option<String> {
        None
    }
    fn set(&self, _key: &str) -> Result<(), String> {
        Err("no credential store on this platform".into())
    }
    fn delete(&self) -> Result<(), String> {
        Ok(())
    }
}

/// The key to use: `VT_API_KEY`, then the store, then a legacy plaintext `<score key>`.
pub fn resolve_key(k: &pe_db::Knowledge, store: &dyn KeyStore) -> String {
    let env = std::env::var("VT_API_KEY").ok().filter(|v| !v.is_empty());
    env.or_else(|| store.get()).or_else(|| k.settings.get("score", "key").map(str::to_string).filter(|v| !v.is_empty())).unwrap_or_default()
}

/// Move a plaintext `<score key>` from settings.xml into the store and blank it in the file.
/// Returns true when a key was moved. When the store cannot be written the key stays where it is.
pub fn migrate_plaintext_key(k: &mut pe_db::Knowledge, store: &dyn KeyStore) -> Result<bool, String> {
    let Some(key) = k.settings.get("score", "key").map(str::to_string).filter(|v| !v.is_empty()) else {
        return Ok(false);
    };
    store.set(&key)?;
    if k.dir.is_some() {
        k.save_setting("score", "key", "").map_err(|e| e.to_string())?;
    } else {
        k.settings.set("score", "key", "");
    }
    Ok(true)
}
