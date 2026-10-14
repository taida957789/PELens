//! VirusTotal key storage. Its own test binary: one test changes `VT_API_KEY` for the process.
use pe_online::secret::*;
use std::sync::Arc;

struct Failing;
impl KeyStore for Failing {
    fn get(&self) -> Option<String> {
        None
    }
    fn set(&self, _key: &str) -> Result<(), String> {
        Err("locked".into())
    }
    fn delete(&self) -> Result<(), String> {
        Err("locked".into())
    }
}

fn kb(tag: &str) -> std::path::PathBuf {
    let dir = pe_analysis::testkit::write_knowledge(&format!("secret-{tag}"));
    let st = std::fs::read_to_string(dir.join("settings.xml")).unwrap().replace("key=\"\"", "key=\"PLAIN\"");
    std::fs::write(dir.join("settings.xml"), st).unwrap();
    dir
}

#[test]
fn key_order_migration_and_stores() {
    // SAFETY: the only test of this binary that reads or changes the environment.
    unsafe { std::env::remove_var("VT_API_KEY") };
    let mut k = pe_db::Knowledge::builtin();
    let store = MemoryStore::default();
    assert_eq!(resolve_key(&k, &store), "");
    k.settings.set("score", "key", "PLAIN");
    assert_eq!(resolve_key(&k, &store), "PLAIN", "legacy plaintext setting");
    store.set("STORED").unwrap();
    assert_eq!(resolve_key(&k, &store), "STORED", "the store wins over settings.xml");
    unsafe { std::env::set_var("VT_API_KEY", "ENV") };
    assert_eq!(resolve_key(&k, &store), "ENV", "the environment wins over everything");
    unsafe { std::env::set_var("VT_API_KEY", "") };
    assert_eq!(resolve_key(&k, &store), "STORED", "an empty variable is ignored");
    unsafe { std::env::remove_var("VT_API_KEY") };
    store.delete().unwrap();
    assert_eq!(store.get(), None);

    // migration: in memory only (no directory)
    let s2 = MemoryStore::default();
    assert!(migrate_plaintext_key(&mut k, &s2).unwrap());
    assert_eq!((s2.get().as_deref(), k.settings.get("score", "key")), (Some("PLAIN"), Some("")));
    assert!(!migrate_plaintext_key(&mut k, &s2).unwrap(), "nothing left to move");

    // migration: settings.xml on disk is rewritten without the key
    let dir = kb("disk");
    let mut k = pe_db::Knowledge::load(&dir);
    let shared = Arc::new(MemoryStore::default());
    assert!(migrate_plaintext_key(&mut k, &shared).unwrap());
    assert_eq!(shared.get().as_deref(), Some("PLAIN"));
    let on_disk = std::fs::read_to_string(dir.join("settings.xml")).unwrap();
    assert!(!on_disk.contains("PLAIN") && on_disk.contains("key=\"\""), "{on_disk}");
    assert_eq!(pe_db::Knowledge::load(&dir).settings.get("score", "key"), Some(""));

    // a store that cannot be written leaves the key where it was
    let dir = kb("fail");
    let mut k = pe_db::Knowledge::load(&dir);
    assert_eq!(migrate_plaintext_key(&mut k, &Failing).unwrap_err(), "locked");
    assert!(std::fs::read_to_string(dir.join("settings.xml")).unwrap().contains("PLAIN"));
    assert_eq!(resolve_key(&k, &Failing), "PLAIN");

    // the settings used for queries come from the same resolution
    let (_, key, _) = pe_online::vt_settings_with(&k, &MemoryStore::with("M"));
    assert_eq!(key, "M");
    let arc: Arc<dyn KeyStore> = Arc::new(MemoryStore::with("A"));
    arc.set("B").unwrap();
    assert_eq!(arc.get().as_deref(), Some("B"));
    arc.delete().unwrap();
    assert_eq!(arc.get(), None);
}

/// The real Windows Credential Manager, under a name used only by this test.
#[cfg(windows)]
#[test]
fn windows_credential_manager() {
    let c = CredentialStore::new(&format!("PELens/test-{}", std::process::id()));
    assert_eq!(c.get(), None);
    c.delete().unwrap(); // deleting a missing credential is fine
    c.set("sécret-ключ-鍵").unwrap();
    assert_eq!(c.get().as_deref(), Some("sécret-ключ-鍵"));
    c.set("other").unwrap();
    assert_eq!(c.get().as_deref(), Some("other"));
    c.set("").unwrap(); // an empty key removes the credential
    assert_eq!(c.get(), None);
    c.set("x").unwrap();
    c.delete().unwrap();
    assert_eq!(c.get(), None);
    assert_eq!(CredentialStore::vt().target, VT_TARGET);
    // invalid target names are reported, not panicked on
    assert!(CredentialStore::new("").set("x").is_err());
}
