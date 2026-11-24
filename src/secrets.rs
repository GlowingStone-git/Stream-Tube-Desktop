//! YouTube sign-in secrets live in the OS credential store.
//!
//! The browser-cookie session (`web_session`) and the TV OAuth tokens (`auth`)
//! used to be JSON in the SQLite `kv` table. Anything that could read the
//! profile directory could replay the Google session. They are stored with the
//! `keyring` crate instead:
//!
//! - Windows: Credential Manager
//! - macOS: Keychain
//! - Linux: Secret Service (GNOME Keyring or KWallet)
//!
//! The database keeps only markers (`auth.kept`, `web_session.kept`, and
//! `*.drop` while a sign-out is still waiting on the store). On the first
//! launch after this change, plaintext still in the database is copied into
//! the credential store and those rows are blanked.
//!
//! Windows Credential Manager rejects a credential blob larger than 2560
//! bytes, and the `keyring` crate stores passwords as UTF-16, so the real
//! budget is 1280 code units. A cookie jar is bigger than that, so each
//! secret is split into entries of at most 1000 UTF-16 code units
//! (`auth.0`, `auth.1`, … plus `auth.n` for the count, and the same for
//! `web_session`).
//!
//! If the store can't be opened (headless Linux without a Secret Service, or
//! a locked keyring), the session stays in memory for this process only.
//! It is blanked out of the database rather than written back in plaintext,
//! and Settings → General shows a warning. A sign-out that couldn't reach
//! the store is retried on the next launch (`*.drop`) so the entry doesn't
//! quietly come back.

use parking_lot::Mutex;
use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;

/// TV OAuth tokens (`access_token`, `refresh_token`, expiry, account).
pub const AUTH: &str = "auth";
/// Browser cookies for the youtube.com session.
pub const WEB_SESSION: &str = "web_session";

/// `keyring` service name. Entries show up under this name in Credential
/// Manager / Keychain / Seahorse.
const SERVICE: &str = "streamtube";

/// UTF-16 code units per entry. 1000 units is 2000 bytes, under Credential
/// Manager's 2560-byte blob limit (the `keyring` crate stores UTF-16).
const MAX_UTF16_UNITS: usize = 1000;

/// Enough for a large cookie jar (about 64 KB of ASCII) and no more.
const MAX_CHUNKS: usize = 64;

const MEMORY_ONLY_LONG: &str = "\
Stream Tube couldn't open the system credential store (Windows Credential Manager, \
macOS Keychain, or the Linux Secret Service). This YouTube sign-in is kept in memory \
only and will be forgotten when you quit. The database copy has been cleared. On Linux, \
install and unlock GNOME Keyring or KWallet, then sign in again.";

const UNAVAILABLE_LONG: &str = "\
A YouTube sign-in is saved in the system credential store, but that store couldn't be \
opened, so you are signed out for this run. Unlock it (on Linux: GNOME Keyring or \
KWallet) and restart Stream Tube.";

const PENDING_DELETE_LONG: &str = "\
Sign-out couldn't remove the saved YouTube sign-in from the system credential store. \
Stream Tube will remove it the next time the store is available.";

const MEMORY_ONLY_SHORT: &str = "\
YouTube sign-in will be forgotten when you quit: the system credential store isn't available. See Settings → General.";

const UNAVAILABLE_SHORT: &str = "\
Saved YouTube sign-in couldn't be loaded because the system credential store isn't available. See Settings → General.";

const PENDING_DELETE_SHORT: &str = "\
Sign-out couldn't remove the saved YouTube sign-in from the system credential store. See Settings → General.";

enum EntryError {
    Unavailable(String),
    Corrupt(String),
}

impl std::fmt::Display for EntryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EntryError::Unavailable(m) | EntryError::Corrupt(m) => f.write_str(m),
        }
    }
}

trait EntryStore: Send + Sync {
    fn get(&self, account: &str) -> Result<Option<String>, EntryError>;
    fn set(&self, account: &str, value: &str) -> Result<(), EntryError>;
    fn delete(&self, account: &str) -> Result<(), EntryError>;
}

trait Kv: Send + Sync {
    fn get(&self, key: &str) -> Option<String>;
    fn put(&self, key: &str, value: &str);
}

fn utf16_units(s: &str) -> usize {
    s.encode_utf16().count()
}

fn chunk_secret(secret: &str) -> Vec<String> {
    let mut chunks = Vec::new();
    let mut cur = String::new();
    let mut units = 0usize;
    for ch in secret.chars() {
        let n = ch.len_utf16();
        if units + n > MAX_UTF16_UNITS && !cur.is_empty() {
            chunks.push(std::mem::take(&mut cur));
            units = 0;
        }
        cur.push(ch);
        units += n;
    }
    if !cur.is_empty() {
        chunks.push(cur);
    }
    debug_assert!(chunks.iter().all(|c| utf16_units(c) <= MAX_UTF16_UNITS));
    chunks
}

fn count_account(name: &str) -> String {
    format!("{name}.n")
}

fn part_account(name: &str, index: usize) -> String {
    format!("{name}.{index}")
}

fn kept_key(name: &str) -> String {
    format!("{name}.kept")
}

fn drop_key(name: &str) -> String {
    format!("{name}.drop")
}

/// Splits a secret across several credential entries so each one fits in
/// Windows Credential Manager.
struct Chunked<S> {
    inner: S,
}

impl<S: EntryStore> Chunked<S> {
    fn read_count(&self, name: &str) -> Result<usize, EntryError> {
        match self.inner.get(&count_account(name))? {
            Some(s) => s
                .parse::<usize>()
                .map_err(|_| EntryError::Corrupt("chunk count is unreadable".into())),
            None => Ok(0),
        }
    }
}

impl<S: EntryStore> EntryStore for Chunked<S> {
    fn get(&self, name: &str) -> Result<Option<String>, EntryError> {
        let count = self.read_count(name)?;
        if count == 0 {
            return Ok(None);
        }
        if count > MAX_CHUNKS {
            return Err(EntryError::Corrupt("too many credential chunks".into()));
        }
        let mut out = String::new();
        for i in 0..count {
            match self.inner.get(&part_account(name, i))? {
                Some(chunk) => out.push_str(&chunk),
                None => {
                    return Err(EntryError::Corrupt(format!(
                        "missing credential chunk {i} of {count}"
                    )));
                }
            }
        }
        Ok(Some(out))
    }

    fn set(&self, name: &str, secret: &str) -> Result<(), EntryError> {
        let chunks = chunk_secret(secret);
        if chunks.is_empty() {
            return self.delete(name);
        }
        if chunks.len() > MAX_CHUNKS {
            return Err(EntryError::Unavailable(
                "session is too large for the credential store".into(),
            ));
        }
        let old = self.read_count(name)?;
        for (i, chunk) in chunks.iter().enumerate() {
            self.inner.set(&part_account(name, i), chunk)?;
        }
        self.inner
            .set(&count_account(name), &chunks.len().to_string())?;
        for i in chunks.len()..old {
            self.inner.delete(&part_account(name, i))?;
        }
        Ok(())
    }

    fn delete(&self, name: &str) -> Result<(), EntryError> {
        // A damaged count still needs its chunks removed, so sweep the
        // maximum when the count entry itself can't be trusted.
        let count = match self.read_count(name) {
            Ok(n) => n.min(MAX_CHUNKS),
            Err(EntryError::Corrupt(_)) => MAX_CHUNKS,
            Err(e) => return Err(e),
        };
        for i in 0..count {
            self.inner.delete(&part_account(name, i))?;
        }
        self.inner.delete(&count_account(name))?;
        Ok(())
    }
}

struct State {
    /// `None` means we already looked and there is no secret this run.
    loaded: HashMap<String, Option<String>>,
    ephemeral: HashSet<String>,
    unreadable: HashSet<String>,
    pending_delete: HashSet<String>,
    store_error: Option<String>,
    logged_error: bool,
}

impl Default for State {
    fn default() -> Self {
        Self {
            loaded: HashMap::new(),
            ephemeral: HashSet::new(),
            unreadable: HashSet::new(),
            pending_delete: HashSet::new(),
            store_error: None,
            logged_error: false,
        }
    }
}

struct Vault<S, K> {
    creds: Chunked<S>,
    kv: K,
    state: Mutex<State>,
}

impl<S: EntryStore, K: Kv> Vault<S, K> {
    fn new(store: S, kv: K) -> Self {
        Self {
            creds: Chunked { inner: store },
            kv,
            state: Mutex::new(State::default()),
        }
    }

    fn fresh(&self) -> Self
    where
        S: Clone,
        K: Clone,
    {
        Self::new(self.creds.inner.clone(), self.kv.clone())
    }

    fn load(&self, key: &str) -> Option<String> {
        let mut st = self.state.lock();
        if let Some(hit) = st.loaded.get(key) {
            return hit.clone();
        }
        self.load_uncached(key, &mut st)
    }

    fn save(&self, key: &str, secret: &str) {
        if secret.is_empty() {
            self.clear(key);
            return;
        }
        let mut st = self.state.lock();
        match self.write_verified(key, secret) {
            Ok(()) => {
                self.note_stored(key, &mut st);
                self.kv.put(key, "");
                st.loaded.insert(key.to_string(), Some(secret.to_string()));
            }
            Err(e) => {
                self.remember_store_error(&mut st, &e.to_string());
                self.keep_in_memory(key, secret.to_string(), &mut st);
            }
        }
    }

    fn clear(&self, key: &str) {
        let mut st = self.state.lock();
        let durable =
            self.kv.get(&kept_key(key)).is_some() || self.kv.get(&drop_key(key)).is_some();
        let deleted = self.creds.delete(key);
        self.kv.put(key, "");
        st.ephemeral.remove(key);
        st.unreadable.remove(key);
        st.loaded.insert(key.to_string(), None);
        match deleted {
            Ok(()) => {
                self.kv.put(&kept_key(key), "");
                self.kv.put(&drop_key(key), "");
                st.pending_delete.remove(key);
            }
            Err(e) if !durable => {
                // Nothing was ever persisted (or the only copy is this process).
                self.kv.put(&kept_key(key), "");
                self.kv.put(&drop_key(key), "");
                st.pending_delete.remove(key);
                let _ = e;
            }
            Err(e) => {
                self.remember_store_error(&mut st, &e.to_string());
                // Stay signed out now, and delete the entry once the store answers.
                self.kv.put(&kept_key(key), "");
                self.kv.put(&drop_key(key), "1");
                st.pending_delete.insert(key.to_string());
            }
        }
    }

    fn warning_messages(&self) -> Vec<String> {
        let st = self.state.lock();
        let mut out = Vec::new();
        if !st.ephemeral.is_empty() {
            out.push(with_detail(MEMORY_ONLY_LONG, st.store_error.as_deref()));
        }
        if !st.unreadable.is_empty() {
            out.push(with_detail(UNAVAILABLE_LONG, st.store_error.as_deref()));
        }
        if !st.pending_delete.is_empty() {
            out.push(with_detail(PENDING_DELETE_LONG, st.store_error.as_deref()));
        }
        out
    }

    fn short_warning(&self) -> Option<String> {
        let st = self.state.lock();
        let mut parts = Vec::new();
        if !st.ephemeral.is_empty() {
            parts.push(MEMORY_ONLY_SHORT);
        }
        if !st.unreadable.is_empty() {
            parts.push(UNAVAILABLE_SHORT);
        }
        if !st.pending_delete.is_empty() {
            parts.push(PENDING_DELETE_SHORT);
        }
        if parts.is_empty() {
            None
        } else {
            Some(parts.join(" "))
        }
    }

    fn load_uncached(&self, key: &str, st: &mut State) -> Option<String> {
        if self.kv.get(&drop_key(key)).is_some() {
            return self.finish_pending_delete(key, st);
        }
        let legacy = self.kv.get(key);
        let kept = self.kv.get(&kept_key(key)).is_some();
        match self.creds.get(key) {
            Ok(Some(secret)) => {
                self.note_stored(key, st);
                if legacy.is_some() {
                    self.kv.put(key, "");
                }
                st.loaded.insert(key.to_string(), Some(secret.clone()));
                Some(secret)
            }
            Ok(None) => {
                if let Some(secret) = legacy {
                    self.migrate(key, secret, st)
                } else {
                    if kept {
                        // The marker outlived the credential (removed outside the app).
                        self.kv.put(&kept_key(key), "");
                    }
                    st.unreadable.remove(key);
                    st.loaded.insert(key.to_string(), None);
                    None
                }
            }
            Err(EntryError::Corrupt(detail)) => {
                self.remember_store_error(st, &detail);
                if let Some(secret) = legacy {
                    self.migrate(key, secret, st)
                } else {
                    st.unreadable.insert(key.to_string());
                    st.loaded.insert(key.to_string(), None);
                    None
                }
            }
            Err(EntryError::Unavailable(detail)) => {
                self.remember_store_error(st, &detail);
                if let Some(secret) = legacy {
                    self.keep_in_memory(key, secret, st)
                } else if kept {
                    st.unreadable.insert(key.to_string());
                    st.loaded.insert(key.to_string(), None);
                    None
                } else {
                    st.loaded.insert(key.to_string(), None);
                    None
                }
            }
        }
    }

    fn finish_pending_delete(&self, key: &str, st: &mut State) -> Option<String> {
        match self.creds.delete(key) {
            Ok(()) => {
                self.kv.put(&drop_key(key), "");
                self.kv.put(&kept_key(key), "");
                self.kv.put(key, "");
                st.pending_delete.remove(key);
                st.loaded.insert(key.to_string(), None);
                None
            }
            Err(e) => {
                self.remember_store_error(st, &e.to_string());
                st.pending_delete.insert(key.to_string());
                st.loaded.insert(key.to_string(), None);
                None
            }
        }
    }

    fn migrate(&self, key: &str, secret: String, st: &mut State) -> Option<String> {
        match self.write_verified(key, &secret) {
            Ok(()) => {
                self.note_stored(key, st);
                self.kv.put(key, "");
                st.loaded.insert(key.to_string(), Some(secret.clone()));
                Some(secret)
            }
            Err(e) => {
                self.remember_store_error(st, &e.to_string());
                self.keep_in_memory(key, secret, st)
            }
        }
    }

    /// Remember `secret` for this process and make sure the database does not
    /// keep a plaintext copy. A partial credential write is deleted when the
    /// store still answers.
    fn keep_in_memory(&self, key: &str, secret: String, st: &mut State) -> Option<String> {
        self.kv.put(key, "");
        self.kv.put(&kept_key(key), "");
        let _ = self.creds.delete(key);
        st.ephemeral.insert(key.to_string());
        st.unreadable.remove(key);
        st.loaded.insert(key.to_string(), Some(secret.clone()));
        Some(secret)
    }

    fn note_stored(&self, key: &str, st: &mut State) {
        self.kv.put(&kept_key(key), "1");
        self.kv.put(&drop_key(key), "");
        st.ephemeral.remove(key);
        st.unreadable.remove(key);
        st.pending_delete.remove(key);
    }

    fn write_verified(&self, key: &str, secret: &str) -> Result<(), EntryError> {
        self.creds.set(key, secret)?;
        match self.creds.get(key) {
            Ok(Some(got)) if got == secret => Ok(()),
            Ok(_) => {
                let _ = self.creds.delete(key);
                Err(EntryError::Corrupt(
                    "credential store read-back did not match".into(),
                ))
            }
            Err(e) => {
                let _ = self.creds.delete(key);
                Err(e)
            }
        }
    }

    fn remember_store_error(&self, st: &mut State, detail: &str) {
        if st.store_error.is_none() {
            let detail: String = detail.chars().take(200).collect();
            st.store_error = Some(detail);
        }
        if !st.logged_error {
            st.logged_error = true;
            if let Some(detail) = &st.store_error {
                eprintln!("streamtube: credential store: {detail}");
            }
        }
    }
}

fn with_detail(message: &str, detail: Option<&str>) -> String {
    match detail {
        Some(d) if !d.is_empty() => format!("{message} ({d})"),
        _ => message.to_string(),
    }
}

struct KeyringStore;

fn map_keyring(err: keyring::Error) -> EntryError {
    match err {
        keyring::Error::NoEntry => EntryError::Unavailable("no credential entry".into()),
        keyring::Error::BadEncoding(_) => {
            EntryError::Corrupt("credential is not valid text".into())
        }
        keyring::Error::TooLong(attr, limit) => EntryError::Corrupt(format!(
            "{attr} exceeds the credential store limit of {limit}"
        )),
        keyring::Error::Ambiguous(_) => {
            EntryError::Corrupt("several credentials match this sign-in".into())
        }
        other => EntryError::Unavailable(other.to_string()),
    }
}

impl EntryStore for KeyringStore {
    fn get(&self, account: &str) -> Result<Option<String>, EntryError> {
        let entry = keyring::Entry::new(SERVICE, account).map_err(map_keyring)?;
        match entry.get_password() {
            Ok(v) => Ok(Some(v)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(map_keyring(e)),
        }
    }

    fn set(&self, account: &str, value: &str) -> Result<(), EntryError> {
        let entry = keyring::Entry::new(SERVICE, account).map_err(map_keyring)?;
        entry.set_password(value).map_err(map_keyring)
    }

    fn delete(&self, account: &str) -> Result<(), EntryError> {
        let entry = keyring::Entry::new(SERVICE, account).map_err(map_keyring)?;
        match entry.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(map_keyring(e)),
        }
    }
}

struct DbKv;

impl Kv for DbKv {
    fn get(&self, key: &str) -> Option<String> {
        crate::store::kv_get(key).filter(|s| !s.is_empty())
    }

    fn put(&self, key: &str, value: &str) {
        // The session keys themselves may only be blanked. Markers hold "1"
        // or "". Anything else would be the secret landing in SQLite again.
        let marker = key.ends_with(".kept") || key.ends_with(".drop");
        if !marker && !value.is_empty() {
            eprintln!("streamtube: refused to write session material for {key} into the database");
            return;
        }
        if marker && value != "1" && !value.is_empty() {
            eprintln!("streamtube: refused to write session material for {key} into the database");
            return;
        }
        crate::store::kv_set(key, value);
    }
}

fn global() -> &'static Vault<KeyringStore, DbKv> {
    static V: OnceLock<Vault<KeyringStore, DbKv>> = OnceLock::new();
    V.get_or_init(|| Vault::new(KeyringStore, DbKv))
}

/// Load both secrets once so a database row is migrated before the UI asks,
/// and so a missing credential store is reported at startup.
pub fn preload() {
    let _ = global().load(AUTH);
    let _ = global().load(WEB_SESSION);
}

pub fn load(key: &str) -> Option<String> {
    global().load(key)
}

pub fn save(key: &str, secret: &str) {
    global().save(key, secret);
}

pub fn clear(key: &str) {
    global().clear(key);
}

/// Full explanation for Settings → General. Empty when the store is fine
/// or there is no session to protect.
pub fn warning_messages() -> Vec<String> {
    global().warning_messages()
}

/// One line for a toast. `None` when there's nothing to warn about.
pub fn short_warning() -> Option<String> {
    global().short_warning()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Fault {
        Ok,
        Down,
        /// `set` reports success and stores nothing, so read-back fails.
        Forgetful,
    }

    #[derive(Clone)]
    struct MapStore {
        entries: Arc<Mutex<HashMap<String, String>>>,
        fault: Arc<Mutex<Fault>>,
    }

    impl MapStore {
        fn new() -> Self {
            Self {
                entries: Arc::new(Mutex::new(HashMap::new())),
                fault: Arc::new(Mutex::new(Fault::Ok)),
            }
        }

        fn set_fault(&self, fault: Fault) {
            *self.fault.lock() = fault;
        }
    }

    impl EntryStore for MapStore {
        fn get(&self, account: &str) -> Result<Option<String>, EntryError> {
            match *self.fault.lock() {
                Fault::Down => Err(EntryError::Unavailable(
                    "secret service not available".into(),
                )),
                Fault::Forgetful => Ok(None),
                Fault::Ok => Ok(self.entries.lock().get(account).cloned()),
            }
        }

        fn set(&self, account: &str, value: &str) -> Result<(), EntryError> {
            match *self.fault.lock() {
                Fault::Down => Err(EntryError::Unavailable(
                    "secret service not available".into(),
                )),
                Fault::Forgetful => Ok(()),
                Fault::Ok => {
                    self.entries
                        .lock()
                        .insert(account.to_string(), value.to_string());
                    Ok(())
                }
            }
        }

        fn delete(&self, account: &str) -> Result<(), EntryError> {
            match *self.fault.lock() {
                Fault::Down => Err(EntryError::Unavailable(
                    "secret service not available".into(),
                )),
                Fault::Ok | Fault::Forgetful => {
                    self.entries.lock().remove(account);
                    Ok(())
                }
            }
        }
    }

    #[derive(Clone, Default)]
    struct MemKv {
        map: Arc<Mutex<HashMap<String, String>>>,
    }

    impl Kv for MemKv {
        fn get(&self, key: &str) -> Option<String> {
            self.map.lock().get(key).cloned().filter(|s| !s.is_empty())
        }

        fn put(&self, key: &str, value: &str) {
            self.map.lock().insert(key.to_string(), value.to_string());
        }
    }

    fn vault() -> (Vault<MapStore, MemKv>, MapStore, MemKv) {
        let store = MapStore::new();
        let kv = MemKv::default();
        let v = Vault::new(store.clone(), kv.clone());
        (v, store, kv)
    }

    fn assert_no_secret(kv: &MemKv, needle: &str) {
        for (k, v) in kv.map.lock().iter() {
            assert!(!v.contains(needle), "{k} holds session material: {v}");
        }
    }

    const TOKEN: &str = "ya29.SUPERSECRET-refresh-1//SUPERSECRET";

    fn legacy_auth() -> String {
        format!(
            r#"{{"access_token":"{TOKEN}","refresh_token":"{TOKEN}","expires_at":10,"account":{{"name":"Ada"}}}}"#
        )
    }

    #[test]
    fn chunks_stay_under_the_windows_credential_limit() {
        let exact: String = "a".repeat(MAX_UTF16_UNITS);
        assert_eq!(chunk_secret(&exact).len(), 1);

        let over: String = "a".repeat(MAX_UTF16_UNITS + 1);
        let parts = chunk_secret(&over);
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0].len(), MAX_UTF16_UNITS);
        assert_eq!(parts[1], "a");

        // An emoji is one char and two UTF-16 units, so it must not be
        // appended to a chunk that only has one unit of room left.
        let boundary = format!("{}😀", "a".repeat(MAX_UTF16_UNITS - 1));
        let parts = chunk_secret(&boundary);
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[1], "😀");
        assert!(parts.iter().all(|c| utf16_units(c) <= MAX_UTF16_UNITS));
        assert!(parts.iter().all(|c| utf16_units(c) * 2 <= 2560));
    }

    #[test]
    fn plaintext_session_moves_into_the_store_and_leaves_the_db_blank() {
        let (v, store, kv) = vault();
        kv.put(AUTH, &legacy_auth());
        let loaded = v.load(AUTH).expect("session");
        assert_eq!(loaded, legacy_auth());
        assert_eq!(kv.map.lock().get(AUTH).map(String::as_str), Some(""));
        assert_eq!(
            kv.map.lock().get(&kept_key(AUTH)).map(String::as_str),
            Some("1")
        );
        assert_no_secret(&kv, "SUPERSECRET");
        assert!(v.warning_messages().is_empty());

        // Next launch reads the credential store, not the database.
        let again = v.fresh().load(AUTH).expect("still signed in");
        assert_eq!(again, legacy_auth());
        assert_eq!(kv.map.lock().get(AUTH).map(String::as_str), Some(""));
        assert_no_secret(&kv, "SUPERSECRET");
        let _ = store;
    }

    #[test]
    fn large_cookie_jar_is_split_under_the_windows_limit() {
        let (v, store, kv) = vault();
        let cookie = format!("COOKIESECRET:{}", "x".repeat(5_000));
        let legacy =
            format!(r#"{{"cookies":{{"SAPISID":"{cookie}","SID":"sid"}},"account":"Ada"}}"#);
        kv.put(WEB_SESSION, &legacy);
        assert_eq!(v.load(WEB_SESSION).as_deref(), Some(legacy.as_str()));
        assert_no_secret(&kv, "COOKIESECRET");
        assert_no_secret(&kv, "SAPISID");

        let entries = store.entries.lock();
        let mut chunks = 0;
        for (k, val) in entries.iter() {
            assert!(k.starts_with("web_session."), "{k}");
            assert!(
                utf16_units(val) <= MAX_UTF16_UNITS,
                "{k} is {} utf-16 units",
                utf16_units(val)
            );
            assert!(utf16_units(val) * 2 <= 2560);
            if k != "web_session.n" {
                chunks += 1;
            }
        }
        assert!(
            chunks >= 5,
            "expected the cookie jar to be split, got {chunks} chunks"
        );
        let count = chunks.to_string();
        assert_eq!(
            entries.get("web_session.n").map(String::as_str),
            Some(count.as_str())
        );
    }

    #[test]
    fn smaller_secret_drops_leftover_chunks() {
        let (v, store, kv) = vault();
        v.save(AUTH, &"p".repeat(2_500));
        assert!(store.entries.lock().contains_key("auth.2"));
        v.save(AUTH, "short-token");
        {
            let entries = store.entries.lock();
            assert_eq!(entries.get("auth.n").map(String::as_str), Some("1"));
            assert_eq!(
                entries.get("auth.0").map(String::as_str),
                Some("short-token")
            );
            assert!(!entries.contains_key("auth.1"));
            assert!(!entries.contains_key("auth.2"));
        }
        assert_no_secret(&kv, "short-token");
        assert_eq!(v.fresh().load(AUTH).as_deref(), Some("short-token"));
    }

    #[test]
    fn sign_out_removes_credential_entries() {
        let (v, store, kv) = vault();
        kv.put(AUTH, &legacy_auth());
        kv.put(WEB_SESSION, r#"{"cookies":{"SAPISID":"SUPERSECRET"}}"#);
        assert!(v.load(AUTH).is_some());
        assert!(v.load(WEB_SESSION).is_some());
        v.clear(AUTH);
        assert!(v.load(AUTH).is_none());
        assert!(v.fresh().load(AUTH).is_none());
        assert!(store.entries.lock().keys().all(|k| !k.starts_with("auth")));
        assert_eq!(
            kv.map.lock().get(&kept_key(AUTH)).map(String::as_str),
            Some("")
        );
        // The other session is untouched.
        assert_eq!(
            v.fresh().load(WEB_SESSION).as_deref(),
            Some(r#"{"cookies":{"SAPISID":"SUPERSECRET"}}"#)
        );
        v.clear(WEB_SESSION);
        assert!(v.fresh().load(WEB_SESSION).is_none());
        assert!(store.entries.lock().is_empty());
        assert_no_secret(&kv, "SUPERSECRET");
    }

    #[test]
    fn missing_credential_store_keeps_the_session_in_memory_only() {
        let (v, store, kv) = vault();
        kv.put(AUTH, &legacy_auth());
        store.set_fault(Fault::Down);
        assert_eq!(v.load(AUTH).as_deref(), Some(legacy_auth().as_str()));
        assert_eq!(kv.map.lock().get(AUTH).map(String::as_str), Some(""));
        assert_ne!(
            kv.map.lock().get(&kept_key(AUTH)).map(String::as_str),
            Some("1")
        );
        assert_no_secret(&kv, "SUPERSECRET");
        let warnings = v.warning_messages();
        assert!(
            warnings.iter().any(|m| m.contains("in memory only")),
            "{warnings:?}"
        );
        assert!(
            v.short_warning()
                .unwrap()
                .contains("forgotten when you quit")
        );

        // A new sign-in in the same situation is not written to the database.
        v.save(WEB_SESSION, "COOKIESECRET-new");
        assert_eq!(v.load(WEB_SESSION).as_deref(), Some("COOKIESECRET-new"));
        assert_no_secret(&kv, "COOKIESECRET");
        assert_eq!(kv.map.lock().get(WEB_SESSION).map(String::as_str), Some(""));

        // Next launch has neither the old plaintext nor a credential entry.
        store.set_fault(Fault::Ok);
        assert!(v.fresh().load(AUTH).is_none());
        assert!(v.fresh().load(WEB_SESSION).is_none());
    }

    #[test]
    fn saved_sign_in_is_not_loaded_when_the_store_is_down() {
        let (v, store, kv) = vault();
        v.save(AUTH, &legacy_auth());
        assert_eq!(
            kv.map.lock().get(&kept_key(AUTH)).map(String::as_str),
            Some("1")
        );
        store.set_fault(Fault::Down);
        let next = v.fresh();
        assert!(next.load(AUTH).is_none());
        let warnings = next.warning_messages();
        assert!(
            warnings
                .iter()
                .any(|m| m.contains("signed out for this run")),
            "{warnings:?}"
        );
        // The marker stays so the next launch can try the store again.
        assert_eq!(
            kv.map.lock().get(&kept_key(AUTH)).map(String::as_str),
            Some("1")
        );
        assert_no_secret(&kv, "SUPERSECRET");
        store.set_fault(Fault::Ok);
        assert_eq!(
            v.fresh().load(AUTH).as_deref(),
            Some(legacy_auth().as_str())
        );
    }

    #[test]
    fn failed_sign_out_is_retried_on_the_next_launch() {
        let (v, store, kv) = vault();
        v.save(AUTH, &legacy_auth());
        store.set_fault(Fault::Down);
        v.clear(AUTH);
        assert!(v.load(AUTH).is_none());
        assert_eq!(
            kv.map.lock().get(&drop_key(AUTH)).map(String::as_str),
            Some("1")
        );
        assert!(
            v.warning_messages()
                .iter()
                .any(|m| m.contains("couldn't remove"))
        );
        // While the store is down the secret is still physically there, but
        // it must not sign the user back in.
        assert!(store.entries.lock().contains_key("auth.0"));
        assert!(v.fresh().load(AUTH).is_none());

        store.set_fault(Fault::Ok);
        assert!(v.fresh().load(AUTH).is_none());
        assert!(store.entries.lock().keys().all(|k| !k.starts_with("auth")));
        assert_eq!(
            kv.map.lock().get(&drop_key(AUTH)).map(String::as_str),
            Some("")
        );
        assert_no_secret(&kv, "SUPERSECRET");
    }

    #[test]
    fn store_that_drops_writes_does_not_leave_plaintext_behind() {
        let (v, store, kv) = vault();
        kv.put(AUTH, &legacy_auth());
        store.set_fault(Fault::Forgetful);
        assert_eq!(v.load(AUTH).as_deref(), Some(legacy_auth().as_str()));
        assert_eq!(kv.map.lock().get(AUTH).map(String::as_str), Some(""));
        assert_no_secret(&kv, "SUPERSECRET");
        assert!(
            store.entries.lock().is_empty(),
            "a failed read-back must not leave chunks"
        );
        assert!(
            v.warning_messages()
                .iter()
                .any(|m| m.contains("in memory only"))
        );
    }
}
