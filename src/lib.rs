#![doc = include_str!("../README.md")]

use std::{
    collections::{
        HashMap,
    },
    sync::atomic,
};
use std::sync::{Arc, RwLock, RwLockReadGuard};
use libc::{
    c_char,
    c_int,
    c_void,
    size_t,
};

use sequoia_openpgp as openpgp;
use openpgp::{
    Fingerprint,
    KeyHandle,
    KeyID,
    cert::{
        Cert,
    },
    crypto::{
        Password,
        mem::Protected,
    },
    packet::{
        Key,
        key::{SecretParts, UnspecifiedParts, UnspecifiedRole},
        UserID,
    },
    policy::{
        NullPolicy,
        StandardPolicy,
    },
    serialize::Serialize,
};

/// Controls tracing.
const TRACE: bool = cfg!(debug_assertions)
    && option_env!("SEQUOIA_OCTOPUS_DISABLE_TRACING").is_none();

/// Enable Thunderbird-specific quirks
///
/// If true, then the octopus will deviate from RNP's behavior in
/// order to work around a bug or assumption in Thunderbird.  This
/// also clearly marks all occurrences of workarounds in this crate.
const THUNDERBIRD_WORKAROUND: bool = true;

#[allow(unused_macros)]
macro_rules! stub {
    ($s: ident) => {
        #[no_mangle] pub extern "C"
        fn $s() -> crate::RnpResult {
            log!("\nSTUB: {}\n", stringify!($s));
            crate::RNP_ERROR_NOT_IMPLEMENTED
        }
    };
}

#[allow(dead_code)]
#[macro_use]
pub mod error;
use error::*;

#[allow(dead_code)]
pub mod stubs;

use sequoia_ipc::Keygrip;

pub mod keystore;
use keystore::Keystore;

pub mod buffer;
use buffer::*;

#[allow(dead_code)]
pub mod flags;
use flags::*;
#[allow(dead_code)]
pub mod io;
use io::*;
#[allow(dead_code)]
pub mod utils;
use utils::*;
#[allow(dead_code)]
pub mod conversions;
use conversions::*;

pub mod version;
#[allow(dead_code)]
pub mod op_verify;
#[allow(dead_code)]
pub mod op_encrypt;
#[allow(dead_code)]
pub mod op_sign;
pub mod recombine;
#[allow(dead_code)]
pub mod op_generate;
#[allow(dead_code)]
pub mod signature;
use signature::RnpSignature;
#[allow(dead_code)]
pub mod key;
use key::RnpKey;
#[allow(dead_code)]
pub mod iter;
#[allow(dead_code)]
pub mod userid;
use userid::RnpUserID;
#[allow(dead_code)]
pub mod import;
pub mod security_rules;
pub mod dump_packets;
pub mod armor;

// The gpg module is copied from OpenPGP CA.  We don't want to modify
// it.
#[allow(dead_code)]
pub mod gpg;

pub mod tbprofile;
pub mod wot;
pub mod parcimonie;

pub const NP: &NullPolicy = unsafe { &NullPolicy::new() };

#[allow(dead_code)]
fn cert_dump(cert: &Cert) {
    use openpgp::packet::key::SecretKeyMaterial;

    eprintln!("Cert: {}, {}", cert.fingerprint(),
              cert.with_policy(&StandardPolicy::new(), None)
              .map(|cert| {
                  cert.primary_userid()
                      .map(|ua| {
                          String::from_utf8_lossy(ua.userid().value())
                              .into_owned()
                      })
                      .unwrap_or("<No UserID>"[..].into())
              })
              .unwrap_or("<Invalid>".into()));

    for (i, k) in cert.keys().enumerate() {
        eprint!("  {}. {}", i, k.key().fingerprint());
        match k.key().optional_secret() {
            Some(SecretKeyMaterial::Unencrypted(_)) => {
                eprint!(" has unencrypted secret key material");
            }
            Some(SecretKeyMaterial::Encrypted(_)) => {
                eprint!(" has encrypted secret key material");
            }
            None => {
                eprint!(" has NO secret key material");
            }
        }
        eprintln!("");
    }
}

#[derive(Default)]
pub struct RnpContext {
    policy: Arc<RwLock<StandardPolicy<'static>>>,
    certs: Keystore,
    unlocked_keys: HashMap<Fingerprint, Key<SecretParts, UnspecifiedRole>>,
    password_cb: Option<(RnpPasswordCb, *mut c_void)>,
    plaintext_cache: recombine::PlaintextCache,
}

type RnpPasswordCb = unsafe extern fn(*mut RnpContext,
                                      *mut c_void,
                                      *const RnpKey,
                                      *const c_char,
                                      *mut c_char,
                                      size_t) -> bool;

#[no_mangle] pub unsafe extern "C"
fn rnp_ffi_create(ctx: *mut *mut RnpContext,
                  pub_fmt: *const c_char,
                  sec_fmt: *const c_char)
                  -> RnpResult
{
    rnp_function!(rnp_ffi_create, crate::TRACE);
    assert_ptr!(ctx);
    let pub_fmt = assert_str!(pub_fmt);
    let sec_fmt = assert_str!(sec_fmt);
    if pub_fmt != "GPG" || sec_fmt != "GPG" {
        rnp_return_status!(RNP_ERROR_BAD_FORMAT);
    }

    // Try to make sure that a pubring.gpg exists.  Thunderbird will
    // read in the file, and if that succeeds, invoke rnp_load_keys
    // with it.  It is important to us that this call happens, because
    // this will set up our GnuPG synchronization.
    //
    // This is a best-effort mechanism.
    if let Some(profile) = tbprofile::TBProfile::path() {
        let maybe_create_keyring = |path: std::path::PathBuf| {
            // Create an empty keyring if the file does not exist.
            if let Ok(mut sink) =
                std::fs::OpenOptions::new().write(true).create_new(true)
                .open(&path)
            {
                // The empty keyring must not be zero-sized, because
                // Thunderbird equates that with no file or any other io
                // error reading the file.  So, let's write a marker
                // packet.
                //
                // A marker packet is safe, it will be ignored by both RNP
                // and Sequoia.  Thunderbird with both RNP and the Octopus
                // will happily import certs into such a keyring.
                match openpgp::Packet::Marker(Default::default())
                    .serialize(&mut sink)
                {
                    Ok(_) =>
                        t!("Created new empty keyring in {}", path.display()),
                    Err(e) =>
                        t!("Creating new empty keyring in {} failed: {}",
                           path.display(), e),
                }
            } else if let Ok(mut sink) =
                std::fs::OpenOptions::new().write(true).create(false)
                .open(&path)
            {
                // See if the existing file is empty.
                if let Ok(0) = sink.metadata().map(|m| m.len()) {
                    // It is.  This will prevent rnp_load_keys from
                    // being invoked, see above.  Modify it in place.
                    // No one else is updating these files in place,
                    // so we don't risk clobbering the keyring here.
                    match openpgp::Packet::Marker(Default::default())
                        .serialize(&mut sink)
                    {
                        Ok(_) =>
                            t!("Wrote marker to empty keyring in {}",
                               path.display()),
                        Err(e) =>
                            t!("Writing marker to empty keyring in {} \
                                failed: {}", path.display(), e),
                    }
                }
            }
        };

        maybe_create_keyring(profile.join("pubring.gpg"));
        maybe_create_keyring(profile.join("secring.gpg"));
    }

    let mut policy = sequoia_policy_config::ConfiguredStandardPolicy::new();
    if let Err(e) = policy.parse_default_config() {
        global_warn!("Reading crypto policy: {}", e);
    }
    let policy = policy.build();

    *ctx = Box::into_raw(Box::new(RnpContext {
        policy: Arc::new(RwLock::new(policy)),
        ..Default::default()
    }));
    rnp_success!()
}

#[no_mangle] pub unsafe extern "C"
fn rnp_ffi_destroy(ctx: *mut RnpContext) -> RnpResult {
    rnp_function!(rnp_ffi_destroy, crate::TRACE);
    arg!(ctx);
    if ! ctx.is_null() {
        drop(Box::from_raw(ctx));
    }
    rnp_success!()
}

#[no_mangle] pub unsafe extern "C"
fn rnp_ffi_set_log_fd(ctx: *mut RnpContext, _fd: c_int) -> RnpResult {
    rnp_function!(rnp_ffi_set_log_fd, crate::TRACE);
    let _ = assert_ptr_mut!(ctx);
    rnp_success!()
}

#[no_mangle] pub unsafe extern "C"
fn rnp_ffi_set_pass_provider(ctx: *mut RnpContext,
                             cb: RnpPasswordCb,
                             cookie: *mut c_void)
                             -> RnpResult {
    rnp_function!(rnp_ffi_set_pass_provider, crate::TRACE);
    let ctx = assert_ptr_mut!(ctx);
    arg!(cb);
    arg!(cookie);
    ctx.password_cb = Some((cb, cookie));
    rnp_success!()
}

impl RnpContext {
    pub fn policy(&self) -> RwLockReadGuard<StandardPolicy<'static>> {
        self.policy.read().unwrap()
    }

    /// Inserts a cert into the keystore.
    ///
    /// This strips any secret key material.
    ///
    /// # Locking
    ///
    /// This acquires a write lock on the keystore and, if the
    /// certificate is already present, a write lock on the
    /// certificate's cell.
    pub fn insert_cert(&mut self, cert: Cert) {
        self.certs.write().insert(cert.strip_secret_key_material());
    }

    /// Inserts a cert from an external source into the keystore.
    ///
    /// This strips any secret key material.
    ///
    /// certs from external sources won't be serialized.
    ///
    /// # Locking
    ///
    /// This acquires a write lock on the keystore and, if the
    /// certificate is already present, a write lock on the
    /// certificate's cell.
    pub fn insert_cert_external(&mut self, cert: Cert) {
        self.certs.write().insert_external(cert.strip_secret_key_material());
    }

    /// Inserts a key into the keystore.
    ///
    /// Secret key material is preserved.
    ///
    /// # Locking
    ///
    /// This acquires a write lock on the keystore and, if the
    /// certificate is already present, a write lock on the
    /// certificate's cell.
    pub fn insert_key(&mut self, cert: Cert) {
        self.certs.write().insert(cert);
    }

    /// Retrieves a certificate from the keystore by userid.
    ///
    /// RNP searches both the certring and the keyring, and the
    /// keyhandle can thus refer to two certificates, potentially
    /// different versions of the same, or even different
    /// certificates!  Since we merge the key keyrings, this is not a
    /// problem for us.
    ///
    /// # Locking
    ///
    /// This acquires a read lock on the keystore and one or more
    /// certificates' cells.  See the corresponding search methods for
    /// details.
    pub fn cert(&self, by: &RnpIdentifier) -> Option<Cert> {
        rnp_function!(RnpContext::cert, TRACE);

        use RnpIdentifier::*;
        let cert = match by {
            UserID(id) => self.cert_by_userid(id),
            KeyID(id) => self.cert_by_subkey_id(id),
            Fingerprint(fp) => self.cert_by_subkey_fp(fp),
            Keygrip(grip) => self.cert_by_subkey_grip(grip),
        };

        t!("Lookup by {:?} returned cert {:?}",
           by,
           cert.as_ref().map(|c| c.fingerprint()));

        cert
    }

    /// Retrieves a certificate by userid.
    ///
    /// XXX: This is super dodgy.  rnp.h says "Note: only valid
    /// userids are checked while searching by userid." but it is not
    /// clear what that means.
    ///
    /// XXX: I think it would be better to fail these lookups.  Are
    /// they used by TB?
    ///
    /// # Locking
    ///
    /// This acquires a read lock on the keystore.  Currently, this
    /// function performs a linear scan of all keys.  As such, it
    /// potentially acquires (in turn) a read lock on all of the
    /// certificates' cells.
    pub fn cert_by_userid(&self, uid: &UserID) -> Option<Cert> {
        let mut r_cert = None;

        // XXX O(n)
        for cert in self.certs.read().iter() {
            if cert.userids().any(|u| u.userid() == uid) {
                r_cert = Some(cert.clone());
                break;
            }
        }

        r_cert
    }

    /// Retrieves a certificate from the keystore by (sub)key
    /// handle.
    ///
    /// # Locking
    ///
    /// This acquires a read lock on the keystore and, if a matching
    /// certificate is present, a read lock on the certificate's cell.
    pub fn cert_by_subkey_handle(&self, handle: &KeyHandle) -> Option<Cert> {
        match handle {
            KeyHandle::Fingerprint(fp) => self.cert_by_subkey_fp(fp),
            KeyHandle::KeyID(id) => self.cert_by_subkey_id(id),
        }
    }

    /// Retrieves a certificate from the keystore by (sub)key
    /// fingerprint.
    ///
    /// # Locking
    ///
    /// This acquires a read lock on the keystore and, if a matching
    /// certificate is present, a read lock on the certificate's cell.
    pub fn cert_by_subkey_fp(&self, fp: &Fingerprint) -> Option<Cert> {
        self.certs.read().by_fp(fp).nth(0).map(|c| c.clone())
    }

    /// Retrieves a certificate from the keystore by (sub)key
    /// keyid.
    ///
    /// # Locking
    ///
    /// This acquires a read lock on the keystore and, if a matching
    /// certificate is present, a read lock on the certificate's cell.
    pub fn cert_by_subkey_id(&self, id: &KeyID) -> Option<Cert> {
        let ks = self.certs.read();

         let r = ks.by_primary_id(id).nth(0)
            .or_else(|| ks.by_subkey_id(id).nth(0))
            .map(|c| c.clone());
        r
    }

    /// Retrieves a certificate from the keystore by (sub)key
    /// keygrip.
    ///
    /// # Locking
    ///
    /// This acquires a read lock on the keystore and, if a matching
    /// certificate is present, a read lock on the certificate's cell.
    pub fn cert_by_subkey_grip(&self, grip: &Keygrip) -> Option<Cert> {
        let ks = self.certs.read();

        let r = ks.by_primary_grip(grip).nth(0)
            .or_else(|| ks.by_subkey_grip(grip).nth(0))
            .map(|c| c.clone());
        r
    }
}

#[derive(Debug)]
pub enum RnpPasswordFor {
    AddSubkey,
    AddUserID,
    Sign,
    Decrypt,
    Unlock,
    Protect,
    Unprotect,
    DecryptSymmetric,
    EncryptSymmetric,
}

impl RnpPasswordFor {
    fn pgp_context(&self) -> *const c_char {
        use RnpPasswordFor::*;
        (match self {
            AddSubkey => b"add subkey\x00".as_ptr(),
            AddUserID => b"add userid\x00".as_ptr(),
            Sign => b"sign\x00".as_ptr(),
            Decrypt => b"decrypt\x00".as_ptr(),
            Unlock => b"unlock\x00".as_ptr(),
            Protect => b"protect\x00".as_ptr(),
            Unprotect => b"unprotect\x00".as_ptr(),
            DecryptSymmetric => b"decrypt (symmetric)\x00".as_ptr(),
            EncryptSymmetric => b"encrypt (symmetric)\x00".as_ptr(),
        }) as *const c_char
    }
}

impl RnpContext {
    pub fn request_password(&mut self,
                            key: Option<&RnpKey>,
                            reason: RnpPasswordFor) -> Option<Password> {
        rnp_function!(RnpContext::request_password, TRACE);
        t!("key = {:?}, reason = {:?}", key.map(|k| k.fingerprint()), reason);

        if let Some((f, cookie)) = self.password_cb {
            let mut buf: Protected = vec![0; 128].into();
            let len = buf.len();
            let ok = unsafe {
                f(self,
                  cookie,
                  key.map(|k| k as *const _).unwrap_or(std::ptr::null()),
                  reason.pgp_context(),
                  buf.as_mut().as_mut_ptr() as *mut c_char,
                  len)
            };

            if ! ok {
                t!("password_cb returned failure");
                return None;
            }

            if let Some(got) = buf.iter().position(|b| *b == 0) {
                t!("password_cb returned a password");
                Some(Password::from(&buf[..got]))
            } else {
                eprintln!("sequoia-octopus: given password exceeded buffer");
                None
            }
        } else {
            t!("No password_cb set");
            None
        }
    }

    /// Decrypts the given key, if necessary.
    pub fn decrypt_key_for(&mut self,
                           cert: Option<&Cert>,
                           mut key: Key<SecretParts, UnspecifiedRole>,
                           reason: RnpPasswordFor)
                           -> openpgp::Result<Key<SecretParts, UnspecifiedRole>>
    {
        rnp_function!(RnpContext::decrypt_key_for, TRACE);
        t!("cert = {:?}, key = {}, reason = {:?}",
           cert.map(|c| c.fingerprint()),
           key.fingerprint(),
           reason);

        if ! key.has_unencrypted_secret() {
            if let Some(k) = self.unlocked_keys.get(&key.fingerprint()) {
                // Use the unlocked key instead of prompting for a
                // password.
                t!("Found unlocked key in cache");
                return Ok(k.clone());
            }

            let rnp_key = if let Some(cert) = cert {
                RnpKey::new(self, key.into(), cert)
            } else {
                RnpKey::without_cert(self, key.into())
            };

            if let Some(pw) = self.request_password(Some(&rnp_key), reason) {
                key = Key::<UnspecifiedParts, UnspecifiedRole>::from(rnp_key)
                    .parts_into_secret()?;
                let k = key.clone();
                key.secret_mut().decrypt_in_place(&k, &pw)
                    .map_err(|_| Error::BadPassword)?;
                t!("Key decrypted successfully")
            } else {
                return Err(anyhow::anyhow!("no password given"));
            }
        } else {
            t!("Key is not encrypted, nothing to do");
        }
        Ok(key)
    }

    /// Returns false iff the key has not been unlocked.
    pub fn key_is_locked(&mut self, key: &Key<SecretParts, UnspecifiedRole>)
                         -> bool {
        ! self.unlocked_keys.contains_key(&key.fingerprint())
    }

    /// Locks the key.
    pub fn key_lock(&mut self, key: &Key<SecretParts, UnspecifiedRole>) {
        self.unlocked_keys.remove(&key.fingerprint());
    }

    /// Unlocks the key.
    ///
    /// If `password` is None, this function will ask for a password
    /// using the callback.
    pub fn key_unlock(&mut self,
                      mut key: Key<SecretParts, UnspecifiedRole>,
                      password: Option<Password>)
                      -> openpgp::Result<()>
    {
        rnp_function!(RnpContext::key_unlock, crate::TRACE);
        t!("key: {}; password: {:?}",
           key.fingerprint(),
           if password.is_some() { "provided" } else { "None" });

        if ! key.has_unencrypted_secret() {
            if let Some(pw) = password
                .or_else(|| self.request_password(
                    None, RnpPasswordFor::Unlock))
            {
                let k = key.clone();
                key.secret_mut().decrypt_in_place(&k, &pw)
                    .map_err(|_| Error::BadPassword)?;
            } else {
                return Err(anyhow::anyhow!("no password given"));
            }
        }

        assert!(key.has_unencrypted_secret());
        self.unlocked_keys.insert(key.fingerprint(), key);
        Ok(())
    }

    /// Returns a reference to the unlocked key in the cache, if it
    /// exists.
    pub fn key_unlocked_ref(&self,
                            key: &Key<UnspecifiedParts, UnspecifiedRole>)
                            -> Option<&Key<SecretParts, UnspecifiedRole>>
    {
        self.unlocked_keys.get(&key.fingerprint())
    }
}

#[no_mangle] pub unsafe extern "C"
fn rnp_load_keys(ctx: *mut RnpContext,
                 format: *const c_char,
                 input: *mut RnpInput,
                 flags: RnpLoadSaveFlags)
                 -> RnpResult {
    rnp_function!(rnp_load_keys, TRACE);

    let ctx = assert_ptr_mut!(ctx);
    let format = assert_str!(format);
    let input = assert_ptr_mut!(input);
    arg!(flags);

    static BANNER_SHOWN: atomic::AtomicBool = atomic::AtomicBool::new(false);
    if ! BANNER_SHOWN.load(atomic::Ordering::Relaxed) {
        warn!("Your Thunderbird is using Sequoia's Octopus, version {}\n\
               (sequoia-openpgp: {}).  For details, and to report issues please\n\
               see https://gitlab.com/sequoia-pgp/sequoia-octopus-librnp .",
              env!("CARGO_PKG_VERSION"), sequoia_openpgp::VERSION);
        if let Some(path) = crate::tbprofile::TBProfile::path() {
            warn!("Your Thunderbird profile appears to be: {:?}", path);
        } else {
            warn!("Failed to detect your Thunderbird profile.  Please report\n\
                   open an issue at https://gitlab.com/sequoia-pgp/sequoia-octopus-librnp .");
        }
        BANNER_SHOWN.store(true, atomic::Ordering::Relaxed);
    }

    if format != "GPG" {
        rnp_return_status!(RNP_ERROR_BAD_FORMAT);
    }

    let input_size = input.size();

    match flags {
        RNP_LOAD_SAVE_PUBLIC_KEYS => {
            if let Ok(input_size) = input_size {
                if let Some(profile) = tbprofile::TBProfile::path() {
                    let pubring = profile.join("pubring.gpg");
                    if let Ok(pubring) = std::fs::metadata(pubring) {
                        let file_size = pubring.len();
                        t!("input is {} bytes, pubring.gpg is {} bytes.",
                           input_size, file_size);
                        if input_size == file_size {
                            t!("Looks like a match.  Periodically flushing \
                                the keystore to disk.");
                            rnp_try_or!((*ctx).certs.set_directory(profile),
                                        RNP_ERROR_GENERIC);
                        } else {
                            t!("pubring.gpg does not match input.  \
                                Conservatively disabling flushing the \
                                keystore to disk.");
                        }
                    }
                }
            }

            // Also load GPG's public key database.
            if let Err(err) = (*ctx).certs.load_gpg_keyring_in_background(
                (*ctx).policy.clone())
            {
                warn!("Import gpg's keyring: {}", err);
            }

            let policy = ctx.policy().clone();
            rnp_try_or!(ctx.certs.start_parcimonie(policy), RNP_ERROR_GENERIC);
        }
        RNP_LOAD_SAVE_SECRET_KEYS => (),
        f => {
            warn!("sequoia-octopus: unexpected flags to rnp_load_keys: {:x}",
                  f);
            rnp_return_status!(RNP_ERROR_BAD_PARAMETERS);
        },
    }

    use std::io::Read;
    let mut data = Vec::new();
    if let Err(err) = input.read_to_end(&mut data)
    {
        warn!("sequoia-octopus: Error reading input: {}", err);
        rnp_return_status!(RNP_ERROR_GENERIC);
    }

    let policy = (*ctx).policy.clone();
    if let Err(err) = (*ctx).certs.load_keyring_in_background(
        data, flags == RNP_LOAD_SAVE_SECRET_KEYS, policy)
    {
        warn!("sequoia-octopus: Error reading certs: {}", err);
        rnp_return_status!(RNP_ERROR_GENERIC);
    }

    rnp_success!()
}

#[no_mangle] pub unsafe extern "C"
fn rnp_save_keys(ctx: *mut RnpContext,
                 format: *const c_char,
                 output: *mut RnpOutput,
                 flags: RnpLoadSaveFlags)
                 -> RnpResult {
    rnp_function!(rnp_save_keys, TRACE);
    let ctx = assert_ptr_mut!(ctx);
    let format = assert_str!(format);
    let output = assert_ptr_mut!(output);
    if format != "GPG" {
        rnp_return_status!(RNP_ERROR_BAD_FORMAT);
    }

    let mut r = Ok(());
    let mut count = 0;
    match flags {
        RNP_LOAD_SAVE_PUBLIC_KEYS => {
            let _ = (*ctx).certs.block_on_load();
            for cert in (*ctx).certs.read().to_save().filter(|cert| ! cert.is_tsk()) {
                if let Err(err) = cert.serialize(output) {
                    r = Err(err);
                    break;
                } else {
                    count += 1;
                }
            }
        },
        RNP_LOAD_SAVE_SECRET_KEYS => {
            let _ = (*ctx).certs.block_on_load();
            for cert in (*ctx).certs.read().to_save().filter(|cert| cert.is_tsk()) {
                if let Err(err) = cert.as_tsk().serialize(output) {
                    r = Err(err);
                    break;
                } else {
                    count += 1;
                }
            }
        }
        f => {
            warn!("unexpected flags to rnp_save_keys: {:x}", f);
            rnp_return_status!(RNP_ERROR_BAD_PARAMETERS);
        },
    };

    if count == 0 {
        // We didn't write any bytes.  Currently, Thunderbird will not
        // invoke rnp_load_keys if a keyring is a zero-sized file.  To
        // avoid that, i.e. make sure that rnp_load_keys is invoked,
        // we write a placeholder there.  See the comments in
        // rnp_ffi_create for details.
        if let Err(err) = openpgp::Packet::Marker(Default::default())
            .serialize(output)
        {
            if r.is_ok() {
                r = Err(err);
            }
        }
    }

    rnp_return_status!(if let Err(err) = r {
        warn!("failed saving keys: {}", err);
        RNP_ERROR_GENERIC
    } else {
        RNP_SUCCESS
    })
}

#[no_mangle] pub unsafe extern "C"
fn rnp_get_public_key_count(ctx: *mut RnpContext,
                            count: *mut size_t)
                            -> RnpResult {
    rnp_function!(rnp_get_public_key_count, crate::TRACE);
    let ctx = assert_ptr_mut!(ctx);
    let count = assert_ptr_mut!(count);

    // We load the keyrings in the background.  But, once TB tries to
    // get the number of certs, we have to wait on that process.
    let _ = ctx.certs.block_on_load();

    // Make sure the agent listing is up to date.
    let mut ks = ctx.certs.write();
    ks.key_on_agent_hard(&Fingerprint::V4(Default::default()));
    drop(ks);

    let ks = ctx.certs.read();
    *count = ks.iter().filter(|cert| {
        if cert.is_tsk() {
            false
        } else if ks.key_on_agent(&cert.fingerprint()).0 {
            false
        } else {
            true
        }
    }).count();
    t!("-> {}", *count);
    rnp_success!()
}

#[no_mangle] pub unsafe extern "C"
fn rnp_get_secret_key_count(ctx: *mut RnpContext,
                            count: *mut size_t)
                            -> RnpResult {
    rnp_function!(rnp_get_secret_key_count, TRACE);
    let ctx = assert_ptr_mut!(ctx);
    let count = assert_ptr_mut!(count);

    // We load the keyrings in the background.  But, once TB tries to
    // get the number of certs, we have to wait on that process.
    let _ = ctx.certs.block_on_load();

    // Make sure the agent listing is up to date.
    let mut ks = ctx.certs.write();
    ks.key_on_agent_hard(&Fingerprint::V4(Default::default()));
    drop(ks);

    let ks = ctx.certs.read();
    *count = ks.iter().filter(|cert| {
        if cert.is_tsk() {
            true
        } else {
            let fpr = &cert.fingerprint();
            ks.key_on_agent(fpr).0
        }
    }).count();
    t!("-> {}", *count);
    rnp_success!()
}
