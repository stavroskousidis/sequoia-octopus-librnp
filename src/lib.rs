use std::{
    collections::{
        HashMap,
    },
    ffi::{
        CStr,
    },
    cell::{
        RefMut,
    },
};
use libc::{
    c_char,
    c_int,
    c_void,
    size_t,
};

use sequoia_openpgp as openpgp;
use openpgp::{
    Fingerprint,
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
        key::{SecretParts, UnspecifiedRole},
        UserID,
    },
    policy::{
        StandardPolicy,
    },
    serialize::Serialize,
};

/// Controls tracing.
const TRACE: bool = cfg!(debug_assertions);

macro_rules! stub {
    ($s: ident) => {
        #[no_mangle] pub extern "C"
        fn $s() -> RnpResult {
            eprintln!("\nSTUB: {}\n", stringify!($s));
            RNP_ERROR_NOT_IMPLEMENTED
        }
    };
}

// XXX: This is a copy of sequoia/ipc/src/keygrip.rs.
mod keygrip;
use keygrip::*;

mod keystore;
use keystore::Keystore;

mod buffer;
use buffer::*;

#[allow(dead_code)]
#[macro_use]
mod error;
use error::*;
#[allow(dead_code)]
mod flags;
use flags::*;
#[allow(dead_code)]
mod io;
use io::*;
#[allow(dead_code)]
mod utils;
use utils::*;
#[allow(dead_code)]
mod conversions;
use conversions::*;

mod version;
#[allow(dead_code)]
mod op_verify;
#[allow(dead_code)]
mod op_encrypt;
#[allow(dead_code)]
mod op_sign;
#[allow(dead_code)]
mod op_generate;
#[allow(dead_code)]
mod signature;
use signature::RnpSignature;
#[allow(dead_code)]
mod key;
use key::RnpKey;
#[allow(dead_code)]
mod iter;
#[allow(dead_code)]
mod userid;
use userid::RnpUserID;
#[allow(dead_code)]
mod import;
mod keyring;
use keyring::parse_keyring;
// The gpg module is copied from OpenPGP CA.  We don't want to modify
// it.
#[allow(dead_code)]
mod gpg;

mod tbprofile;
mod wot;

pub const P: &StandardPolicy = &StandardPolicy::new();

#[derive(Default)]
pub struct RnpContext {
    certs: Keystore,
    keys: Keystore,
    unlocked_keys: HashMap<Fingerprint, Key<SecretParts, UnspecifiedRole>>,
    password_cb: Option<(RnpPasswordCb, *mut c_void)>,
}

type RnpPasswordCb = unsafe extern fn(*mut RnpContext,
                                      *mut c_void,
                                      *const Cert,
                                      *const c_char,
                                      *mut c_char,
                                      size_t) -> bool;

#[no_mangle] pub unsafe extern "C"
fn rnp_ffi_create(ctx: *mut *mut RnpContext,
                  pub_fmt: *const c_char,
                  sec_fmt: *const c_char)
                  -> RnpResult
{
    assert_ptr!(ctx);
    assert_ptr!(pub_fmt);
    assert_ptr!(sec_fmt);
    if CStr::from_ptr(pub_fmt).to_bytes() != b"GPG"
        || CStr::from_ptr(sec_fmt).to_bytes() != b"GPG"
    {
        return RNP_ERROR_BAD_FORMAT;
    }

    *ctx = Box::into_raw(Box::new(RnpContext::default()));
    RNP_SUCCESS
}

#[no_mangle] pub unsafe extern "C"
fn rnp_ffi_destroy(ctx: *mut RnpContext) -> RnpResult {
    if ! ctx.is_null() {
        drop(Box::from_raw(ctx));
    }
    RNP_SUCCESS
}

#[no_mangle] pub unsafe extern "C"
fn rnp_ffi_set_log_fd(ctx: *mut RnpContext, _fd: c_int) -> RnpResult {
    assert_ptr!(ctx);
    RNP_SUCCESS
}

#[no_mangle] pub unsafe extern "C"
fn rnp_ffi_set_pass_provider(ctx: *mut RnpContext,
                             cb: RnpPasswordCb,
                             cookie: *mut c_void)
                             -> RnpResult {
    assert_ptr!(ctx);
    (*ctx).password_cb = Some((cb, cookie));
    RNP_SUCCESS
}

impl RnpContext {
    /// Inserts a cert into the certring.
    pub fn insert_cert(&mut self, cert: Cert) {
        self.certs.insert(cert);
    }

    /// Inserts a cert from an external source into the certring.
    ///
    /// certs from external sources won't be serialized.
    pub fn insert_cert_external(&mut self, cert: Cert) {
        self.certs.insert_external(cert);
    }

    /// Inserts a key into the keyring.
    pub fn insert_key(&mut self, key: Cert) {
        self.keys.insert(key);
    }

    /// Retrieves a certificate from both stores by userid.
    ///
    /// RNP searches both the certring and the keyring, and the
    /// keyhandle can thus refer to two certificates, potentially
    /// different versions of the same, or even different
    /// certificates!  We also search both rings, but merge the
    /// results.  If the merge fails, we conservatively fail the
    /// lookup.
    pub fn cert(&self, by: &RnpIdentifier) -> Option<Cert> {
        rnp_function!(RnpContext::cert, TRACE);

        use RnpIdentifier::*;
        let (key, cert) = match by {
            UserID(id) => self.cert_by_userid(id),
            KeyID(id) => self.cert_by_subkey_id(id),
            Fingerprint(fp) => self.cert_by_subkey_fp(fp),
            Keygrip(grip) => self.cert_by_subkey_grip(grip),
        };

        t!("Lookup by {:?} returned cert {:?} and key {:?}",
           by,
           cert.as_ref().map(|c| c.fingerprint()),
           key.as_ref().map(|c| c.fingerprint()));

        match (key, cert) {
            (None, None) => None,
            (Some(key), None) => Some(key),
            (None, Some(cert)) => Some(cert),
            (Some(key), Some(cert)) => match key.merge_public(cert) {
                Ok(cert) => Some(cert),
                Err(e) => {
                    warn!("Error merging certificates: {}", e);
                    None
                },
            },
        }
    }

    /// Retrieves a certificate from both stores by userid.
    ///
    /// XXX: This is super dodgy.  rnp.h says "Note: only valid
    /// userids are checked while searching by userid." but it is not
    /// clear what that means.
    ///
    /// XXX: I think it would be better to fail these lookups.  Are
    /// they used by TB?
    pub fn cert_by_userid(&self, uid: &UserID)
                               -> (Option<Cert>, Option<Cert>) {
        let mut r_key = None;
        let mut r_cert = None;

        // XXX O(n)
        for cert in self.keys.iter() {
            if cert.userids().any(|u| u.userid() == uid) {
                r_key = Some(cert.clone());
                break;
            }
        }
        for cert in self.certs.iter() {
            if cert.userids().any(|u| u.userid() == uid) {
                r_cert = Some(cert.clone());
                break;
            }
        }

        (r_key, r_cert)
    }

    /// Retrieves a certificate from both stores by (sub)key
    /// fingerprint.
    pub fn cert_by_subkey_fp(&self, fp: &Fingerprint)
                               -> (Option<Cert>, Option<Cert>) {
        (self.keys.by_primary_fp(fp)
         .or_else(|| self.keys.by_subkey_fp(fp))
         .map(|c| c.clone()),
         self.certs.by_primary_fp(fp)
         .or_else(|| self.certs.by_subkey_fp(fp))
         .map(|c| c.clone()))
    }

    /// Retrieves a certificate from both stores by (sub)key
    /// keyid.
    pub fn cert_by_subkey_id(&self, id: &KeyID)
                               -> (Option<Cert>, Option<Cert>) {
        (self.keys.by_primary_id(id)
         .or_else(|| self.keys.by_subkey_id(id))
         .map(|c| c.clone()),
         self.certs.by_primary_id(id)
         .or_else(|| self.certs.by_subkey_id(id))
         .map(|c| c.clone()))
    }

    /// Retrieves a certificate from both stores by (sub)key
    /// keygrip.
    pub fn cert_by_subkey_grip(&self, grip: &Keygrip)
                               -> (Option<Cert>, Option<Cert>) {
        (self.keys.by_primary_grip(grip)
         .or_else(|| self.keys.by_subkey_grip(grip))
         .map(|c| c.clone()),
         self.certs.by_primary_grip(grip)
         .or_else(|| self.certs.by_subkey_grip(grip))
         .map(|c| c.clone()))
    }

    /// Retrieves a key from the keyring by (sub)key fingerprint.
    pub fn key_mut_by_fp(&mut self, fp: &Fingerprint) -> Option<RefMut<Cert>> {
        self.keys.by_primary_fp_mut(fp)
            .or(self.keys.by_subkey_fp_mut(fp))
    }

    /// Retrieves a cert from the certring by (sub)key fingerprint.
    pub fn cert_mut_by_fp(&mut self, fp: &Fingerprint) -> Option<RefMut<Cert>> {
        self.certs.by_primary_fp_mut(fp)
            .or(self.certs.by_subkey_fp_mut(fp))
    }
}

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
                            cert: Option<&Cert>,
                            reason: RnpPasswordFor) -> Option<Password> {
        if let Some((f, cookie)) = self.password_cb {
            let mut buf: Protected = vec![0; 128].into();
            let len = buf.len();
            let ok = unsafe {
                f(self,
                  cookie,
                  cert.map(|c| c as *const _).unwrap_or(std::ptr::null()),
                  reason.pgp_context(),
                  buf.as_mut().as_mut_ptr() as *mut c_char,
                  len)
            };

            if ! ok {
                return None;
            }

            if let Some(got) = buf.iter().position(|b| *b == 0) {
                Some(Password::from(&buf[..got]))
            } else {
                eprintln!("sequoia-octopus: given password exceeded buffer");
                None
            }
        } else {
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
        if ! key.has_unencrypted_secret() {
            if let Some(k) = self.unlocked_keys.get(&key.fingerprint()) {
                // Use the unlocked key instead of prompting for a
                // password.
                return Ok(k.clone());
            }

            let pk_algo = key.pk_algo();
            if let Some(pw) = self.request_password(cert, reason) {
                key.secret_mut().decrypt_in_place(pk_algo, &pw)?;
            } else {
                return Err(anyhow::anyhow!("no password given"));
            }
        }
        Ok(key)
    }

    /// Returns false iff the key has not been unlocked.
    pub fn key_is_locked(&mut self, key: &Key<SecretParts, UnspecifiedRole>)
                         -> bool {
        self.unlocked_keys.contains_key(&key.fingerprint())
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
        if ! key.has_unencrypted_secret() {
            let pk_algo = key.pk_algo();
            if let Some(pw) = password
                .or_else(|| self.request_password(
                    None, RnpPasswordFor::Unlock))
            {
                key.secret_mut().decrypt_in_place(pk_algo, &pw)?;
            } else {
                return Err(anyhow::anyhow!("no password given"));
            }
        }

        self.unlocked_keys.insert(key.fingerprint(), key);
        Ok(())
    }
}

static mut TBPROFILE: Option<tbprofile::TBProfile> = None;

fn load_gpg_keyring(ctx: &mut RnpContext,
                    gpg_ctx: Option<&gpg::Ctx>)
    -> openpgp::Result<()>
{
    let gpg_ctx_;
    let gpg_ctx = if let Some(gpg_ctx) = gpg_ctx {
        gpg_ctx
    } else {
        gpg_ctx_ = Some(gpg::Ctx::new()?);
        &gpg_ctx_.as_ref().unwrap()
    };
    let export = gpg::export(&gpg_ctx, None)?;

    for cert in parse_keyring(std::io::Cursor::new(export))? {
        match cert {
            Ok(c) =>
                (*ctx).insert_cert_external(c),
            Err(e) => {
                // We definitely don't want to error out when
                // importing stuff from gpg.  So, warn, but don't
                // stop.
                warn!("sequoia-octopus: Error parsing cert: {}", e);
            },
        }
    }

    Ok(())
}

#[no_mangle] pub unsafe extern "C"
fn rnp_load_keys(ctx: *mut RnpContext,
                 format: *const c_char,
                 input: *mut RnpInput,
                 flags: RnpLoadSaveFlags)
                 -> RnpResult {
    assert_ptr!(ctx);
    assert_ptr!(format);
    assert_ptr!(input);

    if TBPROFILE.is_none() {
        match tbprofile::TBProfile::load() {
            Ok(p) => TBPROFILE = Some(p),
            Err(err) => eprintln!("sequoia-octopus: \
                                   Loading TB Profile: {}", err),
        }
    }

    if CStr::from_ptr(format).to_bytes() != b"GPG" {
        return RNP_ERROR_BAD_FORMAT;
    }

    let input = &mut *input;
    let certs = parse_keyring(input);

    let certs = match certs {
        Ok(c) => c,
        Err(e) => {
            eprintln!("sequoia-octopus: Error reading certs: {}", e);
            return RNP_ERROR_GENERIC;
        },
    };

    let mut acc = Vec::new();
    for cert in certs {
        match cert {
            Ok(c) => acc.push(c),
            Err(e) => {
                // XXX: How to deal with partial loads?
                eprintln!("sequoia-octopus: Error parsing cert: {}", e);
                return RNP_ERROR_GENERIC;
            },
        }
    }

    match flags {
        RNP_LOAD_SAVE_PUBLIC_KEYS =>
            for cert in acc {
                (*ctx).insert_cert(cert);
            },
        RNP_LOAD_SAVE_SECRET_KEYS =>
            for key in acc {
                (*ctx).insert_key(key);
            },
        f => {
            eprintln!("sequoia-octopus: unexpected flags to rnp_load_keys: \
                       {:x}", f);
            return RNP_ERROR_BAD_PARAMETERS;
        },
    }

    if flags == RNP_LOAD_SAVE_PUBLIC_KEYS {
        // Also load GPG's public key database.
        match gpg::Ctx::new() {
            Ok(gpg_ctx) => {
                if let Err(err) = load_gpg_keyring(&mut *ctx, Some(&gpg_ctx)) {
                    warn!("Import gpg's keyring: {}", err);
                }

                if let Some(p) = TBPROFILE.as_ref() {
                    if let Err(err) = wot::update_acceptance(&gpg_ctx, p) {
                        warn!("Updating web of trust: {}", err);
                    }
                }
            }
            Err(err) => {
                warn!("Creating a gpg context: {}", err);
            }
        }
    }

    RNP_SUCCESS
}

#[no_mangle] pub unsafe extern "C"
fn rnp_save_keys(ctx: *mut RnpContext,
                 format: *const c_char,
                 output: *mut RnpOutput,
                 flags: RnpLoadSaveFlags)
                 -> RnpResult {
    assert_ptr!(ctx);
    assert_ptr!(format);
    assert_ptr!(output);
    if CStr::from_ptr(format).to_bytes() != b"GPG" {
        return RNP_ERROR_BAD_FORMAT;
    }

    let output = &mut *output;
    let certs = match flags {
        RNP_LOAD_SAVE_PUBLIC_KEYS => &(*ctx).certs,
        RNP_LOAD_SAVE_SECRET_KEYS => &(*ctx).keys,
        f => {
            warn!("unexpected flags to rnp_load_keys: {:x}", f);
            return RNP_ERROR_BAD_PARAMETERS;
        },
    };

    if let Err(e) = (|| -> openpgp::Result<()> {
        for cert in certs.to_save() {
            if flags & RNP_LOAD_SAVE_SECRET_KEYS > 0 {
                cert.as_tsk().serialize(output)?;
            } else {
                cert.serialize(output)?;
            }
        }
        Ok(())
    })() {
        warn!("failed saving keys: {}", e);
        RNP_ERROR_GENERIC
    } else {
        RNP_SUCCESS
    }
}

#[no_mangle] pub unsafe extern "C"
fn rnp_get_public_key_count(ctx: *mut RnpContext,
                            count: *mut size_t)
                            -> RnpResult {
    assert_ptr!(ctx);
    *count = (*ctx).certs.len();
    RNP_SUCCESS
}

#[no_mangle] pub unsafe extern "C"
fn rnp_get_secret_key_count(ctx: *mut RnpContext,
                            count: *mut size_t)
                            -> RnpResult {
    assert_ptr!(ctx);
    *count = (*ctx).keys.len();
    RNP_SUCCESS
}

// These are bound in RNPlib.jsm but not actually used.
macro_rules! unused {
    ($s: ident) => {
        #[no_mangle] pub extern "C"
        fn $s() -> RnpResult {
            warn!("previously unused function is used: {}", stringify!($s));
            RNP_ERROR_NOT_IMPLEMENTED
        }
    };
}

unused!(rnp_guess_contents);
unused!(rnp_decrypt);
unused!(rnp_symenc_get_aead_alg);
unused!(rnp_symenc_get_cipher);
unused!(rnp_symenc_get_hash_alg);
unused!(rnp_symenc_get_s2k_iterations);
unused!(rnp_symenc_get_s2k_type);
