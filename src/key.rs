use std::{
    ffi::{
        CStr,
    },
    io,
    time::{
        Duration,
        UNIX_EPOCH,
    },
};
use libc::{
    c_char,
    size_t,
};

use sequoia_openpgp as openpgp;
use openpgp::{
    Fingerprint,
    cert::{
        Cert,
        CertRevocationBuilder,
        SubkeyRevocationBuilder,
        amalgamation::ValidAmalgamation,
    },
    packet::{
        Packet,
        UserID,
        Key,
        key::{
            UnspecifiedParts,
            UnspecifiedRole,
        },
    },
    serialize::Serialize,
    types::{
        HashAlgorithm,
        ReasonForRevocation,
    },
};

use crate::{
    P,
    RnpResult,
    RnpContext,
    RnpOutput,
    Keygrip,
    RnpUserID,
    RnpPasswordFor,
    str_to_rnp_buffer,
    c_str_to_rnp_buffer,
    c_str_to_rnp_buffer_lossy,
    cstr_to_str,
    flags::*,
    conversions::*,
    error::*,
};

#[derive(Debug)]
pub struct RnpKey {
    ctx: *mut RnpContext,
    key: Key<UnspecifiedParts, UnspecifiedRole>,
    cert: Option<Cert>,
}

impl RnpKey {
    pub fn new(ctx: *mut RnpContext,
               key: Key<UnspecifiedParts, UnspecifiedRole>) -> Self {
        RnpKey {
            ctx,
            key,
            cert: None,
        }
    }

    pub fn with_cert(ctx: *mut RnpContext,
                     key: Key<UnspecifiedParts, UnspecifiedRole>,
                     cert: Cert) -> Self {
        RnpKey {
            ctx,
            key,
            cert: Some(cert),
        }
    }

    fn cert(&mut self) -> Option<&Cert> {
        if self.cert.is_none() {
            if let Some(cert) = unsafe {
                (*self.ctx).cert(&RnpIdentifier::Fingerprint(self.key.fingerprint()))
            } {
                self.cert = Some(cert);
            }
        }

        self.cert.as_ref()
    }
}

impl std::ops::Deref for RnpKey {
    type Target = Key<UnspecifiedParts, UnspecifiedRole>;

    fn deref(&self) -> &Self::Target {
        &self.key
    }
}

#[no_mangle] pub unsafe extern "C"
fn rnp_locate_key(ctx: *mut RnpContext,
                  identifier_type: *const c_char,
                  identifier: *const c_char,
                  key: *mut *mut RnpKey)
                  -> RnpResult {
    rnp_function!(rnp_locate_key, crate::TRACE);

    assert_ptr!(ctx);
    assert_ptr!(identifier_type);
    assert_ptr!(identifier);
    assert_ptr!(key);

    let id = rnp_try!(
        rnp_try!(RnpIdentifierType::from_rnp_id(identifier_type))
            .with_identifier(identifier));
    t!("Locating key by {:?}", id);

    if let Some(cert) = (*ctx).cert(&id) {
        use RnpIdentifier::*;
        let k = match id {
            UserID(_) => cert.primary_key().key().clone()
                .role_into_unspecified(),
            KeyID(id) => cert.keys().key_handle(id)
                .nth(0).expect("must exist in cert").key().clone(),
            Fingerprint(fp) => cert.keys().key_handle(fp)
                .nth(0).expect("must exist in cert").key().clone(),
            Keygrip(grip) => cert.keys().filter(|k| {
                crate::Keygrip::of(k.mpis()).map(|g| g == grip).unwrap_or(false)
            })
                .nth(0).expect("must exist in cert").key().clone(),
        }.parts_into_unspecified();

        *key = Box::into_raw(Box::new(RnpKey {
            ctx,
            key: k,
            cert: Some(cert),
        }));
    } else {
        *key = std::ptr::null_mut();
    }
    RNP_SUCCESS
}

#[no_mangle] pub unsafe extern "C"
fn rnp_key_handle_destroy(key: *mut RnpKey)
                          -> RnpResult {
    if ! key.is_null() {
        drop(Box::from_raw(key));
    }
    RNP_SUCCESS
}

#[no_mangle] pub unsafe extern "C"
fn rnp_key_get_keyid(key: *const RnpKey,
                     keyid: *mut *mut c_char)
                     -> RnpResult {
    assert_ptr!(key);
    assert_ptr!(keyid);

    *keyid = str_to_rnp_buffer(format!("{:X}", (*key).keyid()));
    RNP_SUCCESS
}

#[no_mangle] pub unsafe extern "C"
fn rnp_key_get_fprint(key: *const RnpKey,
                     fprint: *mut *mut c_char)
                     -> RnpResult {
    assert_ptr!(key);
    assert_ptr!(fprint);

    *fprint = str_to_rnp_buffer(format!("{:X}", (*key).fingerprint()));
    RNP_SUCCESS
}

#[no_mangle] pub unsafe extern "C"
fn rnp_key_get_alg(key: *const RnpKey,
                   alg: *mut *mut c_char)
                   -> RnpResult {
    assert_ptr!(key);
    assert_ptr!(alg);

    *alg = str_to_rnp_buffer((*key).pk_algo().to_rnp_id());
    RNP_SUCCESS
}

impl RnpKey {
    fn is_primary(&mut self) -> Result<bool> {
        if let Some(cert) = self.cert() {
            Ok(cert.fingerprint() == self.fingerprint())
        } else {
            Err(RNP_ERROR_NO_SUITABLE_KEY)
        }
    }
}

// XXX: A key can be both primary and subkey at the same time in
// different certs, and what this function returns is not clearly
// defined.  The result depends on the order the keys are looked up.
#[no_mangle] pub unsafe extern "C"
fn rnp_key_is_primary(key: *mut RnpKey,
                      result: *mut bool)
                      -> RnpResult {
    assert_ptr!(key);
    assert_ptr!(result);
    *result = rnp_try!((*key).is_primary());
    RNP_SUCCESS
}

// XXX: A key can be both primary and subkey at the same time in
// different certs, and what this function returns is not clearly
// defined.  The result depends on the order the keys are looked up.
#[no_mangle] pub unsafe extern "C"
fn rnp_key_is_sub(key: *mut RnpKey,
                  result: *mut bool)
                  -> RnpResult {
    assert_ptr!(key);
    assert_ptr!(result);
    *result = ! rnp_try!((*key).is_primary());
    RNP_SUCCESS
}

#[no_mangle] pub unsafe extern "C"
fn rnp_key_get_grip(key: *const RnpKey,
                    grip: *mut *mut c_char)
                   -> RnpResult {
    assert_ptr!(key);
    assert_ptr!(grip);

    if let Ok(keygrip) = Keygrip::of((*key).mpis()) {
        *grip = str_to_rnp_buffer(keygrip.to_string());
        RNP_SUCCESS
    } else {
        RNP_ERROR_GENERIC
    }
}

#[no_mangle] pub unsafe extern "C"
fn rnp_key_get_primary_grip(key: *mut RnpKey,
                            grip: *mut *mut c_char)
                            -> RnpResult {
    assert_ptr!(key);
    assert_ptr!(grip);

    if let Some(cert) = (*key).cert() {
        if let Ok(keygrip) = Keygrip::of(cert.primary_key().mpis()) {
            *grip = str_to_rnp_buffer(keygrip.to_string());
            RNP_SUCCESS
        } else {
            RNP_ERROR_GENERIC
        }
    } else {
        RNP_ERROR_NO_SUITABLE_KEY
    }
}

/// XXX: This is a really odd function.  How can we not have the
/// public key?
#[no_mangle] pub unsafe extern "C"
fn rnp_key_have_public(key: *const RnpKey,
                       result: *mut bool)
                       -> RnpResult {
    assert_ptr!(key);
    assert_ptr!(result);

    *result = true;
    RNP_SUCCESS
}

#[no_mangle] pub unsafe extern "C"
fn rnp_key_have_secret(key: *const RnpKey,
                       result: *mut bool)
                       -> RnpResult {
    assert_ptr!(key);
    assert_ptr!(result);

    *result = (*key).has_secret();
    RNP_SUCCESS
}

#[no_mangle] pub unsafe extern "C"
fn rnp_key_get_bits(key: *const RnpKey,
                    bits: *mut u32)
                    -> RnpResult {
    assert_ptr!(key);
    assert_ptr!(bits);

    if let Some(b) = (*key).mpis().bits() {
        *bits = b as u32;
        RNP_SUCCESS
    } else {
        RNP_ERROR_NO_SUITABLE_KEY
    }
}

#[no_mangle] pub unsafe extern "C"
fn rnp_key_get_creation(key: *const RnpKey,
                        creation: *mut u32)
                    -> RnpResult {
    assert_ptr!(key);
    assert_ptr!(creation);

    *creation =
        (*key).creation_time().duration_since(UNIX_EPOCH)
        .expect("creation time is representable as epoch")
        .as_secs() as u32;
    RNP_SUCCESS
}

#[no_mangle] pub unsafe extern "C"
fn rnp_key_get_expiration(key: *mut RnpKey,
                          expiration: *mut u32)
                          -> RnpResult {
    rnp_function!(rnp_key_get_expiration, crate::TRACE);
    let key = assert_ptr_mut!(key);
    assert_ptr!(expiration);
    let fp = key.fingerprint();

    if let Some(cert) = key.cert()
        .and_then(|c| c.with_policy(P, None).ok())
    {
        let vka = cert
            .keys().key_handle(fp)
            .nth(0).expect("subkey must exist");

        *expiration =
            vka.key_validity_period().map(|d| d.as_secs() as u32)
            .unwrap_or(0); // 0 is special and means does not expire.
    } else {
        // Not valid under the policy.  Treat as expired.
        t!("The (sub)key {} is not valid under the standard policy, \
            treating as expired.", fp);

        // Expired immediately.  0 is special and means does not expire.
        *expiration = 1;
    }
    RNP_SUCCESS
}

#[no_mangle] pub unsafe extern "C"
fn rnp_key_get_primary_uid(key: *mut RnpKey,
                           uid: *mut *mut c_char)
                           -> RnpResult {
    assert_ptr!(key);
    assert_ptr!(uid);

    // If we fail to find a primary userid using the standard policy,
    // we fall back to using a null policy.  This value is only used
    // for displaying purposes, and falling back seems reasonable to
    // me.
    use openpgp::policy::{Policy, NullPolicy};
    const NP: &dyn Policy = &NullPolicy::new();

    if let Some(cert) = (*key).cert()
        .and_then(|c| c.with_policy(P, None).ok()
                  .or_else(|| c.with_policy(NP, None).ok()))
    {
        if let Ok(u) = cert.primary_userid() {
            *uid = c_str_to_rnp_buffer_lossy(u.value());
            RNP_SUCCESS
        } else {
            RNP_ERROR_GENERIC
        }
    } else {
        RNP_ERROR_NO_SUITABLE_KEY
    }
}

// XXX: should we only consider valid userids, or all of them?
#[no_mangle] pub unsafe extern "C"
fn rnp_key_get_uid_at(key: *mut RnpKey,
                      idx: size_t,
                      uid: *mut *mut c_char)
                      -> RnpResult {
    assert_ptr!(key);
    assert_ptr!(uid);

    if let Some(cert) = (*key).cert() {
        if let Some(u) = cert.userids().nth(idx) {
            if let Some(ptr) = c_str_to_rnp_buffer(u.value()) {
                *uid = ptr;
                RNP_SUCCESS
            } else {
                RNP_ERROR_GENERIC
            }
        } else {
            RNP_ERROR_BAD_PARAMETERS
        }
    } else {
        RNP_ERROR_NO_SUITABLE_KEY
    }
}

// XXX: should we only consider valid userids, or all of them?
#[no_mangle] pub unsafe extern "C"
fn rnp_key_get_uid_handle_at(key: *mut RnpKey,
                             idx: size_t,
                             uid: *mut *mut RnpUserID)
                             -> RnpResult {
    assert_ptr!(key);
    assert_ptr!(uid);

    if let Some(cert) = (*key).cert() {
        if let Some(u) = cert.userids().nth(idx) {
            if let Some(u) = RnpUserID::new((*key).ctx,
                                            u.userid().clone(),
                                            cert.clone()) {
                *uid = Box::into_raw(Box::new(u));
                RNP_SUCCESS
            } else {
                RNP_ERROR_GENERIC
            }
        } else {
            RNP_ERROR_BAD_PARAMETERS
        }
    } else {
        RNP_ERROR_NO_SUITABLE_KEY
    }
}

// XXX: should we only consider valid userids, or all of them?
#[no_mangle] pub unsafe extern "C"
fn rnp_key_get_uid_count(key: *mut RnpKey,
                         count: *mut size_t)
                         -> RnpResult {
    assert_ptr!(key);
    assert_ptr!(count);

    if let Some(cert) = (*key).cert() {
        *count = cert.userids().count();
        RNP_SUCCESS
    } else {
        RNP_ERROR_NO_SUITABLE_KEY
    }
}

// XXX: should we only consider valid subkeys, or all of them?
#[no_mangle] pub unsafe extern "C"
fn rnp_key_get_subkey_at(key: *mut RnpKey,
                         idx: size_t,
                         subkey: *mut *mut RnpKey)
                         -> RnpResult {
    assert_ptr!(key);
    assert_ptr!(subkey);

    if let Some(cert) = (*key).cert() {
        if let Some(k) = cert.keys().subkeys().nth(idx) {
            *subkey = Box::into_raw(Box::new(RnpKey {
                ctx: (*key).ctx,
                key: k.key().clone()
                    .parts_into_unspecified()
                    .role_into_unspecified(),
                cert: Some(cert.clone()),
            }));
            RNP_SUCCESS
        } else {
            RNP_ERROR_BAD_PARAMETERS
        }
    } else {
        RNP_ERROR_NO_SUITABLE_KEY
    }
}

// XXX: should we only consider valid subkeys, or all of them?
#[no_mangle] pub unsafe extern "C"
fn rnp_key_get_subkey_count(key: *mut RnpKey,
                            count: *mut size_t)
                            -> RnpResult {
    assert_ptr!(key);
    assert_ptr!(count);

    if let Some(cert) = (*key).cert() {
        *count = cert.keys().subkeys().count();
        RNP_SUCCESS
    } else {
        RNP_ERROR_NO_SUITABLE_KEY
    }
}

#[no_mangle] pub unsafe extern "C"
fn rnp_key_allows_usage(key: *mut RnpKey,
                        usage: *const c_char,
                        result: *mut bool)
                        -> RnpResult {
    assert_ptr!(key);
    assert_ptr!(usage);
    assert_ptr!(result);

    let usage = rnp_try!(RnpKeyUsage::from_rnp_id(usage));

    if let Some(cert) = (*key).cert()
        .and_then(|c| c.with_policy(P, None).ok())
    {
        let vka = cert
            .keys().key_handle((*key).fingerprint())
            .nth(0).expect("subkey must exist");

        *result = vka.has_any_key_flag(usage.to_keyflags());
    } else {
        // Not valid under the policy.  Don't allow use of key.
        *result = false;
    }
    RNP_SUCCESS
}

// XXX: Revocation is a lot less binary than RNP would like it to be.
// How should we handle third-party revocations here?
#[no_mangle] pub unsafe extern "C"
fn rnp_key_is_revoked(key: *mut RnpKey,
                      result: *mut bool)
                      -> RnpResult {
    assert_ptr!(key);
    assert_ptr!(result);

    if let Some(cert) = (*key).cert()
        .and_then(|c| c.with_policy(P, None).ok())
    {
        let vka = cert
            .keys().key_handle((*key).fingerprint())
            .nth(0).expect("subkey must exist");

        use openpgp::types::RevocationStatus::*;
        *result =
            match vka.revocation_status() {
                Revoked(_) => true,
                CouldBe(_) => false, // XXX
                NotAsFarAsWeKnow => false,
            };
    } else {
        // Not valid under the policy.  Treat as revoked.
        *result = true;
    }
    RNP_SUCCESS
}

#[no_mangle] pub unsafe extern "C"
fn rnp_key_export_autocrypt(key: *mut RnpKey,
                            _subkey: *mut RnpKey,
                            uid: *const c_char,
                            output: *mut RnpOutput,
                            _flags: u32)
                            -> RnpResult {
    assert_ptr!(key);
    assert_ptr!(uid);
    assert_ptr!(output);
    let uid = rnp_try!(cstr_to_str(uid));

    fn f(cert: &Cert, uid: &str, output: &mut dyn io::Write)
         -> openpgp::Result<()>
    {
        // Attempt to parse the given user id into only the email.
        let parsed_uid = UserID::from(uid.to_string());
        let addr = parsed_uid.email().ok().and_then(|e| e)
        // But fall back to whatever we got.
            .unwrap_or(uid.to_string());

        // Instead of implementing what RNP does, we use
        // sequoia-autocrypt for the normalization, and ignore subkey.
        use sequoia_autocrypt::AutocryptHeader;
        let header = AutocryptHeader::new_sender(P, cert, &addr, None)?;
        let cert = header.key.expect("on success, the cleaned cert is there");
        cert.serialize(output)?;
        Ok(())
    }

    if let Some(cert) = (*key).cert() {
        if let Err(e) = f(cert, uid, &mut *output) {
            eprintln!("sequoia-octopus: failed to export for autocrypt: {}", e);
            RNP_ERROR_GENERIC
        } else {
            RNP_SUCCESS
        }
    } else {
        RNP_ERROR_NO_SUITABLE_KEY
    }
}

/// XXX: This API seems dangerous.
#[no_mangle] pub unsafe extern "C"
fn rnp_key_remove(key: *mut RnpKey,
                  flags: RnpKeyRemoveFlags)
                  -> RnpResult {
    assert_ptr!(key);
    let key = &mut *key;
    let ctx = &mut *key.ctx;

    let is_subkey = ! rnp_try!((*key).is_primary());
    let remove_public = flags & RNP_KEY_REMOVE_PUBLIC > 0;
    let remove_secret = flags & RNP_KEY_REMOVE_SECRET > 0;
    let remove_subkeys = flags & RNP_KEY_REMOVE_SUBKEYS > 0;

    match (is_subkey, remove_subkeys) {
        (false, false) => {
            // XXX RNP allows one to delete a primary key without
            // deleting the subkeys.  That is so odd.  We don't
            // support that, because:
            //
            //   - We store whole certificates, and without the
            //     primary key, we have no place to store the subkey.
            //   - The usecase for doing that seems dodgy.
            return RNP_ERROR_NOT_SUPPORTED;
        },
        (false, true) => (), // OK.
        (true, false) => (), // OK.
        (true, true) => return RNP_ERROR_BAD_PARAMETERS,
    }

    let fp = key.fingerprint();

    /// Removes the subkey or certificate with fingerprint `fp`.
    ///
    /// Returns true if at least one key/cert has been removed.
    fn remove_all(certs: &mut Vec<Cert>, fp: &Fingerprint) -> bool {
        let mut removed_one = false;

        // First, remove all certs with that fingerprint.
        certs.retain(|c| if c.fingerprint() == *fp {
            removed_one = true;
            false
        } else {
            true
        });

        // Then, remove all subkeys with that fingerprint.
        certs.iter_mut().for_each(|c| {
            *c = c.clone().retain_subkeys(|ska| if ska.fingerprint() == *fp {
                removed_one = true;
                false
            } else {
                true
            });
        });

        removed_one
    }

    if remove_public {
        if ! ctx.certs.remove_all(&fp) && ! remove_secret {
            return RNP_ERROR_KEY_NOT_FOUND;
        }
    }

    if remove_secret {
        if ! ctx.keys.remove_all(&fp) {
            return RNP_ERROR_KEY_NOT_FOUND;
        }
    }

    RNP_SUCCESS
}

#[no_mangle] pub unsafe extern "C"
fn rnp_key_export(key: *mut RnpKey,
                  output: *mut RnpOutput,
                  flags: RnpKeyExportFlags)
                  -> RnpResult {
    assert_ptr!(key);
    assert_ptr!(output);
    let key = &mut *key;
    let output = &mut *output;

    let is_subkey = ! rnp_try!(key.is_primary());
    let armored = flags & RNP_KEY_EXPORT_ARMORED > 0;
    // XXX: This flag is so odd.  How can you not export the public
    // key?
    let _export_public = flags & RNP_KEY_EXPORT_PUBLIC > 0;
    let export_secret = flags & RNP_KEY_EXPORT_SECRET > 0;
    let export_subkeys = flags & RNP_KEY_EXPORT_SUBKEYS > 0;

    match (is_subkey, export_subkeys) {
        (false, false) => {
            // XXX RNP allows one to export a primary key without
            // exporting the subkeys.  That is so odd.
            () // Grudgingly...
        },
        (false, true) => (), // OK.
        (true, false) => (), // OK.
        (true, true) => return RNP_ERROR_BAD_PARAMETERS,
    }

    let mut cert = key.cert()
        .expect("worked for is_primary() above").clone();

    // Cut down cert.
    if ! export_subkeys {
        cert = cert.retain_subkeys(|_| false);
    } else if is_subkey {
        let subkey = key.fingerprint();
        cert = cert.retain_subkeys(|ska| ska.fingerprint() == subkey);
    }

    fn f(cert: Cert, armored: bool, export_secret: bool, sink: &mut RnpOutput)
         -> openpgp::Result<()> {
        match (armored, export_secret) {
            (false, false) => cert.export(sink)?,
            (false,  true) => cert.as_tsk().export(sink)?,
            ( true, false) => cert.armored().export(sink)?,
            ( true,  true) => {
                // XXX: This is not available in sequoia-openpgp 1.0:
                //
                // cert.as_tsk().armored().export(sink)?
                //
                // Drop this workaround once we depend on >= 1.1, and
                // use the above instead.
                use openpgp::armor::{Writer, Kind};
                let mut w = Writer::new(sink, Kind::SecretKey)?;
                cert.as_tsk().serialize(&mut w)?;
                w.finalize()?;
            },
        }
        Ok(())
    }

    if let Err(e) = f(cert, armored, export_secret, output) {
        warn!("failed to export key: {}", e);
        RNP_ERROR_WRITE
    } else {
        RNP_SUCCESS
    }
}

#[no_mangle] pub unsafe extern "C"
fn rnp_key_is_locked(key: *mut RnpKey,
                     result: *mut bool)
                     -> RnpResult {
    assert_ptr!(key);
    assert_ptr!(result);
    let key = &mut *key;
    if let Some(k) = key.key.parts_as_secret().ok() {
        *result = (*key.ctx).key_is_locked(k);
        RNP_SUCCESS
    } else {
        RNP_ERROR_NO_SUITABLE_KEY
    }
}

#[no_mangle] pub unsafe extern "C"
fn rnp_key_lock(key: *mut RnpKey)
                -> RnpResult {
    assert_ptr!(key);
    let key = &mut *key;
    if let Some(k) = key.key.parts_as_secret().ok() {
        (*key.ctx).key_lock(k);
        RNP_SUCCESS
    } else {
        RNP_ERROR_NO_SUITABLE_KEY
    }
}

#[no_mangle] pub unsafe extern "C"
fn rnp_key_unlock(key: *mut RnpKey,
                  password: *const c_char)
                  -> RnpResult {
    assert_ptr!(key);
    let password = if password.is_null() {
        None
    } else {
        Some(rnp_try!(cstr_to_str(password)).to_string().into())
    };

    let key = &mut *key;
    if let Some(k) = key.key.parts_as_secret().ok() {
        if let Err(e) = (*key.ctx).key_unlock(k.clone(), password) {
            warn!("rnp_key_unlock: {}: e", e);
            RNP_ERROR_GENERIC
        } else {
            RNP_SUCCESS
        }
    } else {
        RNP_ERROR_NO_SUITABLE_KEY
    }
}

#[no_mangle] pub unsafe extern "C"
fn rnp_key_is_protected(key: *mut RnpKey,
                        result: *mut bool)
                        -> RnpResult {
    rnp_function!(rnp_key_is_protected, crate::TRACE);
    let key = assert_ptr_ref!(key);
    assert_ptr!(result);
    *result = key.has_secret() && ! key.has_unencrypted_secret();
    t!("Key {:X} is protected? {}", key.fingerprint(), *result);
    RNP_SUCCESS
}

#[no_mangle] pub unsafe extern "C"
fn rnp_key_protect(key: *mut RnpKey,
                   password: *const c_char,
                   _cipher: *const c_char,
                   _cipher_mode: *const c_char,
                   _hash: *const c_char,
                   _iterations: size_t)
                   -> RnpResult {
    rnp_function!(rnp_key_protect, crate::TRACE);
    let key = assert_ptr_mut!(key);
    let fp = key.fingerprint();
    assert_ptr!(password);
    let password = rnp_try!(cstr_to_str(password));

    let ctx = &mut *key.ctx;
    let mut key =
        if let Ok(key) = key.key.clone().parts_into_secret() {
            key
        } else {
            return RNP_ERROR_NO_SUITABLE_KEY;
        };

    let f = || -> openpgp::Result<()> {
        if key.has_unencrypted_secret() {
            t!("Key {:X} is NOT currently protected", fp);
        } else {
            t!("Key {:X} is currently protected", fp);
            key = ctx.decrypt_key_for(None, key, RnpPasswordFor::Protect)?;
        }

        let key = key.encrypt_secret(&password.into())?;
        if let Some(mut cert) = ctx.key_mut_by_fp(&fp) {
            let key: openpgp::Packet =
                if key.fingerprint() == cert.fingerprint() {
                    key.role_into_primary().into()
                } else {
                    key.role_into_subordinate().into()
                };

            *cert = cert.clone().insert_packets(Some(key))?;
            Ok(())
        } else {
            _warn!("Key {:X} not found in keyring", fp);
            Err(anyhow::anyhow!("Key {:X} not found in keyring", fp))
        }
    };

    if let Err(e) = f() {
        _warn!("{}", e);
        RNP_ERROR_GENERIC
    } else {
        RNP_SUCCESS
    }
}

#[no_mangle] pub unsafe extern "C"
fn rnp_key_unprotect(key: *mut RnpKey,
                     password: *const c_char)
                     -> RnpResult {
    rnp_function!(rnp_key_unprotect, crate::TRACE);
    let key = assert_ptr_mut!(key);
    let fp = key.fingerprint();
    let password = if password.is_null() {
        None
    } else {
        Some(rnp_try!(cstr_to_str(password)))
    };

    let ctx = &mut *key.ctx;
    let mut key =
        if let Ok(key) = key.key.clone().parts_into_secret() {
            key
        } else {
            return RNP_ERROR_NO_SUITABLE_KEY;
        };

    let f = || -> openpgp::Result<()> {
        if key.has_unencrypted_secret() {
            t!("Key {:X} is NOT currently protected, we're done", fp);
            return Ok(());
        } else {
            t!("Key {:X} is currently protected", fp);
            if let Some(p) = password {
                key = key.decrypt_secret(&p.into())?;
            } else {
                key = ctx.decrypt_key_for(None, key, RnpPasswordFor::Protect)?;
            }
        }

        if let Some(mut cert) = ctx.key_mut_by_fp(&fp) {
            let key: openpgp::Packet =
                if key.fingerprint() == cert.fingerprint() {
                    key.role_into_primary().into()
                } else {
                    key.role_into_subordinate().into()
                };

            *cert = cert.clone().insert_packets(Some(key))?;
            Ok(())
        } else {
            _warn!("Key {:X} not found in keyring", fp);
            Err(anyhow::anyhow!("Key {:X} not found in keyring", fp))
        }
    };

    if let Err(e) = f() {
        _warn!("{}", e);
        RNP_ERROR_GENERIC
    } else {
        RNP_SUCCESS
    }
}


#[no_mangle] pub unsafe extern "C"
fn rnp_key_export_revocation(key: *mut RnpKey,
                             output: *mut RnpOutput,
                             _flags: u32,
                             hash: *const c_char,
                             code: *const c_char,
                             reason: *const c_char)
                             -> RnpResult {
    assert_ptr!(key);
    assert_ptr!(output);
    let key = &mut *key;
    let output = &mut *output;

    if ! rnp_try!(key.is_primary()) {
        return RNP_ERROR_BAD_PARAMETERS;
    }

    if ! key.has_secret() {
        warn!("rnp_key_export_revocation: creating third-party revocation \
               not implemented");
        return RNP_ERROR_NOT_IMPLEMENTED;
    }

    let hash = if hash.is_null() {
        None
    } else {
        Some(rnp_try!(HashAlgorithm::from_rnp_id(hash)))
    };

    let code = if code.is_null() {
        ReasonForRevocation::Unspecified
    } else {
        rnp_try!(ReasonForRevocation::from_rnp_id(code))
    };

    let reason = if reason.is_null() {
        b""
    } else {
        CStr::from_ptr(reason).to_bytes()
    };

    fn f(key: &mut RnpKey, sink: &mut RnpOutput, hash: Option<HashAlgorithm>,
         code: ReasonForRevocation, reason: &[u8])
         -> openpgp::Result<()>
    {
        let ctx = unsafe { &mut *key.ctx };
        let primary_key = key.key.clone().parts_into_secret()?;
        let mut keypair = ctx.decrypt_key_for(key.cert.as_ref(),
                                              primary_key,
                                              // XXX: This is what RNP
                                              // does, there is no
                                              // dedicated reason.
                                              RnpPasswordFor::Unlock)?
            .into_keypair()?;

        let sig = CertRevocationBuilder::new()
            .set_reason_for_revocation(code, reason)?
            .build(&mut keypair, key.cert.as_ref().expect("it is a primary"),
                   hash)?;

        Packet::from(sig).serialize(sink)?;
        Ok(())
    }

    if let Err(e) = f(key, output, hash, code, reason) {
        warn!("rnp_key_export_revocation: {}", e);
        RNP_ERROR_GENERIC
    } else {
        RNP_SUCCESS
    }
}

#[no_mangle] pub unsafe extern "C"
fn rnp_key_revoke(key: *mut RnpKey,
                  _flags: u32,
                  hash: *const c_char,
                  code: *const c_char,
                  reason: *const c_char)
                  -> RnpResult {
    rnp_function!(rnp_key_revoke, crate::TRACE);
    let key = assert_ptr_mut!(key);
    let ctx = &mut *key.ctx;

    let cert = if let Some(cert) = key.cert() {
        cert.clone()
    } else {
        return RNP_ERROR_NO_SUITABLE_KEY;
    };

    if ! cert.primary_key().has_secret() {
        warn!("rnp_key_export_revocation: creating third-party revocation \
               not implemented");
        return RNP_ERROR_NOT_IMPLEMENTED;
    }

    let hash = if hash.is_null() {
        None
    } else {
        Some(rnp_try!(HashAlgorithm::from_rnp_id(hash)))
    };

    let code = if code.is_null() {
        ReasonForRevocation::Unspecified
    } else {
        rnp_try!(ReasonForRevocation::from_rnp_id(code))
    };

    let reason = if reason.is_null() {
        b""
    } else {
        CStr::from_ptr(reason).to_bytes()
    };

    fn f(ctx: &mut RnpContext, cert: Cert, key: &RnpKey,
         hash: Option<HashAlgorithm>, code: ReasonForRevocation, reason: &[u8])
         -> openpgp::Result<()>
    {
        let is_primary = cert.fingerprint() == key.fingerprint();

        let primary_key =
            cert.primary_key().key().clone().parts_into_secret()?
            .role_into_unspecified();
        let mut keypair = ctx.decrypt_key_for(key.cert.as_ref(),
                                              primary_key,
                                              // XXX: This is what RNP
                                              // does, there is no
                                              // dedicated reason.
                                              RnpPasswordFor::Unlock)?
            .into_keypair()?;

        let sig = if is_primary {
            CertRevocationBuilder::new()
                .set_reason_for_revocation(code, reason)?
                .build(&mut keypair, &cert, hash)?
        } else {
            SubkeyRevocationBuilder::new()
                .set_reason_for_revocation(code, reason)?
                .build(&mut keypair, &cert, key.key.role_as_subordinate(), hash)?
        };

        // Merge the revocation into the store.
        ctx.keys.insert(cert.insert_packets(Some(sig))?);
        Ok(())
    }

    if let Err(e) = f(ctx, cert, key, hash, code, reason) {
        _warn!("{}", e);
        RNP_ERROR_GENERIC
    } else {
        RNP_SUCCESS
    }
}

#[no_mangle] pub unsafe extern "C"
fn rnp_key_set_expiration(key: *mut RnpKey,
                          expiry: u32)
                          -> RnpResult {
    rnp_function!(rnp_key_set_expiration, crate::TRACE);
    let key = assert_ptr_mut!(key);
    let ctx = &mut *key.ctx;

    let expiry = if expiry == 0 {
        None
    } else {
        Some(Duration::new(expiry as u64, 0))
    };

    let cert = if let Some(cert) = key.cert() {
        cert.clone()
    } else {
        return RNP_ERROR_NO_SUITABLE_KEY;
    };

    fn f(ctx: &mut RnpContext, cert: Cert, key: &RnpKey,
         expiry: Option<Duration>)
         -> openpgp::Result<()>
    {
        let is_primary = cert.fingerprint() == key.fingerprint();
        let absolute_expiration_time =
            expiry.map(|e| key.creation_time() + e);

        let mut primary_signer =
            match cert.primary_key().key().clone().role_into_unspecified()
            .parts_into_secret()
        {
            Ok(key) => {
                ctx.decrypt_key_for(Some(&cert),
                                    key,
                                    // XXX: This is what RNP
                                    // does, there is no
                                    // dedicated reason.
                                    RnpPasswordFor::Unlock)?
                    .into_keypair()?
            },
            Err(e) => {
                _warn!("Cannot change expiration time without \
                        primary secret: {}", e);
                return Err(e);
            },
        };

        let vcert = cert.with_policy(P, None)?;
        let sigs = if is_primary {
            vcert.primary_key()
                .set_expiration_time(
                    &mut primary_signer,
                    absolute_expiration_time)?
        } else {
            let vka = vcert.keys().key_handle(key.fingerprint()).nth(0)
                .ok_or(anyhow::anyhow!(
                    "subkey not bound, cannot change expiration time"))?;

            let mut subkey_signer =
                if vka.for_signing() || vka.for_authentication() {
                    match vka.key().clone().role_into_unspecified()
                        .parts_into_secret()
                    {
                        Ok(key) => {
                            Some(ctx.decrypt_key_for(Some(&cert),
                                                     key,
                                                     // XXX: This is what RNP
                                                     // does, there is no
                                                     // dedicated reason.
                                                     RnpPasswordFor::Unlock)?
                                 .into_keypair()?)
                        },
                        Err(e) => {
                            _warn!("Cannot change expiration time without \
                                    subkey secret: {}", e);
                            return Err(e);
                        },
                    }
                } else {
                    None
                };

            vka.set_expiration_time(
                &mut primary_signer,
                subkey_signer.as_mut()
                    .map(|pair| -> &mut dyn openpgp::crypto::Signer {
                        &mut *pair
                    }),
                absolute_expiration_time)?
        };

        // Merge the updated cert into the store.
        ctx.keys.insert(cert.insert_packets(sigs)?);
        Ok(())
    }

    if let Err(e) = f(ctx, cert, key, expiry) {
        _warn!("{}", e);
        RNP_ERROR_GENERIC
    } else {
        RNP_SUCCESS
    }
}
