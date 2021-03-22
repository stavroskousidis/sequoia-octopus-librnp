use std::{
    cell::Ref,
    cell::RefCell,
    cell::RefMut,
    ffi::{
        CStr,
    },
    io,
    rc::Rc,
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
    cert: Option<Rc<RefCell<Cert>>>,
}

impl RnpKey {
    /// Creates a new RnpKey without reference to the containing certificate.
    ///
    /// If at all possible you should use the `new` variant.  This is
    /// because when the certificate is needed and it is not
    /// available, it is looked up in the keystore.  This introduces
    /// two failure modes: the key is not present, there are multiple
    /// keys that have the same fingerprint.  In the latter case, we
    /// return the best match, which should usually be good enough.
    pub fn without_cert(ctx: *mut RnpContext,
                        key: Key<UnspecifiedParts, UnspecifiedRole>) -> Self {
        let mut key = RnpKey {
            ctx,
            key,
            cert: None,
        };
        key.find_cert();

        key
    }

    pub fn new(ctx: *mut RnpContext,
               key: Key<UnspecifiedParts, UnspecifiedRole>,
               cert: &Cert) -> Self {
        let ctx = unsafe { &mut *ctx };
        let cert_cell_ref = if let Some(cert_cell_ref)
            = ctx.certs.cert_ref_cell(&cert.fingerprint())
        {
            Rc::clone(&cert_cell_ref)
        } else {
            // We've been asked to create a key handle to a key that
            // is not in our keystore.  That's not good.  There are a
            // few things we can do:
            //
            //   1. Crash (this function is infallible).
            //   2. Supply None (this will cause problems later).
            //   3. Reference the passed certificate.
            //   4. Insert the passed certificate into the keystore.
            //
            // For now we opt for #3.  #4 might be better since we
            // don't treat the keyring as a curated keyring anyway.
            warn!("Attempt to create key handle for key ({}, {}) \
                   that is not in the keystore",
                  cert.fingerprint(), key.fingerprint());
            Rc::new(RefCell::new(cert.clone()))
        };

        RnpKey {
            ctx,
            key,
            cert: Some(cert_cell_ref),
        }
    }

    fn find_cert(&mut self) {
        rnp_function!(RnpKey::cert, super::TRACE);
        if self.cert.is_none() {
            t!("Arg, need to find cert in the key store!");

            // There may be multiple certificates with the same key.
            // Prefer an exact match (i.e., fingerprint *and* secret
            // key material match), if one is available.

            let ctx = unsafe { &*self.ctx };
            let fp = self.key.fingerprint();

            let mut candidates = Vec::new();
            for cert in ctx.certs.cert_ref_cell(&fp)
            {
                for k in cert.borrow().keys().key_handle(&fp) {
                    // Eq compares the secret parts.
                    candidates.push(
                        (if &self.key
                         == k.key()
                             .role_as_unspecified()
                             .parts_as_unspecified()
                         {
                             0
                         } else {
                             1
                         },
                         Rc::clone(&cert)))
                }
            }

            if candidates.len() == 0 {
                warn!("No certificate in key store has the key {:X}", fp);
                return;
            }

            candidates.sort_by_key(|a| { (a.0, a.1.borrow().fingerprint()) });
            self.cert = candidates.into_iter().next().map(|c| {
                if c.0 == 1 {
                    warn!("No certificate exactly contains the key {}", fp);
                }

                c.1
            });
        }
    }

    fn cert(&mut self) -> Option<Ref<Cert>> {
        self.find_cert();
        self.cert.as_ref().map(|c| c.borrow())
    }

    fn cert_mut(&mut self) -> Option<RefMut<Cert>> {
        self.find_cert();
        self.cert.as_ref().map(|c| c.borrow_mut())
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
            cert: Some((&*ctx).certs.cert_ref_cell(&cert.fingerprint())
                       .expect("just looked it up")),
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
        let key_fpr = self.fingerprint();
        if let Some(cert) = self.cert() {
            Ok(cert.fingerprint() == key_fpr)
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

    if let Some(cert) = key.cert().as_ref()
        .and_then(|c| c.with_policy(P, None).ok())
    {
        if let Some(vka) = cert.keys().key_handle(fp.clone()).nth(0) {
            *expiration =
                vka.key_validity_period().map(|d| d.as_secs() as u32)
                .unwrap_or(0); // 0 is special and means does not expire.
        } else {
            // Not valid under the policy.  Treat as expired.
            t!("The (sub)key {} is not valid under the standard policy, \
                treating as expired.", &fp);

            // Expired immediately.  0 is special and means does not expire.
            *expiration = 1;
        }
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

    if let Some(cert) = (*key).cert().as_ref()
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
                cert: Some(Rc::clone((*key).cert.as_ref().expect("valid"))),
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

    if let Some(cert) = (*key).cert().as_ref()
        .and_then(|c| c.with_policy(P, None).ok())
    {
        if let Some(vka) = cert
            .keys().key_handle((*key).fingerprint())
            .nth(0)
        {
            *result = vka.has_any_key_flag(usage.to_keyflags());
        } else {
            // Not valid under the policy.  Don't allow use of key.
            *result = false;
        }
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

    if let Some(cert) = (*key).cert().as_ref()
        .and_then(|c| c.with_policy(P, None).ok())
    {
        if let Some(vka) = cert
            .keys().key_handle((*key).fingerprint())
            .nth(0)
        {
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

    fn f(cert: Ref<Cert>, uid: &str, output: &mut dyn io::Write)
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
        let header = AutocryptHeader::new_sender(P, &cert, &addr, None)?;
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

    if remove_public {
        if ! ctx.certs.remove_all(&fp) {
            return RNP_ERROR_KEY_NOT_FOUND;
        }
    }
    else if remove_secret {
        if ! ctx.certs.remove_secret_key_material(&fp) {
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
fn rnp_key_protect(rnp_key: *mut RnpKey,
                   password: *const c_char,
                   _cipher: *const c_char,
                   _cipher_mode: *const c_char,
                   _hash: *const c_char,
                   _iterations: size_t)
                   -> RnpResult {
    rnp_function!(rnp_key_protect, crate::TRACE);
    let rnp_key = assert_ptr_mut!(rnp_key);
    let fp = rnp_key.fingerprint();
    assert_ptr!(password);
    let password = rnp_try!(cstr_to_str(password));
    t!("password = {:?}", password);

    let ctx = &mut *rnp_key.ctx;
    let mut key =
        if let Ok(key) = rnp_key.key.clone().parts_into_secret() {
            key
        } else {
            return RNP_ERROR_NO_SUITABLE_KEY;
        };

    let f = || -> openpgp::Result<()> {
        if key.has_unencrypted_secret() {
            t!("Key {:X} is NOT currently protected", fp);
        } else {
            t!("Key {:X} is currently protected", fp);
            key = ctx.decrypt_key_for(None, key, RnpPasswordFor::Protect)
                .map_err(|_| Error::BadPassword)?;
        }

        let key = key.encrypt_secret(&password.into())?;

        // Update the copy of the key in this handle.
        rnp_key.key = key.clone().parts_into_unspecified();

        if let Some(mut cert) = rnp_key.cert_mut() {
            let key: openpgp::Packet =
                if key.fingerprint() == cert.fingerprint() {
                    key.role_into_primary().into()
                } else {
                    key.role_into_subordinate().into()
                };

            *cert = cert.clone().insert_packets(Some(key))?;
            Ok(())
        } else {
            Err(anyhow::anyhow!("Key for {:X} not found in keyring",
                                fp))
        }
    };

    rnp_return!(f())
}

#[no_mangle] pub unsafe extern "C"
fn rnp_key_unprotect(rnp_key: *mut RnpKey,
                     password: *const c_char)
                     -> RnpResult {
    rnp_function!(rnp_key_unprotect, crate::TRACE);
    let rnp_key = assert_ptr_mut!(rnp_key);
    let fp = rnp_key.fingerprint();
    let password = if password.is_null() {
        None
    } else {
        Some(rnp_try!(cstr_to_str(password)))
    };
    t!("password = {:?}", password);

    let ctx = &mut *rnp_key.ctx;
    let mut key =
        if let Ok(key) = rnp_key.key.clone().parts_into_secret() {
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
                key = key.decrypt_secret(&p.into())
                    .map_err(|_| Error::BadPassword)?;
            } else {
                key = ctx.decrypt_key_for(None, key, RnpPasswordFor::Protect)
                    .map_err(|_| Error::BadPassword)?;
            }
        }

        // Update the copy of the key in this handle.
        rnp_key.key = key.clone().parts_into_unspecified();

        if let Some(mut cert) = rnp_key.cert_mut() {
            let key: openpgp::Packet =
                if key.fingerprint() == cert.fingerprint() {
                    key.role_into_primary().into()
                } else {
                    key.role_into_subordinate().into()
                };

            *cert = cert.clone().insert_packets(Some(key))?;
            Ok(())
        } else {
            Err(anyhow::anyhow!("Key for {:X} not found in keyring",
                                fp))
        }
    };

    rnp_return!(f())
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
        let mut keypair =
            if let Some(cert) = key.cert().as_ref() {
                ctx.decrypt_key_for(Some(cert),
                                    primary_key,
                                    // XXX: This is what RNP
                                    // does, there is no
                                    // dedicated reason.
                                    RnpPasswordFor::Unlock)?
            } else {
                ctx.decrypt_key_for(None,
                                    primary_key,
                                    // XXX: This is what RNP
                                    // does, there is no
                                    // dedicated reason.
                                    RnpPasswordFor::Unlock)?
            }
            .into_keypair()?;

        let sig = CertRevocationBuilder::new()
            .set_reason_for_revocation(code, reason)?
            .build(&mut keypair, &*key.cert().expect("it is a primary"),
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

    fn f(ctx: &mut RnpContext, cert: Cert, key: &mut RnpKey,
         hash: Option<HashAlgorithm>, code: ReasonForRevocation, reason: &[u8])
         -> openpgp::Result<()>
    {
        let is_primary = cert.fingerprint() == key.fingerprint();

        let primary_key =
            cert.primary_key().key().clone().parts_into_secret()?
            .role_into_unspecified();
        let mut keypair =
            if let Some(cert) = key.cert() {
                ctx.decrypt_key_for(Some(&*cert),
                                    primary_key,
                                    // XXX: This is what RNP
                                    // does, there is no
                                    // dedicated reason.
                                    RnpPasswordFor::Unlock)?
            } else {
                ctx.decrypt_key_for(None,
                                    primary_key,
                                    // XXX: This is what RNP
                                    // does, there is no
                                    // dedicated reason.
                                    RnpPasswordFor::Unlock)?
            }
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
        ctx.certs.insert(cert.insert_packets(Some(sig))?);
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
        ctx.certs.insert(cert.insert_packets(sigs)?);
        Ok(())
    }

    if let Err(e) = f(ctx, cert, key, expiry) {
        _warn!("{}", e);
        RNP_ERROR_GENERIC
    } else {
        RNP_SUCCESS
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libc::c_char;
    use std::ffi::CString;

    use crate::rnp_ffi_create;
    use crate::io::RnpInput;
    use crate::import::rnp_import_keys;
    use crate::rnp_output_to_memory;
    use crate::rnp_output_memory_get_buf;
    use crate::rnp_input_from_memory;
    use crate::rnp_input_destroy;
    use crate::rnp_output_destroy;
    use crate::rnp_ffi_destroy;

    #[test]
    fn key_consistency() -> openpgp::Result<()> {
        // Consider the following scenario:
        //
        //  1. Look up a key using rnp_locate_key and get back an
        //     RnpKey handle.
        //
        //  2. Modify the underlying certificate without using the key
        //     handle returned in (1).
        //
        //  3. Use the key handle returned in (1) to access the
        //     certificate.
        //
        // Does (3) see the modifications made in (2) or not?  It
        // should see them.
        //
        // To check for this, create a certificate with a password,
        // and (1) get a reference to the primary key.  We then (2)
        // change the password of the certificate's key, and then (3)
        // export it.  We then check if the password was actually
        // modified.  If not, then the key handle did not see the
        // changes done in (2).
        let change_pw = |ctx: *mut RnpContext,
                         cert: &Cert, old: Option<&str>, new: Option<&str>|
            -> openpgp::Result<()>
        {
            let old_c = old.map(|s| {
                CString::new(s.as_bytes()).unwrap().into_raw() as *const c_char
            });
            let new_c = new.map(|s| {
                CString::new(s.as_bytes()).unwrap().into_raw() as *const c_char
            });

            let mut primary = None;
            for (i, k) in cert.keys().enumerate() {
                let mut key: *mut RnpKey = std::ptr::null_mut();
                let r = unsafe {
                    rnp_locate_key(ctx,
                                   b"fingerprint\x00".as_ptr() as *const c_char,
                                   CString::new(k.fingerprint().to_string())
                                   .unwrap().into_raw() as *const c_char,
                                   &mut key as *mut *mut _)
                };
                assert_eq!(r, RNP_SUCCESS);

                if let Some(old_c) = old_c {
                    let r = unsafe { rnp_key_unprotect(key, old_c) };
                    if r != RNP_SUCCESS {
                        return Err(anyhow::anyhow!("Failed to change password"));
                    }
                    eprintln!("After unprotecting {} with {}",
                              k.fingerprint(), old.unwrap());
                    crate::cert_dump(
                        &unsafe { &mut *ctx }
                            .certs.by_primary_fp(&cert.fingerprint()).unwrap());
                }

                if let Some(new_c) = new_c {
                    let r = unsafe {
                        rnp_key_protect(key, new_c,
                                        std::ptr::null(),
                                        std::ptr::null(),
                                        std::ptr::null(),
                                        0)
                    };
                    assert_eq!(r, RNP_SUCCESS);
                    eprintln!("After protecting {} with {}",
                              k.fingerprint(), new.unwrap());
                    crate::cert_dump(
                        &unsafe { &mut *ctx }
                            .certs.by_primary_fp(&cert.fingerprint()).unwrap());
                }

                if i == 0 {
                    primary = Some(key);
                } else {
                    let r = unsafe { rnp_key_handle_destroy(key) };
                    assert_eq!(r, RNP_SUCCESS);
                }
            }

            let primary = primary.unwrap();

            // Export the key use the primary key handle.
            let mut output: *mut RnpOutput = std::ptr::null_mut();
            let r = unsafe {
                rnp_output_to_memory(&mut output as *mut *mut _, 0)
            };
            assert_eq!(r, RNP_SUCCESS);

            let r = unsafe {
                rnp_key_export(primary, output,
                               RNP_KEY_EXPORT_ARMORED
                               | RNP_KEY_EXPORT_PUBLIC
                               | RNP_KEY_EXPORT_SECRET
                               | RNP_KEY_EXPORT_SUBKEYS)
            };
            assert_eq!(r, RNP_SUCCESS);

            let mut buf: *mut u8 = std::ptr::null_mut();
            let mut len: libc::size_t = 0;
            let r = unsafe {
                rnp_output_memory_get_buf(
                    output,
                    &mut buf as *mut *mut _,
                    &mut len as *mut _,
                    false)
            };
            assert_eq!(r, RNP_SUCCESS);

            let mut input: *mut RnpInput = std::ptr::null_mut();
            let r = unsafe {
                rnp_input_from_memory(
                    &mut input as *mut *mut _,
                    buf, len, false)
            };
            assert_eq!(r, RNP_SUCCESS);

            // And reload load.
            let r = unsafe {
                rnp_import_keys(
                    ctx, input,
                    RNP_LOAD_SAVE_PUBLIC_KEYS
                        | RNP_LOAD_SAVE_SECRET_KEYS,
                    std::ptr::null_mut() as *mut *mut _)
            };
            assert_eq!(r, RNP_SUCCESS);

            let r = unsafe {
                rnp_input_destroy(input)
            };
            assert_eq!(r, RNP_SUCCESS);

            let r = unsafe {
                rnp_output_destroy(output)
            };
            assert_eq!(r, RNP_SUCCESS);

            let r = unsafe { rnp_key_handle_destroy(primary) };
            assert_eq!(r, RNP_SUCCESS);

            Ok(())
        };

        let mut ctx: *mut RnpContext = std::ptr::null_mut();
        let r = unsafe {
            rnp_ffi_create(
                &mut ctx as *mut *mut _,
                b"GPG\x00".as_ptr() as *const c_char,
                b"GPG\x00".as_ptr() as *const c_char)
        };
        assert_eq!(r, RNP_SUCCESS);

        // Create a key.
        let (alice, _) = openpgp::cert::CertBuilder::new()
            .add_userid("alice")
            .add_signing_subkey()
            .set_password(Some("passw0rd".into()))
            .generate()?;

        // Import it into the context.
        let mut buffer = Vec::new();
        alice.as_tsk().serialize(&mut buffer)?;

        let mut input: *mut RnpInput = std::ptr::null_mut();
        let r = unsafe {
            rnp_input_from_memory(
                &mut input as *mut *mut _,
                buffer.as_ptr(), buffer.len(), false)
        };
        assert_eq!(r, RNP_SUCCESS);

        // And load the certificate.
        let r = unsafe {
            rnp_import_keys(
                ctx, input,
                RNP_LOAD_SAVE_PUBLIC_KEYS
                    | RNP_LOAD_SAVE_SECRET_KEYS,
                std::ptr::null_mut() as *mut *mut _)
        };
        assert_eq!(r, RNP_SUCCESS);

        let r = unsafe {
            rnp_input_destroy(input)
        };
        assert_eq!(r, RNP_SUCCESS);

        eprintln!("ctx: keystore: {:?}", unsafe { &mut *ctx }.certs);

        change_pw(ctx, &alice, Some("passw0rd"), Some("new-password-1234"))
            .expect("success");

        change_pw(ctx, &alice, Some("new-password-1234"), Some("third-password"))
            .expect("correct password");

        // Make sure we can still change the password.
        assert!(change_pw(ctx, &alice, Some("bad-password"), Some("more-password"))
                .is_err());

        let r = unsafe {
            rnp_ffi_destroy(ctx)
        };
        assert_eq!(r, RNP_SUCCESS);

        Ok(())
    }
}
