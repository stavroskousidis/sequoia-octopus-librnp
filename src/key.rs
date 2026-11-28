use std::{
    cmp::min,
    fmt,
    io,
    sync::{
        Arc,
        RwLock,
        RwLockReadGuard,
        RwLockWriteGuard,
    },
    time::{
        Duration,
        SystemTime,
        UNIX_EPOCH,
    },
};
use libc::{
    c_char,
    c_void,
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
        Signature,
        UserID,
        Key,
        key::{
            UnspecifiedParts,
            UnspecifiedRole,
        },
    },
    policy::Policy,
    serialize::Serialize,
    types::{
        HashAlgorithm,
        ReasonForRevocation,
        RevocationStatus,
    },
};

use crate::{
    RnpResult,
    RnpContext,
    RnpOutput,
    keygrip::keygrip_of,
    RnpSignature,
    RnpUserID,
    RnpPasswordFor,
    str_to_rnp_buffer,
    c_str_to_rnp_buffer,
    c_str_to_rnp_buffer_lossy,
    cstr_to_str,
    armor::CrLfWriter,
    flags::*,
    conversions::*,
    error::*,
    signature::ca_signatures,
    tbprofile::TBProfile,
};

pub struct RnpKey {
    pub(crate) ctx: *mut RnpContext,
    key: Key<UnspecifiedParts, UnspecifiedRole>,
    cert: Option<Arc<RwLock<Cert>>>,
}

impl fmt::Debug for RnpKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("RnpKey")
            .field("ctx", &self.ctx)
            .field("key", &self.key.fingerprint())
            .field("cert", {
                &if let Some(c) = self.cert.as_ref() {
                    if let Ok(c) = c.read() {
                        c.fingerprint().to_hex()
                    } else {
                        "[LOCKED]".into()
                    }
                } else {
                    "Unknown".into()
                }
            })
            .finish()
    }
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
        rnp_function!(RnpKey::new, crate::TRACE);
        let ctx = unsafe { &mut *ctx };

        let cert_cell = if let Some(cert_cell)
            = ctx.certs.read().cert_cell_by_primary_fp(&cert.fingerprint())
        {
            Arc::clone(&cert_cell)
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
            Arc::new(RwLock::new(cert.clone()))
        };

        RnpKey {
            ctx,
            key,
            cert: Some(cert_cell),
        }
    }

    fn find_cert(&mut self) {
        rnp_function!(RnpKey::find_cert, crate::TRACE);
        if self.cert.is_none() {
            // There may be multiple certificates with the same key.
            // Prefer an exact match (i.e., fingerprint *and* secret
            // key material match), if one is available.

            let ctx = unsafe { &*self.ctx };
            let fp = self.key.fingerprint();

            let mut candidates = Vec::new();
            for cell in ctx.certs.read().cert_cell_by_fp(&fp) {
                let cert = cell.read().unwrap();
                for k in cert.keys().key_handle(&fp) {
                    // Eq compares the secret parts when parts is
                    // unspecified.
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
                         cert.fingerprint(),
                         Arc::clone(&cell)))
                }
            }

            if candidates.len() == 0 {
                warn!("No certificate in key store has the key {:X}", fp);
                return;
            }

            candidates.sort_by_key(|a| { (a.0, a.1.clone()) });
            self.cert = candidates.into_iter().next().map(|(exact, _, cell)| {
                if exact == 1 {
                    warn!("No certificate exactly contains the key {}", fp);
                }

                cell
            });
        }
    }

    fn cert(&mut self) -> Option<RwLockReadGuard<Cert>> {
        self.find_cert();
        self.try_cert()
    }
    pub(crate) fn try_cert(&self) -> Option<RwLockReadGuard<Cert>> {
        self.cert.as_ref().map(|c| c.read().unwrap())
    }

    fn cert_mut(&mut self) -> Option<RwLockWriteGuard<Cert>> {
        self.find_cert();
        self.try_cert_mut()
    }
    fn try_cert_mut(&self) -> Option<RwLockWriteGuard<Cert>> {
        let ctx = unsafe { &*self.ctx };
        ctx.certs.read().mark_updated();
        self.cert.as_ref().map(|c| c.write().unwrap())
    }
}

impl std::ops::Deref for RnpKey {
    type Target = Key<UnspecifiedParts, UnspecifiedRole>;

    fn deref(&self) -> &Self::Target {
        &self.key
    }
}

impl From<RnpKey> for Key<UnspecifiedParts, UnspecifiedRole> {
    fn from(k: RnpKey) -> Self {
        k.key
    }
}

#[no_mangle] pub unsafe extern "C"
fn rnp_locate_key(ctx: *mut RnpContext,
                  identifier_type: *const c_char,
                  identifier: *const c_char,
                  key: *mut *mut RnpKey)
                  -> RnpResult {
    rnp_function!(rnp_locate_key, crate::TRACE);

    let ctx = assert_ptr_mut!(ctx);
    let identifier_type = assert_str!(identifier_type);
    let identifier = assert_str!(identifier);
    let key = assert_ptr_mut!(key);

    let id = rnp_try!(
        rnp_try!(RnpIdentifierType::from_rnp_id(identifier_type))
            .with_identifier(identifier));
    t!("Locating key by {:?}", id);

    // Thunderbird is looking up an identifier.  Now is a good time to
    // check for WoT updates.  However, we cannot stall our caller,
    // hence we schedule a background job and wait for a little while.
    rnp_try_or!(
        (*ctx).certs.update_wot_in_background((*ctx).policy.clone()),
        Error::Generic.into());

    // (*ctx).cert also takes a read lock.  But we need to keep the
    // key store locked for when we look up the matching certificate's
    // cell.
    let ks = (&*ctx).certs.read();
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
                keygrip_of(k.key().mpis()).map(|g| g == grip).unwrap_or(false)
            })
                .nth(0).expect("must exist in cert").key().clone(),
        }.parts_into_unspecified();

        let cert = Some(ks.cert_cell_by_primary_fp(&cert.fingerprint())
                        .expect("just looked it up"));
        drop(ks);
        *key = Box::into_raw(Box::new(RnpKey {
            ctx,
            key: k,
            // XXX: (*ctx).cert() already found the cell.  If that
            // function returned the cell instead, then we could avoid
            // this lock and look up.
            cert,
        }));
    } else {
        *key = std::ptr::null_mut();
    }
    rnp_success!()
}

#[no_mangle] pub unsafe extern "C"
fn rnp_key_handle_destroy(key: *mut RnpKey)
                          -> RnpResult {
    rnp_function!(rnp_key_handle_destroy, crate::TRACE);
    arg!(key);

    if ! key.is_null() {
        drop(Box::from_raw(key));
    }
    rnp_success!()
}

#[no_mangle] pub unsafe extern "C"
fn rnp_key_get_keyid(key: *const RnpKey,
                     keyid: *mut *mut c_char)
                     -> RnpResult {
    rnp_function!(rnp_key_get_keyid, crate::TRACE);
    let key = assert_ptr_ref!(key);
    let keyid = assert_ptr_mut!(keyid);

    *keyid = str_to_rnp_buffer(format!("{:X}", (*key).keyid()));
    rnp_success!()
}

#[no_mangle] pub unsafe extern "C"
fn rnp_key_get_fprint(key: *const RnpKey,
                     fprint: *mut *mut c_char)
                     -> RnpResult {
    rnp_function!(rnp_key_get_fprint, crate::TRACE);
    let key = assert_ptr_ref!(key);
    let fprint = assert_ptr_mut!(fprint);

    *fprint = str_to_rnp_buffer(format!("{:X}", (*key).fingerprint()));
    rnp_success!()
}

#[no_mangle] pub unsafe extern "C"
fn rnp_key_get_alg(key: *const RnpKey,
                   alg: *mut *mut c_char)
                   -> RnpResult {
    rnp_function!(rnp_key_get_alg, crate::TRACE);
    let key = assert_ptr_ref!(key);
    let alg = assert_ptr_mut!(alg);

    *alg = str_to_rnp_buffer((*key).pk_algo().to_rnp_id());
    rnp_success!()
}

#[no_mangle] pub unsafe extern "C"
fn rnp_key_get_curve(key: *mut RnpKey, curve_out: *mut *mut c_char)
                     -> RnpResult {
    rnp_function!(rnp_key_get_curve, crate::TRACE);
    let key = assert_ptr_ref!(key);
    let curve_out = assert_ptr_mut!(curve_out);

    use openpgp::crypto::mpi::PublicKey;
    match key.key.mpis() {
        | PublicKey::EdDSA { curve, .. }
        | PublicKey::ECDSA { curve, .. }
        | PublicKey::ECDH { curve, .. } => {
            use openpgp::types::Curve::*;
            // We want to return an error on unknown curves.
            match curve {
                | NistP256
                | NistP384
                | NistP521
                | BrainpoolP256
                | BrainpoolP512
                | Ed25519
                | Cv25519 => (),
                _ => rnp_return_status!(RNP_ERROR_BAD_PARAMETERS),
            };

            *curve_out = str_to_rnp_buffer(curve.to_rnp_id());
            rnp_success!()
        },
        // Not an ECC algorithm.
        _ => rnp_return_status!(RNP_ERROR_BAD_PARAMETERS),
    }
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
// defined.  The result depends on the order the keys are returned.
#[no_mangle] pub unsafe extern "C"
fn rnp_key_is_primary(key: *mut RnpKey,
                      result: *mut bool)
                      -> RnpResult {
    rnp_function!(rnp_key_is_primary, crate::TRACE);
    let key = assert_ptr_mut!(key);
    let result = assert_ptr_mut!(result);
    *result = rnp_try!((*key).is_primary());
    rnp_success!()
}

// XXX: A key can be both primary and subkey at the same time in
// different certs, and what this function returns is not clearly
// defined.  The result depends on the order the keys are returned.
#[no_mangle] pub unsafe extern "C"
fn rnp_key_is_sub(key: *mut RnpKey,
                  result: *mut bool)
                  -> RnpResult {
    rnp_function!(rnp_key_is_sub, crate::TRACE);
    let key = assert_ptr_mut!(key);
    let result = assert_ptr_mut!(result);
    *result = ! rnp_try!((*key).is_primary());
    rnp_success!()
}

#[no_mangle] pub unsafe extern "C"
fn rnp_key_get_grip(key: *const RnpKey,
                    grip: *mut *mut c_char)
                   -> RnpResult {
    rnp_function!(rnp_key_get_grip, crate::TRACE);
    let key = assert_ptr_ref!(key);
    let grip = assert_ptr_mut!(grip);

    rnp_return_status!(if let Ok(keygrip) = keygrip_of((*key).mpis()) {
        *grip = str_to_rnp_buffer(keygrip.to_string());
        RNP_SUCCESS
    } else {
        RNP_ERROR_GENERIC
    })
}

#[no_mangle] pub unsafe extern "C"
fn rnp_key_get_primary_grip(key: *mut RnpKey,
                            grip: *mut *mut c_char)
                            -> RnpResult {
    rnp_function!(rnp_key_get_primary_grip, crate::TRACE);
    let key = assert_ptr_mut!(key);
    let grip = assert_ptr_mut!(grip);

    rnp_return_status!(if let Some(cert) = (*key).cert() {
        if let Ok(keygrip) = keygrip_of(cert.primary_key().key().mpis()) {
            *grip = str_to_rnp_buffer(keygrip.to_string());
            RNP_SUCCESS
        } else {
            RNP_ERROR_GENERIC
        }
    } else {
        RNP_ERROR_NO_SUITABLE_KEY
    })
}

/// XXX: This is a really odd function.  How can we not have the
/// public key?
#[no_mangle] pub unsafe extern "C"
fn rnp_key_have_public(key: *const RnpKey,
                       result: *mut bool)
                       -> RnpResult {
    rnp_function!(rnp_key_have_public, crate::TRACE);
    let _ = assert_ptr_ref!(key);
    let result = assert_ptr_mut!(result);

    *result = true;
    rnp_success!()
}

#[no_mangle] pub unsafe extern "C"
fn rnp_key_have_secret(key: *const RnpKey,
                       result: *mut bool)
                       -> RnpResult {
    rnp_function!(rnp_key_have_secret, crate::TRACE);
    let key = assert_ptr_ref!(key);
    let result = assert_ptr_mut!(result);

    let mut has_secret = (*key).has_secret();

    // If there is no secret in the Thunderbird keyring, we are
    // looking at the gpg-agent store.  However, we have to be careful
    // to only report secret keys after Thunderbird has created their
    // encrypted passphrase file, otherwise Thunderbird will complain
    // about the OpenPGP state being corrupted, and disable OpenPGP
    // support.
    if ! has_secret && TBProfile::has_encrypted_passphrase_txt() {
        has_secret = (*(*key).ctx).certs.key_on_agent(&(*key).fingerprint());
    }

    t!("returning {:?}", has_secret);
    *result = has_secret;
    rnp_success!()
}

#[no_mangle] pub unsafe extern "C"
fn rnp_key_get_bits(key: *const RnpKey,
                    bits: *mut u32)
                    -> RnpResult {
    rnp_function!(rnp_key_get_bits, crate::TRACE);
    let key = assert_ptr_ref!(key);
    let bits = assert_ptr_mut!(bits);

    rnp_return_status!(if let Some(b) = public_key_bits((*key).mpis()) {
        *bits = b as u32;
        RNP_SUCCESS
    } else {
        RNP_ERROR_NO_SUITABLE_KEY
    })
}

/// Returns the size of the public key in bits.
///
/// Sequoia does not define a size for the algorithms defined in RFC
/// 9980.  Like RNP, we return the size of the algorithm-specific part
/// of the public key, i.e. of the fixed-length octet strings in the
/// key packet.  Note that this is not a security level.
fn public_key_bits(mpis: &openpgp::crypto::mpi::PublicKey) -> Option<usize> {
    use openpgp::crypto::mpi::PublicKey::*;
    match mpis {
        MLDSA65_Ed25519 { eddsa, mldsa } =>
            Some((eddsa.len() + mldsa.len()) * 8),
        MLDSA87_Ed448 { eddsa, mldsa } =>
            Some((eddsa.len() + mldsa.len()) * 8),
        SLHDSA128s { public } => Some(public.len() * 8),
        SLHDSA128f { public } => Some(public.len() * 8),
        SLHDSA256s { public } => Some(public.len() * 8),
        MLKEM768_X25519 { ecdh, mlkem } =>
            Some((ecdh.len() + mlkem.len()) * 8),
        MLKEM1024_X448 { ecdh, mlkem } =>
            Some((ecdh.len() + mlkem.len()) * 8),
        _ => mpis.bits(),
    }
}

/// Returns the version of the key packet.
///
/// A subkey reports its own packet version.
#[no_mangle] pub unsafe extern "C"
fn rnp_key_get_version(key: *const RnpKey,
                       version: *mut u32)
                       -> RnpResult {
    rnp_function!(rnp_key_get_version, crate::TRACE);
    let key = assert_ptr_ref!(key);
    let version = assert_ptr_mut!(version);

    *version = (*key).version() as u32;
    rnp_success!()
}

#[no_mangle] pub unsafe extern "C"
fn rnp_key_get_creation(key: *const RnpKey,
                        creation: *mut u32)
                    -> RnpResult {
    rnp_function!(rnp_key_get_creation, crate::TRACE);
    let key = assert_ptr_ref!(key);
    let creation = assert_ptr_mut!(creation);

    *creation =
        (*key).creation_time().duration_since(UNIX_EPOCH)
        .expect("creation time is representable as epoch")
        .as_secs() as u32;
    rnp_success!()
}

#[no_mangle] pub unsafe extern "C"
fn rnp_key_get_expiration(key: *mut RnpKey,
                          expiration: *mut u32)
                          -> RnpResult {
    rnp_function!(rnp_key_get_expiration, crate::TRACE);
    let key = assert_ptr_mut!(key);
    let expiration = assert_ptr_mut!(expiration);
    let fp = key.fingerprint();
    let policy = (*(key.ctx)).policy().clone();

    if let Some(cert) = key.cert().as_ref()
        .and_then(|c| c.with_policy(&policy, None).ok())
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
    if *expiration > 0 {
        t!("{} expires {} seconds after its creation",
           fp, *expiration);
    } else {
        t!("{} does not expire", fp);
    }
    rnp_success!()
}

#[no_mangle] pub unsafe extern "C"
fn rnp_key_get_primary_uid(key: *mut RnpKey,
                           uid: *mut *mut c_char)
                           -> RnpResult {
    rnp_function!(rnp_key_get_primary_uid, crate::TRACE);
    let key = assert_ptr_mut!(key);
    let uid = assert_ptr_mut!(uid);
    let policy = (*(key.ctx)).policy().clone();

    // If we fail to find a primary userid using the standard policy,
    // we fall back to using a null policy.  This value is only used
    // for displaying purposes, and falling back seems reasonable to
    // me.
    rnp_return_status!(if let Some(cert) = (*key).cert().as_ref()
        .and_then(|c| c.with_policy(&policy, None).ok()
                  .or_else(|| c.with_policy(crate::NP, None).ok()))
    {
        if let Ok(u) = cert.primary_userid() {
            *uid = c_str_to_rnp_buffer_lossy(u.userid().value());
            RNP_SUCCESS
        } else {
            RNP_ERROR_GENERIC
        }
    } else {
        RNP_ERROR_NO_SUITABLE_KEY
    })
}

// XXX: should we only consider valid userids, or all of them?
#[no_mangle] pub unsafe extern "C"
fn rnp_key_get_uid_at(key: *mut RnpKey,
                      idx: size_t,
                      uid: *mut *mut c_char)
                      -> RnpResult {
    rnp_function!(rnp_key_get_uid_at, crate::TRACE);
    let key = assert_ptr_mut!(key);
    arg!(idx);
    let uid = assert_ptr_mut!(uid);

    rnp_return_status!(if let Some(cert) = (*key).cert() {
        if let Some(u) = cert.userids().nth(idx) {
            if let Some(ptr) = c_str_to_rnp_buffer(u.userid().value()) {
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
    })
}

// XXX: should we only consider valid userids, or all of them?
#[no_mangle] pub unsafe extern "C"
fn rnp_key_get_uid_handle_at(key: *mut RnpKey,
                             idx: size_t,
                             uid: *mut *mut RnpUserID)
                             -> RnpResult {
    rnp_function!(rnp_key_get_uid_handle_at, crate::TRACE);
    let key = assert_ptr_mut!(key);
    let uid = assert_ptr_mut!(uid);

    let ctx = (*key).ctx;
    rnp_return_status!(if let Some(cert) = (*key).cert() {
        if let Some(u) = cert.userids().nth(idx) {
            if let Some(u) = RnpUserID::new(ctx,
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
    })
}

// XXX: should we only consider valid userids, or all of them?
#[no_mangle] pub unsafe extern "C"
fn rnp_key_get_uid_count(key: *mut RnpKey,
                         count: *mut size_t)
                         -> RnpResult {
    rnp_function!(rnp_key_get_uid_count, crate::TRACE);
    let key = assert_ptr_mut!(key);
    let count = assert_ptr_mut!(count);

    rnp_return_status!(if let Some(cert) = (*key).cert() {
        *count = cert.userids().count();
        RNP_SUCCESS
    } else {
        RNP_ERROR_NO_SUITABLE_KEY
    })
}

// XXX: should we only consider valid subkeys, or all of them?
#[no_mangle] pub unsafe extern "C"
fn rnp_key_get_subkey_at(key: *mut RnpKey,
                         idx: size_t,
                         subkey: *mut *mut RnpKey)
                         -> RnpResult {
    rnp_function!(rnp_key_get_subkey_at, crate::TRACE);
    let key = assert_ptr_mut!(key);
    let subkey = assert_ptr_mut!(subkey);

    rnp_return_status!(if let Some(cell) = (*key).cert.as_ref() {
        let cert = cell.read().unwrap();

        if let Some(k) = cert.keys().subkeys().nth(idx) {
            *subkey = Box::into_raw(Box::new(RnpKey {
                ctx: (*key).ctx,
                key: k.key().clone()
                    .parts_into_unspecified()
                    .role_into_unspecified(),
                cert: Some(Arc::clone(cell)),
            }));
            RNP_SUCCESS
        } else {
            RNP_ERROR_BAD_PARAMETERS
        }
    } else {
        RNP_ERROR_NO_SUITABLE_KEY
    })
}

// XXX: should we only consider valid subkeys, or all of them?
#[no_mangle] pub unsafe extern "C"
fn rnp_key_get_subkey_count(key: *mut RnpKey,
                            count: *mut size_t)
                            -> RnpResult {
    rnp_function!(rnp_key_get_subkey_count, crate::TRACE);
    let key = assert_ptr_mut!(key);
    let count = assert_ptr_mut!(count);

    rnp_return_status!(if let Some(cert) = (*key).cert() {
        *count = cert.keys().subkeys().count();
        RNP_SUCCESS
    } else {
        RNP_ERROR_NO_SUITABLE_KEY
    })
}

#[no_mangle] pub unsafe extern "C"
fn rnp_key_get_signature_at(key: *mut RnpKey,
                            idx: size_t,
                            sig: *mut *mut RnpSignature)
                            -> RnpResult {
    rnp_function!(rnp_key_get_signature_at, crate::TRACE);
    let key = assert_ptr_mut!(key);
    arg!(idx);
    let sig = assert_ptr_mut!(sig);

    rnp_return_status!(if let Some(cert) = key.try_cert() {
        if let Some(subkey) = cert.keys().key_handle(key.fingerprint()).next() {
            if let Some((s, valid)) =
                ca_signatures(subkey.signatures()).nth(idx)
            {
                *sig = Box::into_raw(Box::new(
                    RnpSignature::new(key.ctx, s.clone(), valid)));
                RNP_SUCCESS
            } else {
                RNP_ERROR_BAD_PARAMETERS
            }
        } else {
            RNP_ERROR_NO_SUITABLE_KEY
        }
    } else {
        RNP_ERROR_NO_SUITABLE_KEY
    })
}

#[no_mangle] pub unsafe extern "C"
fn rnp_key_get_signature_count(key: *mut RnpKey,
                               count: *mut size_t)
                               -> RnpResult {
    rnp_function!(rnp_key_get_signature_count, crate::TRACE);
    let key = assert_ptr_mut!(key);
    let count = assert_ptr_mut!(count);

    rnp_return_status!(if let Some(cert) = key.try_cert() {
        if let Some(subkey) = cert.keys().key_handle(key.fingerprint()).next() {
            *count = ca_signatures(subkey.signatures()).count();
            RNP_SUCCESS
        } else {
            RNP_ERROR_NO_SUITABLE_KEY
        }
    } else {
        RNP_ERROR_NO_SUITABLE_KEY
    })
}

#[no_mangle] pub unsafe extern "C"
fn rnp_key_allows_usage(key: *mut RnpKey,
                        usage: *const c_char,
                        result: *mut bool)
                        -> RnpResult {
    rnp_function!(rnp_key_allows_usage, crate::TRACE);
    let key = assert_ptr_mut!(key);
    let usage = assert_str!(usage);
    let result = assert_ptr_mut!(result);
    let policy = (*((*key).ctx)).policy().clone();

    let usage = rnp_try!(RnpKeyUsage::from_rnp_id(usage));

    let fp = key.fingerprint();
    if let Some(cert) = (*key).cert().as_ref()
        .and_then(|c| c.with_policy(&policy, None).ok())
    {
        if let Some(vka) = cert
            .keys().key_handle(fp)
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
    rnp_success!()
}

// XXX: Revocation is a lot less binary than RNP would like it to be.
// How should we handle third-party revocations here?
#[no_mangle] pub unsafe extern "C"
fn rnp_key_is_revoked(key: *mut RnpKey,
                      result: *mut bool)
                      -> RnpResult {
    rnp_function!(rnp_key_is_revoked, crate::TRACE);
    let key = assert_ptr_mut!(key);
    let result = assert_ptr_mut!(result);
    let policy = (*((*key).ctx)).policy().clone();

    let fp = key.fingerprint();
    if let Some(cert) = (*key).cert().as_ref()
        .and_then(|c| c.with_policy(&policy, None).ok())
    {
        if let Some(vka) = cert
            .keys().key_handle(fp)
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
    rnp_success!()
}

/// Returns the signature that revokes the key, if any.
///
/// Stores NULL if there is no valid revocation signature.  Like
/// `rnp_key_is_revoked`, we rely on Sequoia to decide whether the
/// key is revoked: we only return revocation signatures that
/// Sequoia checked and that are acceptable under the policy, and we
/// ignore third-party revocations.  If there are several such
/// signatures, we return the first one that Sequoia reports.
///
/// Note: `rnp_key_is_revoked` also reports a key as revoked if it is
/// not valid under the policy.  In that case, there need not be a
/// revocation signature, and this function stores NULL.
#[no_mangle] pub unsafe extern "C"
fn rnp_key_get_revocation_signature(key: *mut RnpKey,
                                    sig: *mut *mut RnpSignature)
                                    -> RnpResult {
    rnp_function!(rnp_key_get_revocation_signature, crate::TRACE);
    let key = assert_ptr_mut!(key);
    let sig = assert_ptr_mut!(sig);
    let ctx = key.ctx;
    let policy = (*ctx).policy().clone();

    *sig = std::ptr::null_mut();

    let fp = key.fingerprint();
    let cert = if let Some(cert) = key.cert() {
        cert
    } else {
        rnp_return_status!(RNP_ERROR_BAD_PARAMETERS);
    };

    fn first(status: RevocationStatus) -> Option<openpgp::packet::Signature> {
        use openpgp::types::RevocationStatus::*;
        match status {
            Revoked(revs) => revs.into_iter().next().cloned(),
            CouldBe(_) => None, // XXX
            NotAsFarAsWeKnow => None,
        }
    }

    let rev = if cert.fingerprint() == fp {
        first(cert.revocation_status(&policy, None))
    } else if let Some(ka) = cert.keys().subkeys().key_handle(fp).next() {
        first(ka.revocation_status(&policy, None))
    } else {
        rnp_return_status!(RNP_ERROR_BAD_PARAMETERS);
    };

    if let Some(rev) = rev {
        *sig = Box::into_raw(Box::new(
            RnpSignature::new(ctx, rev, Some(true))));
    }
    rnp_success!()
}

#[no_mangle] pub unsafe extern "C"
fn rnp_key_export_autocrypt(key: *mut RnpKey,
                            subkey: *mut RnpKey,
                            uid: *const c_char,
                            output: *mut RnpOutput,
                            flags: u32)
                            -> RnpResult {
    rnp_function!(rnp_key_export_autocrypt, crate::TRACE);
    let key = assert_ptr_mut!(key);
    arg!(subkey);
    let uid = assert_str!(uid); // XXX: Could be NULL.
    let output = assert_ptr_mut!(output);
    arg!(flags);

    let policy = (*((*key).ctx)).policy().clone();

    fn f(policy: &dyn Policy, cert: RwLockReadGuard<Cert>, uid: &str,
         output: &mut dyn io::Write)
         -> openpgp::Result<()>
    {
        // Attempt to parse the given user id into only the email.
        let parsed_uid = UserID::from(uid.to_string());
        let addr = parsed_uid.email().ok().and_then(|e| e)
        // But fall back to whatever we got.
            .unwrap_or(uid);

        // Instead of implementing what RNP does, we use
        // sequoia-autocrypt for the normalization, and ignore subkey.
        use sequoia_autocrypt::AutocryptHeader;
        let header = AutocryptHeader::new_sender(policy, &cert, addr, None)?;
        let cert = header.key.expect("on success, the cleaned cert is there");
        cert.serialize(output)?;
        Ok(())
    }

    rnp_return_status!(if let Some(cert) = (*key).cert() {
        if let Err(e) = f(&policy, cert, uid, &mut *output) {
            log!("sequoia-octopus: failed to export for autocrypt: {}", e);
            RNP_ERROR_GENERIC
        } else {
            RNP_SUCCESS
        }
    } else {
        RNP_ERROR_NO_SUITABLE_KEY
    })
}

/// XXX: This API seems dangerous.
#[no_mangle] pub unsafe extern "C"
fn rnp_key_remove(key: *mut RnpKey,
                  flags: RnpKeyRemoveFlags)
                  -> RnpResult {
    rnp_function!(rnp_key_remove, crate::TRACE);
    let key = assert_ptr_mut!(key);
    arg!(flags);
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
            rnp_return_status!(RNP_ERROR_NOT_SUPPORTED);
        },
        (false, true) => (), // OK.
        (true, false) => (), // OK.
        (true, true) => rnp_return_status!(RNP_ERROR_BAD_PARAMETERS),
    }

    let fp = key.fingerprint();

    if remove_public {
        if ! ctx.certs.write().remove_all(&fp) {
            rnp_return_status!(RNP_ERROR_KEY_NOT_FOUND);
        }
    }
    else if remove_secret {
        if ! ctx.certs.write().remove_secret_key_material(&fp) {
            rnp_return_status!(RNP_ERROR_KEY_NOT_FOUND);
        }
    }

    rnp_success!()
}

#[no_mangle] pub unsafe extern "C"
fn rnp_key_export(key: *mut RnpKey,
                  output: *mut RnpOutput,
                  flags: RnpKeyExportFlags)
                  -> RnpResult {
    rnp_function!(rnp_key_export, crate::TRACE);
    let key = assert_ptr_mut!(key);
    let output = assert_ptr_mut!(output);
    arg!(flags);
    let key = &mut *key;

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
        (true, true) => rnp_return_status!(RNP_ERROR_BAD_PARAMETERS),
    }

    let mut cert = key.cert()
        .expect("worked for is_primary() above").clone();

    // Cut down cert.
    if ! export_subkeys {
        cert = cert.retain_subkeys(|_| false);
    } else if is_subkey {
        let subkey = key.fingerprint();
        cert = cert.retain_subkeys(|ska| ska.key().fingerprint() == subkey);
    }

    fn f(cert: Cert, armored: bool, export_secret: bool, sink: &mut RnpOutput)
         -> openpgp::Result<()> {
        match (armored, export_secret) {
            (false, false) => cert.export(sink)?,
            (false,  true) => cert.as_tsk().export(sink)?,
            // Like RNP, end the lines of the armor with CRLF.
            ( true, false) =>
                cert.armored().export(&mut CrLfWriter::new(sink))?,
            ( true,  true) =>
                cert.as_tsk().armored().export(&mut CrLfWriter::new(sink))?,
        }
        Ok(())
    }

    rnp_return_status!(if let Err(e) = f(cert, armored, export_secret, output) {
        warn!("failed to export key: {}", e);
        RNP_ERROR_WRITE
    } else {
        RNP_SUCCESS
    })
}

#[no_mangle] pub unsafe extern "C"
fn rnp_key_is_locked(key: *mut RnpKey,
                     result: *mut bool)
                     -> RnpResult {
    rnp_function!(rnp_key_is_locked, crate::TRACE);
    let key = assert_ptr_mut!(key);
    let result = assert_ptr_mut!(result);

    rnp_return_status!(if let Some(k) = key.key.parts_as_secret().ok() {
        *result = (*key.ctx).key_is_locked(k);
        RNP_SUCCESS
    } else {
        if thunderbird_workaround!() {
            // Tell Thunderbird that keys without secret key material
            // are unlocked.  This will make transparent encryption
            // using gpg-agent work.
            *result = false;
            RNP_SUCCESS
        } else {
            // Stock RNP will return an error if invoked on keys
            // without secret key material.
            RNP_ERROR_NO_SUITABLE_KEY
        }
    })
}

#[no_mangle] pub unsafe extern "C"
fn rnp_key_lock(key: *mut RnpKey)
                -> RnpResult {
    rnp_function!(rnp_key_lock, crate::TRACE);
    let key = assert_ptr_mut!(key);

    rnp_return_status!(if let Some(k) = key.key.parts_as_secret().ok() {
        (*key.ctx).key_lock(k);
        RNP_SUCCESS
    } else {
        RNP_ERROR_NO_SUITABLE_KEY
    })
}

#[no_mangle] pub unsafe extern "C"
fn rnp_key_unlock(key: *mut RnpKey,
                  password: *const c_char)
                  -> RnpResult {
    rnp_function!(rnp_key_unlock, crate::TRACE);
    let key = assert_ptr_mut!(key);

    let password = if password.is_null() {
        arg!(password);
        None
    } else {
        arg!("<REDACTED>");
        Some(rnp_try!(cstr_to_str(password)).to_string().into())
    };

    rnp_return_status!(if let Some(k) = key.key.parts_as_secret().ok() {
        if let Err(e) = (*key.ctx).key_unlock(k.clone(), password) {
            warn!("rnp_key_unlock: {}", e);
            RNP_ERROR_GENERIC
        } else {
            RNP_SUCCESS
        }
    } else {
        RNP_ERROR_NO_SUITABLE_KEY
    })
}

#[no_mangle] pub unsafe extern "C"
fn rnp_key_is_protected(key: *mut RnpKey,
                        result: *mut bool)
                        -> RnpResult {
    rnp_function!(rnp_key_is_protected, crate::TRACE);
    let key = assert_ptr_mut!(key);
    let result = assert_ptr_mut!(result);
    *result = (key.has_secret() && ! key.has_unencrypted_secret())
        || (*key.ctx).certs.key_on_agent(&key.fingerprint());
    t!("Key {:X} is {}protected", key.fingerprint(),
       if *result { "" } else { "not " });
    rnp_success!()
}

#[no_mangle] pub unsafe extern "C"
fn rnp_key_get_protection_type(key: *mut RnpKey, typ: *mut *const c_char)
                        -> RnpResult {
    use openpgp::crypto::S2K;
    use openpgp::packet::key::SecretKeyMaterial;

    rnp_function!(rnp_key_get_protection_type, crate::TRACE);
    let key = assert_ptr_mut!(key);
    let typ = assert_ptr_mut!(typ);

    let r_typ = if (*(*key).ctx).certs.key_on_agent(&(*key).fingerprint()) {
        // The secret key material is available, but we have no idea
        // how it is protected (it's unclear why this is even
        // relevant!).  But, if we don't return something that
        // suggests that the secret key material is available
        // *locally*, then Thunderbird will decide the key doesn't
        // really have secret key material (even if
        // rnp_key_have_secret returns true :/).  So, we just say that
        // the secret key material is unencrypted.
        "None"
    } else if let Ok(key) = key.parts_as_secret() {
        match key.secret() {
            SecretKeyMaterial::Unencrypted(_) => "None",
            SecretKeyMaterial::Encrypted(e) => {
                #[allow(deprecated)]
                match e.s2k() {
                    S2K::Iterated { .. } => "Encrypted-Hashed",
                    S2K::Salted { .. } => "Encrypted",
                    S2K::Simple { .. } => "Encrypted",
                    S2K::Private { tag: 101, parameters } =>
                        if let Some(parameters) = parameters {
                            match parameters.get(0) {
                                Some(0) => // PGP_S2K_GPG_NONE
                                    "Unknown",
                                Some(1) => // PGP_S2K_GPG_NO_SECRET
                                    "GPG-None",
                                Some(2) => // PGP_S2K_GPG_SMARTCARD
                                    "GPG-Smartcard",
                                _ =>
                                    "Unknown",
                            }
                        } else {
                            "Unknown"
                        },
                    _ => "Unknown",
                }
            }
        }
    } else {
        "Unknown"
    };

    t!("returning {:?}", r_typ);
    *typ = str_to_rnp_buffer(r_typ);

    rnp_success!()
}

#[no_mangle] pub unsafe extern "C"
fn rnp_key_protect(rnp_key: *mut RnpKey,
                   password: *const c_char,
                   cipher: *const c_char,
                   cipher_mode: *const c_char,
                   hash: *const c_char,
                   iterations: size_t)
                   -> RnpResult {
    rnp_function!(rnp_key_protect, crate::TRACE);
    let rnp_key = assert_ptr_mut!(rnp_key);
    let password = assert_str!(confidential => password);
    arg!(cipher);
    arg!(cipher_mode);
    arg!(hash);
    arg!(iterations);
    let fp = rnp_key.fingerprint();

    let ctx = &mut *rnp_key.ctx;
    let mut key =
        if let Ok(key) = rnp_key.key.clone().parts_into_secret() {
            key
        } else if ctx.certs.key_on_agent(&fp) {
            // The secret key material is managed by the gpg-agent, we
            // cannot change the password, nor should we try to.  Just
            // turn this into a NOP.
            rnp_return_status!(RNP_SUCCESS);
        } else {
            rnp_return_status!(RNP_ERROR_NO_SUITABLE_KEY);
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

            *cert = cert.clone().insert_packets(Some(key))?.0;
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
        arg!(password);
        None
    } else {
        arg!("<REDACTED>");
        Some(rnp_try!(cstr_to_str(password)))
    };
    t!("password = {:?}",
       if password.is_some() { "Something" } else { "None" });

    let ctx = &mut *rnp_key.ctx;
    let mut key =
        if let Ok(key) = rnp_key.key.clone().parts_into_secret() {
            key
        } else if ctx.certs.key_on_agent(&fp) {
            // The secret key material is managed by the gpg-agent, we
            // cannot change the password, nor should we try to.  Just
            // turn this into a NOP.
            rnp_return_status!(RNP_SUCCESS);
        } else {
            rnp_return_status!(RNP_ERROR_NO_SUITABLE_KEY);
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

            *cert = cert.clone().insert_packets(Some(key))?.0;
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
                             flags: u32,
                             hash: *const c_char,
                             code: *const c_char,
                             reason: *const c_char)
                             -> RnpResult {
    rnp_function!(rnp_key_export_revocation, crate::TRACE);
    let key = assert_ptr_mut!(key);
    let output = assert_ptr_mut!(output);
    arg!(flags);

    let hash = if hash.is_null() {
        arg!(hash);
        None
    } else {
        let hash = assert_str!(hash);
        Some(rnp_try!(HashAlgorithm::from_rnp_id(hash)))
    };

    let code = if code.is_null() {
        arg!(code);
        ReasonForRevocation::Unspecified
    } else {
        let code = assert_str!(code);
        rnp_try!(ReasonForRevocation::from_rnp_id(code))
    };

    let reason = if reason.is_null() {
        b""
    } else {
        assert_str!(reason).as_bytes()
    };

    if ! rnp_try!(key.is_primary()) {
        rnp_return_status!(RNP_ERROR_BAD_PARAMETERS);
    }

    if ! key.has_secret() {
        warn!("rnp_key_export_revocation: creating third-party revocation \
               not implemented");
        rnp_return_status!(RNP_ERROR_NOT_IMPLEMENTED);
    }

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

    rnp_return_status!(if let Err(e) = f(key, output, hash, code, reason) {
        warn!("rnp_key_export_revocation: {}", e);
        RNP_ERROR_GENERIC
    } else {
        RNP_SUCCESS
    })
}

#[no_mangle] pub unsafe extern "C"
fn rnp_key_revoke(key: *mut RnpKey,
                  flags: u32,
                  hash: *const c_char,
                  code: *const c_char,
                  reason: *const c_char)
                  -> RnpResult {
    rnp_function!(rnp_key_revoke, crate::TRACE);
    let key = assert_ptr_mut!(key);
    arg!(flags);
    let ctx = &mut *key.ctx;

    let hash = if hash.is_null() {
        arg!(hash);
        None
    } else {
        let hash = assert_str!(hash);
        Some(rnp_try!(HashAlgorithm::from_rnp_id(hash)))
    };

    let code = if code.is_null() {
        arg!(code);
        ReasonForRevocation::Unspecified
    } else {
        let code = assert_str!(code);
        rnp_try!(ReasonForRevocation::from_rnp_id(code))
    };

    let reason = if reason.is_null() {
        b""
    } else {
        assert_str!(reason).as_bytes()
    };

    let cert = if let Some(cert) = key.cert() {
        cert.clone()
    } else {
        rnp_return_status!(RNP_ERROR_NO_SUITABLE_KEY);
    };

    if ! cert.primary_key().key().has_secret() {
        warn!("rnp_key_export_revocation: creating third-party revocation \
               not implemented");
        rnp_return_status!(RNP_ERROR_NOT_IMPLEMENTED);
    }

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
        ctx.certs.write().insert(cert.insert_packets(Some(sig))?.0);
        Ok(())
    }

    rnp_return_status!(if let Err(e) = f(ctx, cert, key, hash, code, reason) {
        warn!("{}", e);
        RNP_ERROR_GENERIC
    } else {
        RNP_SUCCESS
    })
}

/// Returns how long to wait at `now` until a signature can be made
/// that is newer than one made at `superseded`.
///
/// The creation time of a signature has a resolution of one second.
/// Returns `None` if a signature made at `now` is newer than one made
/// at `superseded`.  Also returns `None` if `superseded` is ahead of
/// `now`, which means that the clock was set back: we never wait for
/// more than a second.
fn time_to_supersede(superseded: SystemTime, now: SystemTime)
                     -> Option<Duration>
{
    let second = Duration::new(1, 0);
    match superseded.checked_add(second)?.duration_since(now) {
        Ok(d) if d > Duration::new(0, 0) && d <= second => Some(d),
        _ => None,
    }
}

/// Makes sure that a signature made from now on is newer than the
/// given signatures, by waiting for the next second if necessary.
///
/// Sequoia uses the newest self signature, and if two have the same
/// creation time, which one it uses depends on the signatures'
/// values.  A new self signature must therefore be strictly newer
/// than the one it supersedes, or it takes effect only by chance.
fn wait_to_supersede<'a, I>(sigs: I)
    where I: Iterator<Item = &'a Signature>
{
    let superseded = if let Some(t) = sigs
        .filter_map(|sig| sig.signature_creation_time())
        .max()
    {
        t
    } else {
        return;
    };

    // The clock may be set while we wait, so look at it again
    // afterwards, but don't insist.
    for _ in 0..2 {
        if let Some(d) = time_to_supersede(superseded, SystemTime::now()) {
            std::thread::sleep(d);
        } else {
            break;
        }
    }
}

#[no_mangle] pub unsafe extern "C"
fn rnp_key_set_expiration(key: *mut RnpKey,
                          expiry: u32)
                          -> RnpResult {
    rnp_function!(rnp_key_set_expiration, crate::TRACE);
    let key = assert_ptr_mut!(key);
    arg!(expiry);
    let ctx = &mut *key.ctx;

    let expiry = if expiry == 0 {
        None
    } else {
        Some(Duration::new(expiry as u64, 0))
    };

    let cert = if let Some(cert) = key.cert() {
        cert.clone()
    } else {
        rnp_return_status!(RNP_ERROR_NO_SUITABLE_KEY);
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
                warn!("Cannot change expiration time without \
                        primary secret: {}", e);
                return Err(e);
            },
        };

        let policy = ctx.policy().clone();
        let vcert = cert.with_policy(&policy, None)?;
        let sigs = if is_primary {
            // The new signatures supersede the direct key signature
            // and the binding signatures of the user IDs that are not
            // revoked.
            let primary = vcert.primary_key();
            wait_to_supersede(
                primary.direct_key_signature().ok().into_iter()
                    .chain(vcert.userids().revoked(false)
                           .map(|ua| ua.binding_signature())));

            primary
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
                            warn!("Cannot change expiration time without \
                                    subkey secret: {}", e);
                            return Err(e);
                        },
                    }
                } else {
                    None
                };

            // The new signature supersedes the subkey's binding
            // signature.
            wait_to_supersede(std::iter::once(vka.binding_signature()));

            vka.set_expiration_time(
                &mut primary_signer,
                subkey_signer.as_mut()
                    .map(|pair| -> &mut dyn openpgp::crypto::Signer {
                        &mut *pair
                    }),
                absolute_expiration_time)?
        };

        // Merge the updated cert into the store.
        ctx.certs.write().insert(cert.insert_packets(sigs)?.0);
        Ok(())
    }

    rnp_return_status!(if let Err(e) = f(ctx, cert, key, expiry) {
        warn!("{}", e);
        RNP_ERROR_GENERIC
    } else {
        RNP_SUCCESS
    })
}

#[no_mangle] pub unsafe extern "C"
fn rnp_key_valid_till(key: *mut RnpKey,
                      result: *mut u32)
                      -> RnpResult {
    rnp_function!(rnp_key_valid_till, crate::TRACE);
    let result = assert_ptr_mut!(result);

    // The key expiration time is a 33-bit number, but the
    // RNP API only has place for a 32-bit number :/.
    let mut till = 0;
    let r = rnp_key_valid_till64(key, &mut till as *mut _);
    *result = min(u32::MAX as u64, till) as u32;
    r
}

#[no_mangle] pub unsafe extern "C"
fn rnp_key_valid_till64(key: *mut RnpKey,
                        result: *mut u64)
                        -> RnpResult {
    rnp_function!(rnp_key_valid_till64, crate::TRACE);
    let key = assert_ptr_mut!(key);
    let result = assert_ptr_mut!(result);

    // We need to clone it, because key.cert() takes a &mut.
    let k = key.key.clone().parts_into_public();
    let cert = if let Some(cert) = key.cert() {
        cert
    } else {
        t!("Could not find key's certificate.");
        rnp_return_status!(RNP_ERROR_BAD_PARAMETERS);
    };

    // According to the rnp_key_valid_till's documentation
    // (https://github.com/rnpgp/rnp/blob/7b636f1/include/rnp/rnp.h#L1518),
    // this function returns 0 if the key was never valid.  Otherwise,
    // it returns the minimum of the expiration and revocation time.
    //
    // Thunderbird only checks if the result is 0, and if so does not
    // show the key in the OpenPGP Key Manager.  So, if a key was
    // *ever* valid, then we should return a non-zero result.  This
    // means we want the Null policy (there is a cryptographically
    // valid signature), not the Standard Policy, which is stricter.
    let vc = if let Ok(vc) = cert.with_policy(crate::NP, None) {
        vc
    } else {
        // If it is not even valid with the null policy, return 0.
        *result = 0;
        t!("cert not valid.");
        rnp_return_status!(RNP_SUCCESS);
    };

    // Make sure the key is valid.
    let ka = if let Some(ka) = vc.keys().filter(|ka| *ka.key() == k).nth(0) {
        ka
    } else {
        // If it is not even valid with the null policy, return 0.
        *result = 0;
        t!("key not valid.");
        rnp_return_status!(RNP_SUCCESS);
    };

    // A key's expiration is the minimum of its expiration
    // and the primary key's expiration.

    let t_min = |a, b| {
        match (a, b) {
            (Some(p), Some(s)) => Some(min(p, s)),
            (None, Some(s)) => Some(s),
            (Some(p), None) => Some(p),
            (None, None) => None,
        }
    };

    // Recall: None means the key doesn't expire.
    let mut t = t_min(vc.primary_key().key_expiration_time(),
                      ka.key_expiration_time());

    if let RevocationStatus::CouldBe(revs) = vc.revocation_status() {
        t = revs.into_iter().fold(t, |t, rev| {
            t_min(t, rev.signature_creation_time())
        });
    };
    if let RevocationStatus::CouldBe(revs) = ka.revocation_status() {
        t = revs.into_iter().fold(t, |t, rev| {
            t_min(t, rev.signature_creation_time())
        });
    };

    if let Ok(unix) = t
        .unwrap_or(std::time::UNIX_EPOCH + Duration::new(u32::MAX as u64, 0))
        .duration_since(std::time::UNIX_EPOCH)
    {
        *result = unix.as_secs();
        t!("valid till: {}", *result);
    } else {
        // Ummm... this shouldn't happen, but if it does
        // conservatively consider the key to be invalid.
        *result = 0;
        t!("time failure.");
    }
    rnp_success!()
}

#[no_mangle] pub unsafe extern "C"
fn rnp_key_25519_bits_tweaked(key: *mut RnpKey, result_out: *mut bool)
                              -> RnpResult {
    rnp_function!(rnp_key_25519_bits_tweaked, crate::TRACE);
    let key = assert_ptr_mut!(key);
    let ctx = &mut *key.ctx;
    let result_out = assert_ptr_mut!(result_out);

    // First, check that we are a Curve25519 key.
    use openpgp::crypto::mpi::PublicKey;
    match key.key.mpis() {
        | PublicKey::ECDH { curve, .. } => {
            use openpgp::types::Curve::*;
            // We want to return an error on unknown curves.
            match curve {
                Cv25519 => (),
                _ => rnp_return_status!(RNP_ERROR_BAD_PARAMETERS),
            };
        },
        // Not an ECC algorithm.
        _ => rnp_return_status!(RNP_ERROR_BAD_PARAMETERS),
    }

    // RNP's implementation also considers unlocked keys.  Do the
    // same.
    let maybe_unlocked_key = ctx.key_unlocked_ref(&key.key)
        .map(|k| k.parts_as_unspecified())
        .unwrap_or(&key.key);

    // Now check the secret.
    use openpgp::packet::key;
    rnp_return_status!(match maybe_unlocked_key.optional_secret() {
        Some(key::SecretKeyMaterial::Unencrypted(k)) => k.map(|secret| {
            use openpgp::crypto::mpi::SecretKeyMaterial;
            match secret {
                SecretKeyMaterial::ECDH { scalar } => {
                    // OpenPGP stores the secret in reverse order.
                    const CURVE25519_SIZE: usize = 32;
                    const FIRST: usize = CURVE25519_SIZE - 1;
                    const LAST: usize = 0;

                    // Curve25519 Paper, Sec. 3: A user can, for
                    // example, generate 32 uniform random bytes,
                    // clear bits 0, 1, 2 of the first byte, clear bit
                    // 7 of the last byte, and set bit 6 of the last
                    // byte.
                    let scalar = scalar.value_padded(CURVE25519_SIZE);
                    *result_out =
                        scalar[FIRST] & !0b1111_1000 == 0
                        && scalar[LAST] & 0b1000_0000 == 0
                        && scalar[LAST] & 0b0100_0000 == 0b0100_0000;
                    RNP_SUCCESS

                },
                _ => RNP_ERROR_BAD_PARAMETERS,
            }
        }),
        _ => RNP_ERROR_BAD_PARAMETERS,
    })
}

#[no_mangle] pub unsafe extern "C"
fn rnp_key_25519_bits_tweak(key: *mut RnpKey)
                            -> RnpResult {
    rnp_function!(rnp_key_25519_bits_tweak, crate::TRACE);
    let key = assert_ptr_mut!(key);

    // First, check that we are a Curve25519 key.
    use openpgp::crypto::mpi::PublicKey;
    match key.key.mpis() {
        | PublicKey::ECDH { curve, .. } => {
            use openpgp::types::Curve::*;
            // We want to return an error on unknown curves.
            match curve {
                Cv25519 => (),
                _ => rnp_return_status!(RNP_ERROR_BAD_PARAMETERS),
            };
        },
        // Not an ECC algorithm.
        _ => rnp_return_status!(RNP_ERROR_BAD_PARAMETERS),
    }

    // Now check and clone the secret.
    const CURVE25519_SIZE: usize = 32;
    use openpgp::packet::key;
    use openpgp::crypto::mpi;
    let mut secret =
        match key.key.optional_secret() {
            Some(key::SecretKeyMaterial::Unencrypted(k)) =>
                rnp_try!(k.map(|secret| {
                    match secret {
                        mpi::SecretKeyMaterial::ECDH { scalar } =>
                            Ok(scalar.value_padded(CURVE25519_SIZE)),
                        _ => Err(RNP_ERROR_BAD_PARAMETERS),
                    }
                })),
            _ => rnp_return_status!(RNP_ERROR_BAD_PARAMETERS),
        };

    // OpenPGP stores the secret in reverse order.
    const FIRST: usize = CURVE25519_SIZE - 1;
    const LAST: usize = 0;

    // Curve25519 Paper, Sec. 3: A user can, for example, generate 32
    // uniform random bytes, clear bits 0, 1, 2 of the first byte,
    // clear bit 7 of the last byte, and set bit 6 of the last byte.
    secret[FIRST] &= 0b1111_1000;
    secret[LAST] &= !0b1000_0000;
    secret[LAST] |= 0b0100_0000;

    // Finally, replace the secret in the key.
    key.key = key.key.clone().add_secret(
        key::SecretKeyMaterial::Unencrypted(
            mpi::SecretKeyMaterial::ECDH { scalar: secret.into(), }
            .into()))
        .0.parts_into_unspecified();

    // And update the cert.
    let k = key.key.clone().parts_into_secret().unwrap();
    if let Some(mut cert) = key.cert_mut() {
        let key: openpgp::Packet =
            if k.fingerprint() == cert.fingerprint() {
                k.role_into_primary().into()
            } else {
                k.role_into_subordinate().into()
            };

        *cert = rnp_try_or!(cert.clone().insert_packets(Some(key)),
                            RNP_ERROR_GENERIC).0;
        rnp_success!()
    } else {
        warn!("Key for {:X} not found in keyring", k.fingerprint());
        rnp_return_status!(RNP_ERROR_GENERIC)
    }
}

/// Removes the given UID from KEY.
#[no_mangle] pub unsafe extern "C"
fn rnp_uid_remove(key: *mut RnpKey, uid: *mut RnpUserID)
                  -> RnpResult {
    rnp_function!(rnp_uid_remove, crate::TRACE);
    let key = assert_ptr_mut!(key);
    let uid = assert_ptr_ref!(uid);

    rnp_return_status!(if let Some(mut cert) = key.cert_mut() {
        *cert = cert.clone().retain_userids(|u| u.userid() != uid.userid());
        RNP_SUCCESS
    } else {
        RNP_ERROR_GENERIC
    })
}

type RnpKeySignaturesCB = fn(*mut RnpContext,
                             *mut c_void,
                             *mut RnpSignature,
                             *mut RnpKeyRemoveSignatureAction);

/// Removes signatures from KEY.
#[no_mangle] pub unsafe extern "C"
fn rnp_key_remove_signatures(key: *mut RnpKey,
                             flags: RnpKeyRemoveSignatureFlags,
                             pred: *mut RnpKeySignaturesCB,
                             cookie: *mut c_void)
                             -> RnpResult {
    rnp_function!(rnp_key_remove_signatures, crate::TRACE);
    let key = assert_ptr_mut!(key);
    arg!(flags);
    arg!(pred);
    arg!(cookie);

    let remove_invalid = flags & RNP_KEY_SIGNATURE_INVALID > 0;
    if remove_invalid {
        warn!("Flag RNP_KEY_SIGNATURE_INVALID not implemented, ignoring.");
    }
    let remove_unknown_key = flags & RNP_KEY_SIGNATURE_UNKNOWN_KEY > 0;
    if remove_unknown_key {
        warn!("Flag RNP_KEY_SIGNATURE_UNKNOWN_KEY not implemented, ignoring.");
    }
    let remove_non_selfsig = flags & RNP_KEY_SIGNATURE_NON_SELF_SIG > 0;

    if ! pred.is_null() {
        warn!("Predicate parameter not implemented, ignoring.");
    }

    if let Some(mut cert) = key.cert_mut() {
        let mut acc = Vec::new();

        // The primary key and related signatures.
        let pk_bundle = cert.primary_key().bundle();
        acc.push(pk_bundle.key().clone().into());
        for s in pk_bundle.self_signatures() { acc.push(s.clone().into()); }
        for s in pk_bundle.self_revocations()  { acc.push(s.clone().into()); }
        if ! remove_non_selfsig {
            for s in pk_bundle.other_revocations() { acc.push(s.clone().into()); }
            for s in pk_bundle.certifications() { acc.push(s.clone().into()); }
        }

        // The subkeys and related signatures.
        for skb in cert.keys().subkeys() {
            acc.push(skb.key().clone().into());
            for s in skb.self_signatures()   { acc.push(s.clone().into()); }
            for s in skb.self_revocations()  { acc.push(s.clone().into()); }
            if ! remove_non_selfsig {
                for s in skb.other_revocations() { acc.push(s.clone().into()); }
                for s in skb.certifications() { acc.push(s.clone().into()); }
            }
        }

        // The UserIDs.
        for uidb in cert.userids() {
            acc.push(uidb.userid().clone().into());
            for s in uidb.self_signatures()   { acc.push(s.clone().into()); }
            for s in uidb.self_revocations()  { acc.push(s.clone().into()); }
            for s in uidb.approvals()         { acc.push(s.clone().into()); }
            if ! remove_non_selfsig {
                for s in uidb.other_revocations() { acc.push(s.clone().into()); }
                for s in uidb.certifications() { acc.push(s.clone().into()); }
            }
        }

        // The UserAttributes.
        for uab in cert.user_attributes() {
            acc.push(uab.user_attribute().clone().into());
            for s in uab.self_signatures()   { acc.push(s.clone().into()); }
            for s in uab.self_revocations()  { acc.push(s.clone().into()); }
            for s in uab.approvals()         { acc.push(s.clone().into()); }
            if ! remove_non_selfsig {
                for s in uab.other_revocations() { acc.push(s.clone().into()); }
                for s in uab.certifications() { acc.push(s.clone().into()); }
            }
        }

        // The components that we do not understand, e.g. a secret
        // subkey using an algorithm that we do not know.  We must
        // not drop them just because signatures are removed.  Their
        // self-signatures cannot be verified, they are among the bad
        // signatures.
        for ub in cert.unknowns() {
            acc.push(ub.unknown().clone().into());
            if ! remove_non_selfsig {
                for s in ub.other_revocations() { acc.push(s.clone().into()); }
                for s in ub.certifications() { acc.push(s.clone().into()); }
            }
        }

        if ! remove_invalid {
            for s in cert.bad_signatures() { acc.push(s.clone().into()); }
        }

        *cert = rnp_try_or!(Cert::from_packets(acc.into_iter()),
                            RNP_ERROR_GENERIC);
        rnp_success!()
    } else {
        rnp_return_status!(RNP_ERROR_GENERIC)
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use libc::c_char;
    use std::ffi::CString;

    use sequoia_openpgp::serialize::SerializeInto;

    use crate::rnp_ffi_create;
    use crate::io::RnpInput;
    use crate::import::rnp_import_keys;
    use crate::rnp_output_to_memory;
    use crate::rnp_output_memory_get_buf;
    use crate::rnp_input_from_memory;
    use crate::rnp_input_destroy;
    use crate::rnp_output_destroy;
    use crate::rnp_ffi_destroy;

    const RNP_SUCCESS: u32 = crate::error::RNP_SUCCESS.as_u32();

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
                                   CString::new(k.key().fingerprint().to_string())
                                   .unwrap().into_raw() as *const c_char,
                                   &mut key as *mut *mut _)
                };
                assert_eq!(r, RNP_SUCCESS);

                if let Some(old_c) = old_c {
                    let r = unsafe { rnp_key_unprotect(key, old_c) };
                    if r != RNP_SUCCESS {
                        return Err(anyhow::anyhow!("Failed to change password"));
                    }
                    log!("After unprotecting {} with {}",
                         k.key().fingerprint(), old.unwrap());
                    crate::cert_dump(
                        &unsafe { &mut *ctx }
                            .certs.read()
                            .by_primary_fp(&cert.fingerprint()).unwrap());
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
                    log!("After protecting {} with {}",
                         k.key().fingerprint(), new.unwrap());
                    crate::cert_dump(
                        &unsafe { &mut *ctx }
                            .certs.read()
                            .by_primary_fp(&cert.fingerprint()).unwrap());
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

        log!("ctx: keystore: {:?}", unsafe { &mut *ctx }.certs);

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

    #[test]
    fn curve25519_secret_tweaking() {
        fn test(buffer: &[u8]) {
            let mut ctx: *mut RnpContext = std::ptr::null_mut();
            let r = unsafe {
                rnp_ffi_create(
                    &mut ctx as *mut *mut _,
                    b"GPG\x00".as_ptr() as *const c_char,
                    b"GPG\x00".as_ptr() as *const c_char)
            };
            assert_eq!(r, RNP_SUCCESS);

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

            log!("ctx: keystore: {:?}", unsafe { &mut *ctx }.certs);

            let mut key: *mut RnpKey = std::ptr::null_mut();
            let r = unsafe {
                rnp_locate_key(
                    ctx,
                    b"fingerprint\x00".as_ptr()
                        as *const c_char,
                    b"EA02B24FFD4C1B96616D3DF24766F6B9D5F21EB6\x00".as_ptr()
                        as *const c_char,
                    &mut key as *mut *mut _)
            };
            assert_eq!(r, RNP_SUCCESS);

            let mut result = false;
            let r = unsafe {
                rnp_key_25519_bits_tweaked(key, &mut result)
            };
            assert_eq!(r, RNP_SUCCESS);
            assert_eq!(result, false);

            let r = unsafe {
                rnp_key_25519_bits_tweak(key)
            };
            assert_eq!(r, RNP_SUCCESS);

            // Check modification against reference.
            let reference = b"-----BEGIN PGP PRIVATE KEY BLOCK-----
Comment: EB85 BB5F A33A 75E1 5E94  4E63 F231 550C 4F47 E38E
Comment: Alice Lovelace <alice@openpgp.example>

xVgEXEcE6RYJKwYBBAHaRw8BAQdArjWwk3FAqyiFbFBKT4TzXcVBqPTB3gmzlC/U
b7O1u10AAP9XBeW6lzGOLx7zHH9AsUDUTb2pggYGMzd0P3ulJ2AfvQ4RzSZBbGlj
ZSBMb3ZlbGFjZSA8YWxpY2VAb3BlbnBncC5leGFtcGxlPsKQBBMWCAA4AhsDBQsJ
CAcCBhUKCQgLAgQWAgMBAh4BAheAFiEE64W7X6M6deFelE5j8jFVDE9H444FAl2l
nzoACgkQ8jFVDE9H447pKwD6A5xwUqIDprBzrHfahrImaYEZzncqb25vkLV2arYf
a78A/R3AwtLQvjxwLDuzk4dUtUwvUYibL2sAHwj2kGaHnfICx10EXEcE6RIKKwYB
BAGXVQEFAQEHQEL/BiGtq0k84Km1wqQw2DIikVYrQrMttN8d7BPfnr4iAwEIBwAA
/3/xFPG6U17rhTuq+07gmEvaFYKfxRB6sgAYiW6TMTpQEK7CeAQYFggAIBYhBOuF
u1+jOnXhXpROY/IxVQxPR+OOBQJcRwTpAhsMAAoJEPIxVQxPR+OOWdABAMUdSzpM
hzGs1O0RkWNQWbUzQ8nUOeD9wNbjE3zR+yfRAQDbYqvtWQKN4AQLTxVJN5X5AWyb
Pnn+We1aTBhaGa86AQ==
=3GfK
-----END PGP PRIVATE KEY BLOCK-----
";
            use openpgp::parse::Parse;
            let reference_cert =
                openpgp::Cert::from_bytes(reference).unwrap();
            unsafe {
                use std::ops::Deref;
                assert_eq!(
                    (*key).cert.as_ref().unwrap().as_ref()
                    .read().unwrap().deref(),
                    &reference_cert);
            }

            let mut result = false;
            let r = unsafe {
                rnp_key_25519_bits_tweaked(key, &mut result)
            };
            assert_eq!(r, RNP_SUCCESS);
            assert_eq!(result, true);

            let r = unsafe {
                rnp_key_handle_destroy(key)
            };
            assert_eq!(r, RNP_SUCCESS);

            let r = unsafe {
                rnp_ffi_destroy(ctx)
            };
            assert_eq!(r, RNP_SUCCESS);
        }

        // Secret with LSB set.
        test(b"-----BEGIN PGP PRIVATE KEY BLOCK-----

xVgEXEcE6RYJKwYBBAHaRw8BAQdArjWwk3FAqyiFbFBKT4TzXcVBqPTB3gmzlC/U
b7O1u10AAP9XBeW6lzGOLx7zHH9AsUDUTb2pggYGMzd0P3ulJ2AfvQ4RzSZBbGlj
ZSBMb3ZlbGFjZSA8YWxpY2VAb3BlbnBncC5leGFtcGxlPsKQBBMWCAA4AhsDBQsJ
CAcCBhUKCQgLAgQWAgMBAh4BAheAFiEE64W7X6M6deFelE5j8jFVDE9H444FAl2l
nzoACgkQ8jFVDE9H447pKwD6A5xwUqIDprBzrHfahrImaYEZzncqb25vkLV2arYf
a78A/R3AwtLQvjxwLDuzk4dUtUwvUYibL2sAHwj2kGaHnfICx10EXEcE6RIKKwYB
BAGXVQEFAQEHQEL/BiGtq0k84Km1wqQw2DIikVYrQrMttN8d7BPfnr4iAwEIBwAA
/3/xFPG6U17rhTuq+07gmEvaFYKfxRB6sgAYiW6TMTpREK/CeAQYFggAIBYhBOuF
u1+jOnXhXpROY/IxVQxPR+OOBQJcRwTpAhsMAAoJEPIxVQxPR+OOWdABAMUdSzpM
hzGs1O0RkWNQWbUzQ8nUOeD9wNbjE3zR+yfRAQDbYqvtWQKN4AQLTxVJN5X5AWyb
Pnn+We1aTBhaGa86AQ==
=iQ01
-----END PGP PRIVATE KEY BLOCK-----
");
        // Secret with MSB set.
        test(b"-----BEGIN PGP PRIVATE KEY BLOCK-----

xVgEXEcE6RYJKwYBBAHaRw8BAQdArjWwk3FAqyiFbFBKT4TzXcVBqPTB3gmzlC/U
b7O1u10AAP9XBeW6lzGOLx7zHH9AsUDUTb2pggYGMzd0P3ulJ2AfvQ4RzSZBbGlj
ZSBMb3ZlbGFjZSA8YWxpY2VAb3BlbnBncC5leGFtcGxlPsKQBBMWCAA4AhsDBQsJ
CAcCBhUKCQgLAgQWAgMBAh4BAheAFiEE64W7X6M6deFelE5j8jFVDE9H444FAl2l
nzoACgkQ8jFVDE9H447pKwD6A5xwUqIDprBzrHfahrImaYEZzncqb25vkLV2arYf
a78A/R3AwtLQvjxwLDuzk4dUtUwvUYibL2sAHwj2kGaHnfICx10EXEcE6RIKKwYB
BAGXVQEFAQEHQEL/BiGtq0k84Km1wqQw2DIikVYrQrMttN8d7BPfnr4iAwEIBwAB
AP/xFPG6U17rhTuq+07gmEvaFYKfxRB6sgAYiW6TMTpQEDDCeAQYFggAIBYhBOuF
u1+jOnXhXpROY/IxVQxPR+OOBQJcRwTpAhsMAAoJEPIxVQxPR+OOWdABAMUdSzpM
hzGs1O0RkWNQWbUzQ8nUOeD9wNbjE3zR+yfRAQDbYqvtWQKN4AQLTxVJN5X5AWyb
Pnn+We1aTBhaGa86AQ==
=YOA6
-----END PGP PRIVATE KEY BLOCK-----
");

        // Secret with 2^254 bit cleared.
        test(b"-----BEGIN PGP PRIVATE KEY BLOCK-----

xVgEXEcE6RYJKwYBBAHaRw8BAQdArjWwk3FAqyiFbFBKT4TzXcVBqPTB3gmzlC/U
b7O1u10AAP9XBeW6lzGOLx7zHH9AsUDUTb2pggYGMzd0P3ulJ2AfvQ4RzSZBbGlj
ZSBMb3ZlbGFjZSA8YWxpY2VAb3BlbnBncC5leGFtcGxlPsKQBBMWCAA4AhsDBQsJ
CAcCBhUKCQgLAgQWAgMBAh4BAheAFiEE64W7X6M6deFelE5j8jFVDE9H444FAl2l
nzoACgkQ8jFVDE9H447pKwD6A5xwUqIDprBzrHfahrImaYEZzncqb25vkLV2arYf
a78A/R3AwtLQvjxwLDuzk4dUtUwvUYibL2sAHwj2kGaHnfICx10EXEcE6RIKKwYB
BAGXVQEFAQEHQEL/BiGtq0k84Km1wqQw2DIikVYrQrMttN8d7BPfnr4iAwEIBwAA
/j/xFPG6U17rhTuq+07gmEvaFYKfxRB6sgAYiW6TMTpQEG3CeAQYFggAIBYhBOuF
u1+jOnXhXpROY/IxVQxPR+OOBQJcRwTpAhsMAAoJEPIxVQxPR+OOWdABAMUdSzpM
hzGs1O0RkWNQWbUzQ8nUOeD9wNbjE3zR+yfRAQDbYqvtWQKN4AQLTxVJN5X5AWyb
Pnn+We1aTBhaGa86AQ==
=Txnk
-----END PGP PRIVATE KEY BLOCK-----
");
    }

    #[test]
    fn find_cert() -> anyhow::Result<()> {
        // Create a key.
        let (alice, _) = openpgp::cert::CertBuilder::new()
            .add_userid("alice")
            .add_signing_subkey()
            .generate()?;

        // Import it into the context.
        let buffer = alice.to_vec()?;

        for strip_secrets in [false, true] {
            eprintln!("stripping secrets {:?}", strip_secrets);

            let mut ctx: *mut RnpContext = std::ptr::null_mut();
            let r = unsafe {
                rnp_ffi_create(
                    &mut ctx as *mut *mut _,
                    b"GPG\x00".as_ptr() as *const c_char,
                    b"GPG\x00".as_ptr() as *const c_char)
            };
            assert_eq!(r, RNP_SUCCESS);

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

            log!("ctx: keystore: {:?}", unsafe { &mut *ctx }.certs);

            for (i, key) in alice.keys().enumerate() {
                eprintln!("{}. {}...", i, key.key().fingerprint());
                let key = key.key().clone();
                let key = if strip_secrets {
                    key.take_secret().0
                        .parts_into_unspecified().role_into_unspecified()
                } else {
                    key.parts_into_unspecified().role_into_unspecified()
                };

                let rnp_key = RnpKey::without_cert(ctx, key);
                assert_eq!(rnp_key.cert.unwrap().read().unwrap().fingerprint(),
                           alice.fingerprint());
            }

            let r = unsafe {
                rnp_ffi_destroy(ctx)
            };
            assert_eq!(r, RNP_SUCCESS);
        }

        Ok(())
    }

    const RNP_ERROR_NULL_POINTER: u32 =
        crate::error::RNP_ERROR_NULL_POINTER.as_u32();

    /// Creates a context and imports the certificates.
    fn ctx_with_certs(certs: &[&Cert]) -> *mut RnpContext {
        let mut ctx: *mut RnpContext = std::ptr::null_mut();
        let r = unsafe {
            rnp_ffi_create(
                &mut ctx as *mut *mut _,
                b"GPG\x00".as_ptr() as *const c_char,
                b"GPG\x00".as_ptr() as *const c_char)
        };
        assert_eq!(r, RNP_SUCCESS);

        for cert in certs {
            let buffer = cert.to_vec().unwrap();
            let mut input: *mut RnpInput = std::ptr::null_mut();
            let r = unsafe {
                rnp_input_from_memory(
                    &mut input as *mut *mut _,
                    buffer.as_ptr(), buffer.len(), false)
            };
            assert_eq!(r, RNP_SUCCESS);

            let r = unsafe {
                rnp_import_keys(
                    ctx, input,
                    RNP_LOAD_SAVE_PUBLIC_KEYS,
                    std::ptr::null_mut() as *mut *mut _)
            };
            assert_eq!(r, RNP_SUCCESS);

            let r = unsafe { rnp_input_destroy(input) };
            assert_eq!(r, RNP_SUCCESS);
        }

        ctx
    }

    /// Looks up the key by its fingerprint.
    fn locate(ctx: *mut RnpContext, fp: &openpgp::Fingerprint)
              -> *mut RnpKey
    {
        let fp = CString::new(fp.to_hex()).unwrap();
        let mut key: *mut RnpKey = std::ptr::null_mut();
        let r = unsafe {
            rnp_locate_key(ctx,
                           b"fingerprint\x00".as_ptr() as *const c_char,
                           fp.as_ptr(),
                           &mut key as *mut *mut _)
        };
        assert_eq!(r, RNP_SUCCESS);
        assert!(! key.is_null());
        key
    }

    /// Returns the key's revocation signature, which may be NULL.
    fn revocation_signature(key: *mut RnpKey) -> *mut RnpSignature {
        // Initialize it with something that is not NULL so that we
        // notice that the function stores NULL.
        let mut sig = std::ptr::NonNull::<RnpSignature>::dangling().as_ptr();
        let r = unsafe {
            rnp_key_get_revocation_signature(key, &mut sig as *mut *mut _)
        };
        assert_eq!(r, RNP_SUCCESS);
        sig
    }

    /// Returns whether the key is revoked according to
    /// rnp_key_is_revoked.
    fn is_revoked(key: *mut RnpKey) -> bool {
        let mut revoked = false;
        let r = unsafe { rnp_key_is_revoked(key, &mut revoked as *mut _) };
        assert_eq!(r, RNP_SUCCESS);
        revoked
    }

    /// Returns the code and the text of the signature's reason for
    /// revocation.
    fn get_revocation_reason(sig: *mut RnpSignature) -> (String, Vec<u8>) {
        use std::ffi::CStr;
        use crate::signature::rnp_signature_get_revocation_reason;

        let mut code: *mut c_char = std::ptr::null_mut();
        let mut reason: *mut c_char = std::ptr::null_mut();
        let r = unsafe {
            rnp_signature_get_revocation_reason(
                sig, &mut code as *mut *mut _, &mut reason as *mut *mut _)
        };
        assert_eq!(r, RNP_SUCCESS);
        assert!(! code.is_null());
        assert!(! reason.is_null());
        let result = unsafe {
            (CStr::from_ptr(code).to_str().unwrap().to_string(),
             CStr::from_ptr(reason).to_bytes().to_vec())
        };
        unsafe {
            crate::buffer::rnp_buffer_destroy(code as *mut _);
            crate::buffer::rnp_buffer_destroy(reason as *mut _);
        }
        result
    }

    #[test]
    fn key_version() -> openpgp::Result<()> {
        use openpgp::Profile;
        use openpgp::cert::CertBuilder;

        let (v4, _) = CertBuilder::general_purpose(Some("v4"))
            .set_profile(Profile::RFC4880)?
            .generate()?;
        let (v6, _) = CertBuilder::general_purpose(Some("v6"))
            .set_profile(Profile::RFC9580)?
            .generate()?;

        // Make sure that we test what we mean to test.
        assert!(v4.keys().count() > 1);
        assert!(v6.keys().count() > 1);
        assert_eq!(v4.fingerprint().as_bytes().len(), 20);
        assert_eq!(v6.fingerprint().as_bytes().len(), 32);

        let ctx = ctx_with_certs(&[&v4, &v6]);

        // The primary key and the subkeys report their own version.
        for (cert, expected) in [(&v4, 4), (&v6, 6)] {
            for ka in cert.keys() {
                let key = locate(ctx, &ka.key().fingerprint());

                let mut version: u32 = 0;
                let r = unsafe {
                    rnp_key_get_version(key, &mut version as *mut _)
                };
                assert_eq!(r, RNP_SUCCESS);
                assert_eq!(version, expected);

                let r = unsafe { rnp_key_handle_destroy(key) };
                assert_eq!(r, RNP_SUCCESS);
            }
        }

        // NULL pointers.
        let key = locate(ctx, &v4.fingerprint());
        let mut version: u32 = 0;
        let r = unsafe {
            rnp_key_get_version(std::ptr::null(), &mut version as *mut _)
        };
        assert_eq!(r, RNP_ERROR_NULL_POINTER);
        let r = unsafe {
            rnp_key_get_version(key, std::ptr::null_mut())
        };
        assert_eq!(r, RNP_ERROR_NULL_POINTER);
        let r = unsafe { rnp_key_handle_destroy(key) };
        assert_eq!(r, RNP_SUCCESS);

        let r = unsafe { rnp_ffi_destroy(ctx) };
        assert_eq!(r, RNP_SUCCESS);
        Ok(())
    }

    #[test]
    fn revocation_signature_none() -> openpgp::Result<()> {
        use openpgp::cert::CertBuilder;

        let (cert, _) = CertBuilder::general_purpose(Some("alice"))
            .generate()?;
        let ctx = ctx_with_certs(&[&cert]);

        // Neither the primary key nor the subkeys are revoked.
        assert!(cert.keys().count() > 1);
        for ka in cert.keys() {
            let key = locate(ctx, &ka.key().fingerprint());
            assert!(! is_revoked(key));
            assert!(revocation_signature(key).is_null());
            let r = unsafe { rnp_key_handle_destroy(key) };
            assert_eq!(r, RNP_SUCCESS);
        }

        // NULL pointers.
        let key = locate(ctx, &cert.fingerprint());
        let mut sig: *mut RnpSignature = std::ptr::null_mut();
        let r = unsafe {
            rnp_key_get_revocation_signature(std::ptr::null_mut(),
                                             &mut sig as *mut *mut _)
        };
        assert_eq!(r, RNP_ERROR_NULL_POINTER);
        let r = unsafe {
            rnp_key_get_revocation_signature(key, std::ptr::null_mut())
        };
        assert_eq!(r, RNP_ERROR_NULL_POINTER);
        let r = unsafe { rnp_key_handle_destroy(key) };
        assert_eq!(r, RNP_SUCCESS);

        let r = unsafe { rnp_ffi_destroy(ctx) };
        assert_eq!(r, RNP_SUCCESS);
        Ok(())
    }

    #[test]
    fn revocation_signature_primary() -> openpgp::Result<()> {
        use openpgp::cert::CertBuilder;
        use openpgp::packet::signature::SignatureBuilder;
        use crate::signature::{
            rnp_signature_handle_destroy,
            rnp_signature_is_valid,
        };

        // The key is created, then revoked because it was
        // compromised, and then the user ID is signed again.  A
        // newer self-signature does not undo a hard revocation.
        let day = Duration::new(24 * 60 * 60, 0);
        let t0 = std::time::SystemTime::now() - 3 * day;

        let (cert, _) = CertBuilder::general_purpose(Some("alice"))
            .set_creation_time(t0)
            .generate()?;
        let mut signer = cert.primary_key().key().clone()
            .parts_into_secret()?.into_keypair()?;

        let rev = CertRevocationBuilder::new()
            .set_signature_creation_time(t0 + day)?
            .set_reason_for_revocation(ReasonForRevocation::KeyCompromised,
                                       b"It was the maid :/")?
            .build(&mut signer, &cert, None)?;

        let uid = cert.userids().next().unwrap();
        let binding = uid.userid().bind(
            &mut signer, &cert,
            SignatureBuilder::from(
                uid.self_signatures().next().unwrap().clone())
                .set_signature_creation_time(t0 + 2 * day)?)?;

        let (cert, _) = cert.insert_packets(vec![
            Packet::from(rev.clone()),
            Packet::from(binding),
        ])?;
        assert_eq!(cert.userids().next().unwrap().self_signatures().count(),
                   2);

        let ctx = ctx_with_certs(&[&cert]);

        // The primary key is revoked.
        let key = locate(ctx, &cert.fingerprint());
        assert!(is_revoked(key));
        let sig = revocation_signature(key);
        assert!(! sig.is_null());
        assert_eq!(unsafe { &(*sig) }.mpis(), rev.mpis());
        assert_eq!(get_revocation_reason(sig),
                   ("compromised".to_string(),
                    b"It was the maid :/".to_vec()));
        let r = unsafe { rnp_signature_is_valid(sig, 0) };
        assert_eq!(r, RNP_SUCCESS);
        let r = unsafe { rnp_signature_handle_destroy(sig) };
        assert_eq!(r, RNP_SUCCESS);
        let r = unsafe { rnp_key_handle_destroy(key) };
        assert_eq!(r, RNP_SUCCESS);

        // The subkeys have no revocation signature of their own.
        assert!(cert.keys().subkeys().count() > 0);
        for ka in cert.keys().subkeys() {
            let key = locate(ctx, &ka.key().fingerprint());
            assert!(! is_revoked(key));
            assert!(revocation_signature(key).is_null());
            let r = unsafe { rnp_key_handle_destroy(key) };
            assert_eq!(r, RNP_SUCCESS);
        }

        let r = unsafe { rnp_ffi_destroy(ctx) };
        assert_eq!(r, RNP_SUCCESS);
        Ok(())
    }

    #[test]
    fn revocation_signature_subkey() -> openpgp::Result<()> {
        use openpgp::cert::CertBuilder;
        use crate::signature::rnp_signature_handle_destroy;

        let (cert, _) = CertBuilder::general_purpose(Some("alice"))
            .generate()?;
        let mut signer = cert.primary_key().key().clone()
            .parts_into_secret()?.into_keypair()?;

        assert!(cert.keys().subkeys().count() > 1);
        let revoked = cert.keys().subkeys().next().unwrap().key().clone();
        let rev = SubkeyRevocationBuilder::new()
            .set_reason_for_revocation(ReasonForRevocation::KeyRetired,
                                       b"Not needed any more")?
            .build(&mut signer, &cert, &revoked, None)?;
        let (cert, _) = cert.insert_packets(rev.clone())?;

        let ctx = ctx_with_certs(&[&cert]);

        // Only that subkey is revoked.
        for ka in cert.keys() {
            let key = locate(ctx, &ka.key().fingerprint());
            let sig = revocation_signature(key);
            if ka.key().fingerprint() == revoked.fingerprint() {
                assert!(is_revoked(key));
                assert!(! sig.is_null());
                assert_eq!(unsafe { &(*sig) }.mpis(), rev.mpis());
                assert_eq!(get_revocation_reason(sig),
                           ("retired".to_string(),
                            b"Not needed any more".to_vec()));
                let r = unsafe { rnp_signature_handle_destroy(sig) };
                assert_eq!(r, RNP_SUCCESS);
            } else {
                assert!(! is_revoked(key));
                assert!(sig.is_null());
            }
            let r = unsafe { rnp_key_handle_destroy(key) };
            assert_eq!(r, RNP_SUCCESS);
        }

        let r = unsafe { rnp_ffi_destroy(ctx) };
        assert_eq!(r, RNP_SUCCESS);
        Ok(())
    }

    #[test]
    fn revocation_signature_third_party() -> openpgp::Result<()> {
        use openpgp::cert::CertBuilder;

        // Mallory makes a signature that claims to revoke Alice's
        // key.  We cannot tell whether that is a valid revocation,
        // so there is no revocation signature to return.
        let (alice, _) = CertBuilder::general_purpose(Some("alice"))
            .generate()?;
        let (mallory, _) = CertBuilder::general_purpose(Some("mallory"))
            .generate()?;
        let mut signer = mallory.primary_key().key().clone()
            .parts_into_secret()?.into_keypair()?;

        let rev = CertRevocationBuilder::new()
            .set_reason_for_revocation(ReasonForRevocation::KeyCompromised,
                                       b"Says Mallory")?
            .build(&mut signer, &alice, None)?;
        let (alice, _) = alice.insert_packets(rev)?;

        // Make sure that the signature is part of the certificate.
        assert_eq!(alice.primary_key().other_revocations().count(), 1);
        assert_eq!(alice.primary_key().self_revocations().count(), 0);

        let ctx = ctx_with_certs(&[&alice, &mallory]);

        // ... and that we kept it when we imported the certificate.
        assert_eq!(unsafe { &*ctx }.certs.read()
                   .by_primary_fp(&alice.fingerprint()).unwrap()
                   .primary_key().other_revocations().count(),
                   1);

        let key = locate(ctx, &alice.fingerprint());
        assert!(! is_revoked(key));
        assert!(revocation_signature(key).is_null());
        let r = unsafe { rnp_key_handle_destroy(key) };
        assert_eq!(r, RNP_SUCCESS);

        let r = unsafe { rnp_ffi_destroy(ctx) };
        assert_eq!(r, RNP_SUCCESS);
        Ok(())
    }

    #[test]
    fn revocation_reason_code_and_text() -> openpgp::Result<()> {
        use openpgp::cert::CertBuilder;
        use openpgp::packet::signature::SignatureBuilder;
        use openpgp::types::SignatureType;
        use crate::signature::{
            rnp_signature_get_revocation_reason,
            rnp_signature_handle_destroy,
        };

        // The codes are those of RFC 9580, Section 5.2.3.31, the
        // names are those of RNP.
        let reasons: &[(ReasonForRevocation, u8, &str, &[u8])] = &[
            (ReasonForRevocation::Unspecified, 0, "no", b""),
            (ReasonForRevocation::KeySuperseded, 1, "superseded",
             b"See my new key"),
            (ReasonForRevocation::KeyCompromised, 2, "compromised",
             b"It was the maid :/"),
            (ReasonForRevocation::KeyRetired, 3, "retired",
             "Tsch\u{fc}ss".as_bytes()),
            (ReasonForRevocation::UIDRetired, 32, "no longer valid",
             b"Left the company"),
            // RNP has no name for other codes.
            (ReasonForRevocation::Private(100), 100, "", b"Private use"),
            (ReasonForRevocation::Unknown(4), 4, "", b"Unknown code"),
        ];

        for (reason, code, name, text) in reasons {
            assert_eq!(u8::from(*reason), *code);

            let (cert, _) = CertBuilder::general_purpose(Some("alice"))
                .generate()?;
            let mut signer = cert.primary_key().key().clone()
                .parts_into_secret()?.into_keypair()?;
            let rev = CertRevocationBuilder::new()
                .set_reason_for_revocation(*reason, text)?
                .build(&mut signer, &cert, None)?;
            let (cert, _) = cert.insert_packets(rev)?;

            let ctx = ctx_with_certs(&[&cert]);
            let key = locate(ctx, &cert.fingerprint());
            let sig = revocation_signature(key);
            assert!(! sig.is_null(), "code {}", code);
            assert_eq!(get_revocation_reason(sig),
                       (name.to_string(), text.to_vec()),
                       "code {}", code);

            let r = unsafe { rnp_signature_handle_destroy(sig) };
            assert_eq!(r, RNP_SUCCESS);
            let r = unsafe { rnp_key_handle_destroy(key) };
            assert_eq!(r, RNP_SUCCESS);
            let r = unsafe { rnp_ffi_destroy(ctx) };
            assert_eq!(r, RNP_SUCCESS);
        }

        // A revocation without a Reason for Revocation subpacket,
        // and a reason that contains a NUL character.
        let (cert, _) = CertBuilder::general_purpose(Some("alice"))
            .generate()?;
        let mut signer = cert.primary_key().key().clone()
            .parts_into_secret()?.into_keypair()?;
        let rev = SignatureBuilder::new(SignatureType::KeyRevocation)
            .sign_direct_key(&mut signer, cert.primary_key().key())?;
        assert!(rev.reason_for_revocation().is_none());
        let subkey = cert.keys().subkeys().next().unwrap().key().clone();
        let subkey_rev = SubkeyRevocationBuilder::new()
            .set_reason_for_revocation(ReasonForRevocation::KeyCompromised,
                                       b"NUL\x00NUL")?
            .build(&mut signer, &cert, &subkey, None)?;
        let (cert, _) = cert.insert_packets(vec![
            Packet::from(rev),
            Packet::from(subkey_rev),
        ])?;

        let ctx = ctx_with_certs(&[&cert]);

        let key = locate(ctx, &cert.fingerprint());
        let sig = revocation_signature(key);
        assert!(! sig.is_null());
        assert_eq!(get_revocation_reason(sig), ("".to_string(), b"".to_vec()));

        // `code` and `reason` are optional.
        let r = unsafe {
            rnp_signature_get_revocation_reason(
                sig, std::ptr::null_mut(), std::ptr::null_mut())
        };
        assert_eq!(r, RNP_SUCCESS);
        let mut code: *mut c_char = std::ptr::null_mut();
        let r = unsafe {
            rnp_signature_get_revocation_reason(
                sig, &mut code as *mut *mut _, std::ptr::null_mut())
        };
        assert_eq!(r, RNP_SUCCESS);
        assert!(! code.is_null());
        unsafe { crate::buffer::rnp_buffer_destroy(code as *mut _) };
        let mut reason: *mut c_char = std::ptr::null_mut();
        let r = unsafe {
            rnp_signature_get_revocation_reason(
                sig, std::ptr::null_mut(), &mut reason as *mut *mut _)
        };
        assert_eq!(r, RNP_SUCCESS);
        assert!(! reason.is_null());
        unsafe { crate::buffer::rnp_buffer_destroy(reason as *mut _) };

        // The signature is not.
        let r = unsafe {
            rnp_signature_get_revocation_reason(
                std::ptr::null(), &mut code as *mut *mut _,
                &mut reason as *mut *mut _)
        };
        assert_eq!(r, RNP_ERROR_NULL_POINTER);

        let r = unsafe { rnp_signature_handle_destroy(sig) };
        assert_eq!(r, RNP_SUCCESS);

        // A signature that is not a revocation has no reason either.
        let mut count = 0;
        let r = unsafe {
            rnp_key_get_signature_count(key, &mut count as *mut _)
        };
        assert_eq!(r, RNP_SUCCESS);
        let mut direct_key_sigs = 0;
        for i in 0..count {
            let mut sig: *mut RnpSignature = std::ptr::null_mut();
            let r = unsafe {
                rnp_key_get_signature_at(key, i, &mut sig as *mut *mut _)
            };
            assert_eq!(r, RNP_SUCCESS);
            assert!(! sig.is_null());
            if unsafe { &(*sig) }.typ() == SignatureType::DirectKey {
                direct_key_sigs += 1;
                assert_eq!(get_revocation_reason(sig),
                           ("".to_string(), b"".to_vec()));
            }
            let r = unsafe { rnp_signature_handle_destroy(sig) };
            assert_eq!(r, RNP_SUCCESS);
        }
        assert!(direct_key_sigs > 0);
        let r = unsafe { rnp_key_handle_destroy(key) };
        assert_eq!(r, RNP_SUCCESS);

        // We replace NUL characters.
        let key = locate(ctx, &subkey.fingerprint());
        let sig = revocation_signature(key);
        assert!(! sig.is_null());
        assert_eq!(get_revocation_reason(sig),
                   ("compromised".to_string(), b"NUL_NUL".to_vec()));
        let r = unsafe { rnp_signature_handle_destroy(sig) };
        assert_eq!(r, RNP_SUCCESS);
        let r = unsafe { rnp_key_handle_destroy(key) };
        assert_eq!(r, RNP_SUCCESS);

        let r = unsafe { rnp_ffi_destroy(ctx) };
        assert_eq!(r, RNP_SUCCESS);
        Ok(())
    }

    #[test]
    fn time_to_supersede_cases() {
        let second = Duration::new(1, 0);
        let t = UNIX_EPOCH + Duration::new(1_800_000_000, 0);

        // Within the second of the superseded signature, we have to
        // wait for the next one.
        assert_eq!(time_to_supersede(t, t), Some(second));
        assert_eq!(time_to_supersede(t, t + Duration::new(0, 250_000_000)),
                   Some(Duration::new(0, 750_000_000)));
        assert_eq!(time_to_supersede(t, t + Duration::new(0, 999_999_999)),
                   Some(Duration::new(0, 1)));

        // From the next second on, a new signature is newer.
        assert_eq!(time_to_supersede(t, t + second), None);
        assert_eq!(time_to_supersede(t, t + Duration::new(1, 1)), None);
        assert_eq!(time_to_supersede(t, t + Duration::new(24 * 60 * 60, 0)),
                   None);

        // If the superseded signature is ahead of the clock, we
        // don't wait.
        assert_eq!(time_to_supersede(t, t - Duration::new(0, 1)), None);
        assert_eq!(time_to_supersede(t, t - second), None);
        assert_eq!(time_to_supersede(t, t - Duration::new(24 * 60 * 60, 0)),
                   None);
    }

    const DAY: u32 = 24 * 60 * 60;

    /// Creates a certificate with secret keys whose signatures are a
    /// day old.
    fn day_old_key() -> openpgp::Result<Cert> {
        use openpgp::cert::CertBuilder;

        let (cert, _) = CertBuilder::new()
            .set_creation_time(
                SystemTime::now() - Duration::new(DAY as u64, 0))
            .add_userid("alice")
            .add_userid("alice@example.org")
            .add_signing_subkey()
            .add_transport_encryption_subkey()
            .generate()?;
        assert_eq!(cert.keys().count(), 3);
        Ok(cert)
    }

    /// Creates a context and imports the certificate with its secret
    /// keys.
    fn ctx_with_tsk(cert: &Cert) -> openpgp::Result<*mut RnpContext> {
        let mut ctx: *mut RnpContext = std::ptr::null_mut();
        let r = unsafe {
            rnp_ffi_create(
                &mut ctx as *mut *mut _,
                b"GPG\x00".as_ptr() as *const c_char,
                b"GPG\x00".as_ptr() as *const c_char)
        };
        assert_eq!(r, RNP_SUCCESS);

        let buffer = cert.as_tsk().to_vec()?;
        let mut input: *mut RnpInput = std::ptr::null_mut();
        let r = unsafe {
            rnp_input_from_memory(
                &mut input as *mut *mut _,
                buffer.as_ptr(), buffer.len(), false)
        };
        assert_eq!(r, RNP_SUCCESS);
        let r = unsafe {
            rnp_import_keys(
                ctx, input,
                RNP_LOAD_SAVE_PUBLIC_KEYS | RNP_LOAD_SAVE_SECRET_KEYS,
                std::ptr::null_mut() as *mut *mut _)
        };
        assert_eq!(r, RNP_SUCCESS);
        let r = unsafe { rnp_input_destroy(input) };
        assert_eq!(r, RNP_SUCCESS);

        Ok(ctx)
    }

    /// Changes the key's expiration using a new key handle, like
    /// Thunderbird does.
    fn set_expiration(ctx: *mut RnpContext, fp: &openpgp::Fingerprint,
                      expiry: u32)
    {
        let key = locate(ctx, fp);
        let r = unsafe { rnp_key_set_expiration(key, expiry) };
        assert_eq!(r, RNP_SUCCESS);
        let r = unsafe { rnp_key_handle_destroy(key) };
        assert_eq!(r, RNP_SUCCESS);
    }

    /// Returns the key's expiration using a new key handle.
    fn get_expiration(ctx: *mut RnpContext, fp: &openpgp::Fingerprint)
                      -> u32
    {
        let key = locate(ctx, fp);
        let mut expiration = u32::MAX;
        let r = unsafe {
            rnp_key_get_expiration(key, &mut expiration as *mut _)
        };
        assert_eq!(r, RNP_SUCCESS);
        let r = unsafe { rnp_key_handle_destroy(key) };
        assert_eq!(r, RNP_SUCCESS);
        expiration
    }

    /// Waits for the start of a second, if we are not near it.
    ///
    /// The changes a test makes after it take a few milliseconds.
    /// They fall into the same second unless rnp_key_set_expiration
    /// waits.
    fn wait_for_start_of_second() {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap()
            .subsec_nanos();
        if nanos > 100_000_000 {
            std::thread::sleep(Duration::new(0, 1_000_000_000 - nanos));
        }
    }

    /// Asserts that there are `n` signatures, and that no two of
    /// them have the same creation time.
    fn assert_distinct_creation_times<'a, I>(sigs: I, n: usize)
        where I: Iterator<Item = &'a Signature>
    {
        let mut times = sigs
            .map(|sig| sig.signature_creation_time().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(times.len(), n);
        times.sort();
        times.dedup();
        assert_eq!(times.len(), n, "signatures with the same creation time");
    }

    #[test]
    fn set_expiration_twice_within_a_second() -> openpgp::Result<()> {
        // Thunderbird's test browser_expiredKey.js sets a key's
        // expiration to ten days and then to none, for the primary
        // key and a subkey.  If both changes happen within a second,
        // the second change must take effect nevertheless.
        let cert = day_old_key()?;
        let ctx = ctx_with_tsk(&cert)?;
        let fps = cert.keys().map(|ka| ka.key().fingerprint())
            .collect::<Vec<_>>();

        for fp in fps.iter() {
            assert_eq!(get_expiration(ctx, fp), 0);
        }

        wait_for_start_of_second();

        let expirations = [10 * DAY, 0, 20 * DAY];
        for expiry in expirations {
            for fp in fps.iter() {
                set_expiration(ctx, fp, expiry);
            }
            for fp in fps.iter() {
                assert_eq!(get_expiration(ctx, fp), expiry);
            }
        }

        // Every change added a self signature to each component, and
        // each of them is newer than the one it superseded.
        {
            let n = 1 + expirations.len();
            let ks = unsafe { &mut *ctx }.certs.read();
            let cert = ks.by_primary_fp(&cert.fingerprint()).unwrap();
            assert_distinct_creation_times(
                cert.primary_key().self_signatures(), n);
            assert_eq!(cert.userids().count(), 2);
            for ua in cert.userids() {
                assert_distinct_creation_times(ua.self_signatures(), n);
            }
            assert_eq!(cert.keys().subkeys().count(), 2);
            for ka in cert.keys().subkeys() {
                assert_distinct_creation_times(ka.self_signatures(), n);
            }
        }

        let r = unsafe { rnp_ffi_destroy(ctx) };
        assert_eq!(r, RNP_SUCCESS);
        Ok(())
    }

    #[test]
    fn set_subkey_expiration_twice_within_a_second() -> openpgp::Result<()> {
        // Like set_expiration_twice_within_a_second, but only a
        // subkey's expiration changes, so the primary key's
        // signatures don't make us wait.
        let cert = day_old_key()?;
        let ctx = ctx_with_tsk(&cert)?;

        for ka in cert.keys().subkeys() {
            let fp = ka.key().fingerprint();
            assert_eq!(get_expiration(ctx, &fp), 0);

            wait_for_start_of_second();

            let expirations = [10 * DAY, 0, 20 * DAY];
            for expiry in expirations {
                set_expiration(ctx, &fp, expiry);
                assert_eq!(get_expiration(ctx, &fp), expiry);
            }

            let ks = unsafe { &mut *ctx }.certs.read();
            let cert = ks.by_primary_fp(&cert.fingerprint()).unwrap();
            let ka = cert.keys().subkeys().key_handle(fp.clone()).nth(0)
                .unwrap();
            assert_distinct_creation_times(
                ka.self_signatures(), 1 + expirations.len());
        }

        // The primary key was not changed.
        assert_eq!(get_expiration(ctx, &cert.fingerprint()), 0);
        {
            let ks = unsafe { &mut *ctx }.certs.read();
            let cert = ks.by_primary_fp(&cert.fingerprint()).unwrap();
            assert_eq!(cert.primary_key().self_signatures().count(), 1);
        }

        let r = unsafe { rnp_ffi_destroy(ctx) };
        assert_eq!(r, RNP_SUCCESS);
        Ok(())
    }

    #[test]
    fn set_expiration_after_another_self_signature() -> openpgp::Result<()> {
        use openpgp::packet::signature::SignatureBuilder;
        use openpgp::types::SignatureType;

        // The signatures that a change of the primary key's
        // expiration supersedes need not have the same age.  We have
        // to wait if any of them was made in this second.
        for new_userid in [true, false] {
            let cert = day_old_key()?;
            let mut signer = cert.primary_key().key().clone()
                .parts_into_secret()?.into_keypair()?;

            wait_for_start_of_second();

            let now = SystemTime::now();
            let (cert, userids) = if new_userid {
                // A new user ID.  The direct key signature and the
                // binding signatures of the other user IDs are a day
                // old.
                let userid = UserID::from("bob");
                let sig =
                    SignatureBuilder::new(SignatureType::PositiveCertification)
                    .set_signature_creation_time(now)?
                    .sign_userid_binding(&mut signer, None, &userid)?;
                (cert.insert_packets(
                    vec![Packet::from(userid), sig.into()])?.0, 3)
            } else {
                // A new direct key signature.  The binding signatures
                // of the user IDs are a day old.
                let template =
                    cert.primary_key().self_signatures().next().unwrap();
                let sig = SignatureBuilder::from(template.clone())
                    .set_signature_creation_time(now)?
                    .sign_direct_key(&mut signer, None)?;
                (cert.insert_packets(vec![Packet::from(sig)])?.0, 2)
            };

            let ctx = ctx_with_tsk(&cert)?;
            let fp = cert.fingerprint();
            assert_eq!(get_expiration(ctx, &fp), 0);

            set_expiration(ctx, &fp, 10 * DAY);
            assert_eq!(get_expiration(ctx, &fp), 10 * DAY);

            {
                let ks = unsafe { &mut *ctx }.certs.read();
                let cert = ks.by_primary_fp(&fp).unwrap();
                assert_distinct_creation_times(
                    cert.primary_key().self_signatures(),
                    if new_userid { 2 } else { 3 });
                assert_eq!(cert.userids().count(), userids);
                for ua in cert.userids() {
                    assert_distinct_creation_times(ua.self_signatures(), 2);
                }
            }

            let r = unsafe { rnp_ffi_destroy(ctx) };
            assert_eq!(r, RNP_SUCCESS);
        }
        Ok(())
    }

    const RNP_ERROR_GENERIC: u32 =
        crate::error::RNP_ERROR_GENERIC.as_u32();
    const RNP_ERROR_BAD_PARAMETERS: u32 =
        crate::error::RNP_ERROR_BAD_PARAMETERS.as_u32();
    const RNP_ERROR_NO_SUITABLE_KEY: u32 =
        crate::error::RNP_ERROR_NO_SUITABLE_KEY.as_u32();

    /// Calls a function that returns a string in a buffer that the
    /// caller has to free.
    fn get_string<F>(f: F) -> std::result::Result<String, RnpResult>
        where F: FnOnce(*mut *mut c_char) -> RnpResult
    {
        let mut s: *mut c_char = std::ptr::null_mut();
        let r = f(&mut s as *mut *mut _);
        if r != RNP_SUCCESS {
            assert!(s.is_null());
            return Err(r);
        }
        assert!(! s.is_null());
        let result = unsafe {
            std::ffi::CStr::from_ptr(s).to_str().unwrap().to_string()
        };
        unsafe { crate::buffer::rnp_buffer_destroy(s as *mut _) };
        Ok(result)
    }

    /// Looks up the key by the given kind of identifier.  Returns
    /// NULL if there is no such key.
    fn locate_by(ctx: *mut RnpContext, kind: &str, id: &str)
                 -> *mut RnpKey
    {
        let kind = CString::new(kind).unwrap();
        let id = CString::new(id).unwrap();
        // Initialize it with something that is not NULL so that we
        // notice that the function stores NULL.
        let mut key = std::ptr::NonNull::<RnpKey>::dangling().as_ptr();
        let r = unsafe {
            rnp_locate_key(ctx, kind.as_ptr(), id.as_ptr(),
                           &mut key as *mut *mut _)
        };
        assert_eq!(r, RNP_SUCCESS);
        key
    }

    /// Returns all identifiers of the given kind.
    fn identifiers(ctx: *mut RnpContext, kind: &str) -> Vec<String> {
        use crate::iter::*;

        let kind = CString::new(kind).unwrap();
        let mut iter: *mut RnpIdentifierIterator = std::ptr::null_mut();
        let r = unsafe {
            rnp_identifier_iterator_create(
                ctx, &mut iter as *mut *mut _, kind.as_ptr())
        };
        assert_eq!(r, RNP_SUCCESS);

        let mut ids = Vec::new();
        loop {
            let mut id: *const c_char = std::ptr::null();
            let r = unsafe {
                rnp_identifier_iterator_next(iter, &mut id as *mut *const _)
            };
            assert_eq!(r, RNP_SUCCESS);
            if id.is_null() {
                break;
            }
            ids.push(unsafe {
                std::ffi::CStr::from_ptr(id).to_str().unwrap().to_string()
            });
            unsafe { crate::buffer::rnp_buffer_destroy(id as *mut _) };
        }

        let r = unsafe { rnp_identifier_iterator_destroy(iter) };
        assert_eq!(r, RNP_SUCCESS);
        ids
    }

    fn get_alg(key: *mut RnpKey) -> String {
        get_string(|s| unsafe { rnp_key_get_alg(key, s) }).unwrap()
    }

    fn get_fprint(key: *mut RnpKey) -> String {
        get_string(|s| unsafe { rnp_key_get_fprint(key, s) }).unwrap()
    }

    fn get_bits(key: *mut RnpKey) -> std::result::Result<u32, RnpResult> {
        let mut bits: u32 = 0;
        let r = unsafe { rnp_key_get_bits(key, &mut bits as *mut _) };
        if r == RNP_SUCCESS { Ok(bits) } else { Err(r) }
    }

    fn is_sub(key: *mut RnpKey) -> bool {
        let mut sub = false;
        let r = unsafe { rnp_key_is_sub(key, &mut sub as *mut _) };
        assert_eq!(r, RNP_SUCCESS);
        sub
    }

    /// What the keys of RFC 9980, Appendix A report.
    ///
    /// Nothing here depends on whether the cryptographic backend
    /// supports the algorithms: these are properties of the key
    /// packets.  Whether the certificates are valid is a different
    /// matter, and not tested here.
    #[test]
    fn rfc9980_key_properties() -> openpgp::Result<()> {
        use crate::testdata::rfc9980;

        for v in rfc9980::VECTORS {
            let cert = v.cert();
            assert_eq!(cert.keys().count(), 2, "{}", v.section);
            let ctx = ctx_with_certs(&[&cert]);

            for (i, expected) in v.keys().into_iter().enumerate() {
                let key = locate_by(ctx, "fingerprint", expected.fingerprint);
                assert!(! key.is_null(), "{}", v.section);

                assert_eq!(is_sub(key), i == 1, "{}", v.section);
                assert_eq!(get_fprint(key), expected.fingerprint,
                           "{}", v.section);

                // RFC 9580, Section 5.5.4.2 and 5.5.4.3.
                let keyid = match v.version {
                    4 => &expected.fingerprint[24..],
                    6 => &expected.fingerprint[..16],
                    _ => unreachable!(),
                };
                assert_eq!(
                    get_string(|s| unsafe { rnp_key_get_keyid(key, s) }),
                    Ok(keyid.to_string()), "{}", v.section);

                let mut version: u32 = 0;
                let r = unsafe {
                    rnp_key_get_version(key, &mut version as *mut _)
                };
                assert_eq!(r, RNP_SUCCESS);
                assert_eq!(version, v.version, "{}", v.section);

                assert_eq!(get_alg(key), expected.name, "{}", v.section);
                assert_eq!(get_bits(key), Ok(expected.bits),
                           "{}", v.section);

                assert_eq!(
                    get_string(|s| unsafe { rnp_key_get_grip(key, s) }),
                    Ok(expected.grip.to_string()), "{}", v.section);
                assert_eq!(
                    get_string(|s| unsafe {
                        rnp_key_get_primary_grip(key, s)
                    }),
                    Ok(v.primary.grip.to_string()), "{}", v.section);

                // Like RNP, we don't report a curve for the
                // algorithms from RFC 9980.
                if expected.algo >= 30 {
                    assert_eq!(
                        get_string(|s| unsafe { rnp_key_get_curve(key, s) }),
                        Err(RNP_ERROR_BAD_PARAMETERS), "{}", v.section);
                }

                // The other identifiers find the same key.
                for (kind, id) in [("grip", expected.grip), ("keyid", keyid)] {
                    let other = locate_by(ctx, kind, id);
                    assert!(! other.is_null(), "{}: {}", v.section, kind);
                    assert_eq!(get_fprint(other), expected.fingerprint,
                               "{}: {}", v.section, kind);
                    let r = unsafe { rnp_key_handle_destroy(other) };
                    assert_eq!(r, RNP_SUCCESS);
                }

                let r = unsafe { rnp_key_handle_destroy(key) };
                assert_eq!(r, RNP_SUCCESS);
            }

            // Thunderbird enumerates the keys by keygrip.
            assert_eq!(identifiers(ctx, "grip"), &[v.primary.grip],
                       "{}", v.section);
            assert_eq!(identifiers(ctx, "fingerprint"),
                       &[v.primary.fingerprint],
                       "{}", v.section);

            let r = unsafe { rnp_ffi_destroy(ctx) };
            assert_eq!(r, RNP_SUCCESS);
        }
        Ok(())
    }

    /// Enumerates a keyring with certificates of all kinds by
    /// keygrip.
    #[test]
    fn enumerate_by_keygrip() -> openpgp::Result<()> {
        use std::collections::BTreeSet;
        use openpgp::Profile;
        use openpgp::cert::CertBuilder;
        use sequoia_ipc::Keygrip;
        use crate::testdata::rfc9980;

        // A certificate with keys that GnuPG knows: the keygrips are
        // GnuPG's.
        let (v4, _) = CertBuilder::general_purpose(Some("v4"))
            .set_profile(Profile::RFC4880)?
            .generate()?;
        assert!(v4.keys().count() > 1);
        let v4_grip =
            Keygrip::of(v4.primary_key().key().mpis())?.to_string();

        // A v6 certificate with Ed25519 and X25519 keys.
        let (v6, _) = CertBuilder::general_purpose(Some("v6"))
            .set_profile(Profile::RFC9580)?
            .generate()?;
        assert!(v6.keys().count() > 1);
        assert!(Keygrip::of(v6.primary_key().key().mpis()).is_err());

        let mut certs = vec![v4.clone(), v6.clone()];
        let mut expected_fprs = BTreeSet::new();
        expected_fprs.insert(v4.fingerprint().to_hex());
        expected_fprs.insert(v6.fingerprint().to_hex());
        for v in rfc9980::VECTORS {
            certs.push(v.cert());
            expected_fprs.insert(v.primary.fingerprint.to_string());
        }
        let ctx = ctx_with_certs(&certs.iter().collect::<Vec<_>>());

        // Every certificate is listed, exactly once, by the keygrip
        // of its primary key.
        let grips = identifiers(ctx, "grip");
        assert_eq!(grips.len(), certs.len());
        assert!(grips.contains(&v4_grip));
        for v in rfc9980::VECTORS {
            assert!(grips.contains(&v.primary.grip.to_string()),
                    "{}", v.section);
        }

        let mut fprs = BTreeSet::new();
        for grip in &grips {
            let key = locate_by(ctx, "grip", grip);
            assert!(! key.is_null());
            assert!(! is_sub(key));
            assert_eq!(
                get_string(|s| unsafe { rnp_key_get_grip(key, s) }).as_ref(),
                Ok(grip));
            assert_eq!(
                get_string(|s| unsafe { rnp_key_get_primary_grip(key, s) })
                    .as_ref(),
                Ok(grip));
            // Thunderbird skips a key if this fails.
            assert!(get_bits(key).is_ok());
            fprs.insert(get_fprint(key));
            let r = unsafe { rnp_key_handle_destroy(key) };
            assert_eq!(r, RNP_SUCCESS);
        }
        assert_eq!(fprs, expected_fprs);

        // The subkeys are found by their keygrip, too, and know
        // their primary key's.
        for (cert, primary_grip) in
            [(&v4, &v4_grip),
             (&v6, &get_string(|s| unsafe {
                 rnp_key_get_grip(locate(ctx, &v6.fingerprint()), s)
             }).unwrap())]
        {
            for ka in cert.keys().subkeys() {
                let key = locate(ctx, &ka.key().fingerprint());
                let grip =
                    get_string(|s| unsafe { rnp_key_get_grip(key, s) })
                    .unwrap();
                assert!(! grips.contains(&grip));
                assert_eq!(
                    get_string(|s| unsafe {
                        rnp_key_get_primary_grip(key, s)
                    }).as_ref(),
                    Ok(primary_grip));

                let other = locate_by(ctx, "grip", &grip);
                assert!(! other.is_null());
                assert!(is_sub(other));
                assert_eq!(get_fprint(other), ka.key().fingerprint().to_hex());
                let r = unsafe { rnp_key_handle_destroy(other) };
                assert_eq!(r, RNP_SUCCESS);
                let r = unsafe { rnp_key_handle_destroy(key) };
                assert_eq!(r, RNP_SUCCESS);
            }
        }

        // The keys of the v4 certificate report what they did before
        // we knew the new algorithms.
        let key = locate(ctx, &v4.fingerprint());
        assert_eq!(get_alg(key), "EDDSA");
        assert_eq!(get_bits(key), Ok(256));
        let r = unsafe { rnp_key_handle_destroy(key) };
        assert_eq!(r, RNP_SUCCESS);

        // The keys of the v6 certificate now have a name.
        let key = locate(ctx, &v6.fingerprint());
        assert_eq!(get_alg(key), "ED25519");
        assert_eq!(get_bits(key), Ok(256));
        let r = unsafe { rnp_key_handle_destroy(key) };
        assert_eq!(r, RNP_SUCCESS);
        let mut algs = BTreeSet::new();
        for ka in v6.keys().subkeys() {
            let key = locate(ctx, &ka.key().fingerprint());
            algs.insert(get_alg(key));
            assert_eq!(get_bits(key), Ok(256));
            let r = unsafe { rnp_key_handle_destroy(key) };
            assert_eq!(r, RNP_SUCCESS);
        }
        assert_eq!(algs.into_iter().collect::<Vec<_>>(),
                   &["ED25519", "X25519"]);

        // A keygrip that no key has.
        let key = locate_by(ctx, "grip",
                            "0000000000000000000000000000000000000000");
        assert!(key.is_null());

        let r = unsafe { rnp_ffi_destroy(ctx) };
        assert_eq!(r, RNP_SUCCESS);
        Ok(())
    }

    /// A subkey using an algorithm that we do not know does no harm.
    #[test]
    fn unknown_algorithm_properties() -> openpgp::Result<()> {
        use openpgp::Profile;
        use openpgp::cert::CertBuilder;
        use openpgp::cert::SubkeyBuilder;
        use openpgp::crypto::mpi;
        use openpgp::packet::key::{Key6, PublicParts, SubordinateRole};
        use openpgp::types::{KeyFlags, PublicKeyAlgorithm};

        let (cert, _) = CertBuilder::general_purpose(Some("alice"))
            .set_profile(Profile::RFC9580)?
            .generate()?;
        let n = cert.keys().count();

        // 37 is not assigned by RFC 9580 or RFC 9980.
        let unknown: Key<PublicParts, SubordinateRole> =
            Key6::new(std::time::SystemTime::now()
                      - std::time::Duration::new(60, 0),
                      PublicKeyAlgorithm::Unknown(37),
                      mpi::PublicKey::Unknown {
                          mpis: vec![].into_boxed_slice(),
                          rest: vec![0x42; 64].into_boxed_slice(),
                      })?.into();
        let unknown_fp = unknown.fingerprint();
        let signer = cert.primary_key().key().clone()
            .parts_into_secret()?.into_keypair()?;
        let cert = SubkeyBuilder::new(
            cert.with_policy(crate::NP, None)?,
            unknown.parts_into_unspecified(),
            KeyFlags::empty().set_transport_encryption())?
            .set_primary_key_signer(signer)
            .attach_cert()?
            .strip_secret_key_material();
        assert_eq!(cert.keys().count(), n + 1);

        let ctx = ctx_with_certs(&[&cert]);

        // The certificate is listed, with all its keys.
        let grips = identifiers(ctx, "grip");
        assert_eq!(grips.len(), 1);
        let key = locate_by(ctx, "grip", &grips[0]);
        assert!(! key.is_null());
        assert_eq!(get_fprint(key), cert.fingerprint().to_hex());
        let mut subkeys: usize = 0;
        let r = unsafe {
            rnp_key_get_subkey_count(key, &mut subkeys as *mut _)
        };
        assert_eq!(r, RNP_SUCCESS);
        assert_eq!(subkeys, n);
        let r = unsafe { rnp_key_handle_destroy(key) };
        assert_eq!(r, RNP_SUCCESS);

        // The keys that we know report their properties.
        for ka in cert.keys().filter(|ka| ka.key().fingerprint() != unknown_fp)
        {
            let key = locate(ctx, &ka.key().fingerprint());
            assert!(["ED25519", "X25519"].contains(&get_alg(key).as_str()));
            assert_eq!(get_bits(key), Ok(256));
            assert!(get_string(|s| unsafe { rnp_key_get_grip(key, s) })
                    .is_ok());
            let r = unsafe { rnp_key_handle_destroy(key) };
            assert_eq!(r, RNP_SUCCESS);
        }

        // The key that we do not know has a fingerprint, and knows
        // its primary key.  It has no name, no size, and no keygrip.
        let key = locate(ctx, &unknown_fp);
        assert!(is_sub(key));
        assert_eq!(get_alg(key), "unknown");
        assert_eq!(get_bits(key), Err(RNP_ERROR_NO_SUITABLE_KEY));
        assert_eq!(get_string(|s| unsafe { rnp_key_get_grip(key, s) }),
                   Err(RNP_ERROR_GENERIC));
        assert_eq!(get_string(|s| unsafe { rnp_key_get_curve(key, s) }),
                   Err(RNP_ERROR_BAD_PARAMETERS));
        assert_eq!(
            get_string(|s| unsafe { rnp_key_get_primary_grip(key, s) })
                .as_ref(),
            Ok(&grips[0]));
        let r = unsafe { rnp_key_handle_destroy(key) };
        assert_eq!(r, RNP_SUCCESS);

        let r = unsafe { rnp_ffi_destroy(ctx) };
        assert_eq!(r, RNP_SUCCESS);
        Ok(())
    }

    use openpgp::Fingerprint;
    use openpgp::packet::key::PublicParts;
    use openpgp::parse::Parse;

    /// The user ID of the sample keys of RFC 9980, Appendix A.
    const RFC9980_USERID: &str =
        "PQC user (Test Key) <pqc-test-key@example.com>";

    /// Creates a context.
    fn new_ctx() -> *mut RnpContext {
        let mut ctx: *mut RnpContext = std::ptr::null_mut();
        let r = unsafe {
            rnp_ffi_create(
                &mut ctx as *mut *mut _,
                b"GPG\x00".as_ptr() as *const c_char,
                b"GPG\x00".as_ptr() as *const c_char)
        };
        assert_eq!(r, RNP_SUCCESS);
        ctx
    }

    /// Imports the keys like Thunderbird does.  Returns the status,
    /// and for every key the state of the public key, the state of
    /// the secret key, and the fingerprint.
    fn import_keys(ctx: *mut RnpContext, data: &[u8], flags: u32)
                   -> (RnpResult, Vec<(String, String, String)>)
    {
        let mut input: *mut RnpInput = std::ptr::null_mut();
        let r = unsafe {
            rnp_input_from_memory(
                &mut input as *mut *mut _, data.as_ptr(), data.len(), false)
        };
        assert_eq!(r, RNP_SUCCESS);

        let mut results: *mut c_char = std::ptr::null_mut();
        let status = unsafe {
            rnp_import_keys(ctx, input, flags, &mut results as *mut *mut _)
        };
        let r = unsafe { rnp_input_destroy(input) };
        assert_eq!(r, RNP_SUCCESS);

        let mut keys = Vec::new();
        if status == RNP_SUCCESS {
            assert!(! results.is_null());
            let json: serde_json::Value = serde_json::from_str(unsafe {
                std::ffi::CStr::from_ptr(results).to_str().unwrap()
            }).unwrap();
            unsafe { crate::buffer::rnp_buffer_destroy(results as *mut _) };
            for k in json["keys"].as_array().unwrap() {
                keys.push((k["public"].as_str().unwrap().to_string(),
                           k["secret"].as_str().unwrap().to_string(),
                           k["fingerprint"].as_str().unwrap().to_string()));
            }
        }
        (status, keys)
    }

    /// Creates a memory output.
    fn output_to_memory() -> *mut RnpOutput<'static> {
        let mut output: *mut RnpOutput = std::ptr::null_mut();
        let r = unsafe {
            rnp_output_to_memory(&mut output as *mut *mut _, 0)
        };
        assert_eq!(r, RNP_SUCCESS);
        output
    }

    /// Returns what has been written to the memory output, and
    /// destroys it.
    fn output_into_vec(output: *mut RnpOutput) -> Vec<u8> {
        let mut buf: *mut u8 = std::ptr::null_mut();
        let mut len: libc::size_t = 0;
        let r = unsafe {
            rnp_output_memory_get_buf(
                output, &mut buf as *mut *mut _, &mut len as *mut _, false)
        };
        assert_eq!(r, RNP_SUCCESS);
        let data = if len == 0 {
            Vec::new()
        } else {
            unsafe { std::slice::from_raw_parts(buf, len) }.to_vec()
        };
        let r = unsafe { rnp_output_destroy(output) };
        assert_eq!(r, RNP_SUCCESS);
        data
    }

    /// Exports the key.
    fn export_key(key: *mut RnpKey, flags: RnpKeyExportFlags) -> Vec<u8> {
        let output = output_to_memory();
        let r = unsafe { rnp_key_export(key, output, flags) };
        assert_eq!(r, RNP_SUCCESS);
        output_into_vec(output)
    }

    /// Saves the public or the secret keyring.
    fn save_keys(ctx: *mut RnpContext, flags: RnpLoadSaveFlags) -> Vec<u8> {
        let output = output_to_memory();
        let r = unsafe {
            crate::rnp_save_keys(
                ctx, b"GPG\x00".as_ptr() as *const c_char, output, flags)
        };
        assert_eq!(r, RNP_SUCCESS);
        output_into_vec(output)
    }

    /// Loads a keyring that has been saved by `save_keys` into a new
    /// context.
    ///
    /// The secret keyring is loaded using rnp_load_keys, like
    /// Thunderbird does.  For the public keyring, we call the
    /// function that rnp_load_keys calls to load it: in addition,
    /// rnp_load_keys imports GnuPG's keyring and starts looking for
    /// updates on the network, and a test must do neither.
    fn load_keys(pubring: &[u8], secring: &[u8]) -> *mut RnpContext {
        let ctx = new_ctx();

        let policy = unsafe { &*ctx }.policy.clone();
        unsafe { &mut *ctx }.certs.load_keyring_in_background(
            pubring.to_vec(), false, policy).unwrap();

        let mut input: *mut RnpInput = std::ptr::null_mut();
        let r = unsafe {
            rnp_input_from_memory(
                &mut input as *mut *mut _,
                secring.as_ptr(), secring.len(), false)
        };
        assert_eq!(r, RNP_SUCCESS);
        let r = unsafe {
            crate::rnp_load_keys(
                ctx, b"GPG\x00".as_ptr() as *const c_char, input,
                RNP_LOAD_SAVE_SECRET_KEYS)
        };
        assert_eq!(r, RNP_SUCCESS);
        let r = unsafe { rnp_input_destroy(input) };
        assert_eq!(r, RNP_SUCCESS);

        ctx
    }

    /// Returns the number of public and of secret keys.  This waits
    /// for the keyrings to be loaded.
    fn key_counts(ctx: *mut RnpContext) -> (usize, usize) {
        let mut public: size_t = usize::MAX;
        let r = unsafe {
            crate::rnp_get_public_key_count(ctx, &mut public as *mut _)
        };
        assert_eq!(r, RNP_SUCCESS);
        let mut secret: size_t = usize::MAX;
        let r = unsafe {
            crate::rnp_get_secret_key_count(ctx, &mut secret as *mut _)
        };
        assert_eq!(r, RNP_SUCCESS);
        (public, secret)
    }

    /// Calls a function that returns a boolean.
    fn get_bool<F>(f: F) -> bool
        where F: FnOnce(*mut bool) -> RnpResult
    {
        let mut result = false;
        let r = f(&mut result as *mut _);
        assert_eq!(r, RNP_SUCCESS);
        result
    }

    fn have_secret(key: *mut RnpKey) -> bool {
        get_bool(|b| unsafe { rnp_key_have_secret(key, b) })
    }

    fn get_protection_type(key: *mut RnpKey) -> String {
        get_string(|s| unsafe {
            rnp_key_get_protection_type(key, s as *mut *const c_char)
        }).unwrap()
    }

    /// What Thunderbird asks to decide whether a key can be used.
    #[derive(Debug, PartialEq)]
    struct KeyState {
        revoked: bool,
        /// Seconds after the creation time, zero if the key does not
        /// expire.
        expiration: u32,
        /// Zero if the key has never been valid.
        valid_till: u64,
        sign: bool,
        certify: bool,
        encrypt: bool,
        primary_uid: Option<String>,
    }

    impl KeyState {
        /// A key that does not expire, of a certificate that is valid
        /// under the policy.
        fn valid(sign: bool, certify: bool, encrypt: bool, uid: &str)
                 -> Self
        {
            KeyState {
                revoked: false,
                expiration: 0,
                valid_till: u32::MAX as u64,
                sign, certify, encrypt,
                primary_uid: Some(uid.into()),
            }
        }

        /// A key of a certificate that is not valid, neither under
        /// the policy nor at all.  This is what we report if we
        /// cannot verify the certificate's self-signatures.
        /// Thunderbird does not show such a certificate.
        fn unusable() -> Self {
            KeyState {
                revoked: true,
                expiration: 1,
                valid_till: 0,
                sign: false,
                certify: false,
                encrypt: false,
                primary_uid: None,
            }
        }

        fn of(key: *mut RnpKey) -> Self {
            let allows = |usage: &str| {
                let usage = CString::new(usage).unwrap();
                get_bool(|b| unsafe {
                    rnp_key_allows_usage(key, usage.as_ptr(), b)
                })
            };

            let mut expiration = u32::MAX;
            let r = unsafe {
                rnp_key_get_expiration(key, &mut expiration as *mut _)
            };
            assert_eq!(r, RNP_SUCCESS);

            let mut valid_till = u64::MAX;
            let r = unsafe {
                rnp_key_valid_till64(key, &mut valid_till as *mut _)
            };
            assert_eq!(r, RNP_SUCCESS);

            KeyState {
                revoked: is_revoked(key),
                expiration,
                valid_till,
                sign: allows("sign"),
                certify: allows("certify"),
                encrypt: allows("encrypt"),
                primary_uid:
                    get_string(|s| unsafe { rnp_key_get_primary_uid(key, s) })
                    .ok(),
            }
        }
    }

    /// Returns the tags of the packets.
    fn packet_tags(data: &[u8]) -> Vec<openpgp::packet::Tag> {
        openpgp::PacketPile::from_bytes(data).unwrap()
            .children().map(|p| p.tag()).collect()
    }

    /// Returns whether there is a secret key packet.
    fn has_secret_key_packets(data: &[u8]) -> bool {
        use openpgp::packet::Tag;
        packet_tags(data).into_iter()
            .any(|t| t == Tag::SecretKey || t == Tag::SecretSubkey)
    }

    /// Parses a keyring, and returns the certificates sorted by
    /// fingerprint.
    fn parse_keyring(data: &[u8]) -> openpgp::Result<Vec<Cert>> {
        let mut certs = openpgp::cert::CertParser::from_bytes(data)?
            .collect::<openpgp::Result<Vec<Cert>>>()?;
        certs.sort_by_key(|c| c.fingerprint());
        Ok(certs)
    }

    /// Returns whether Sequoia can verify the self-signatures of the
    /// test vector's certificate with the cryptographic backend that
    /// we have been built with.
    ///
    /// If it cannot, the certificate is not valid.  The tests assert
    /// what we report in either case.
    fn can_verify(v: &crate::testdata::rfc9980::TestVector) -> bool {
        use openpgp::types::PublicKeyAlgorithm;

        let supported =
            PublicKeyAlgorithm::from(v.primary.algo).is_supported();
        // Every backend has Ed25519.
        assert!(supported || v.primary.algo >= 30, "{}", v.section);
        supported
    }

    /// Imports the Transferable Secret Keys of RFC 9980, Appendix A,
    /// with and without the secret key material, and asks what
    /// Thunderbird asks about an imported key.
    #[test]
    fn rfc9980_import() -> openpgp::Result<()> {
        use crate::testdata::rfc9980;

        for v in rfc9980::VECTORS {
            let fp = v.primary.fingerprint.to_string();
            let expected = |subkey: bool| {
                if ! can_verify(v) {
                    KeyState::unusable()
                } else if subkey {
                    // The usage is taken from the key flags.  Whether
                    // the backend supports the algorithm of the
                    // subkey is not considered here.
                    KeyState::valid(false, false, true, RFC9980_USERID)
                } else {
                    KeyState::valid(true, true, false, RFC9980_USERID)
                }
            };

            // With the secret key material.
            let ctx = new_ctx();
            assert_eq!(
                import_keys(ctx, v.tsk, RNP_LOAD_SAVE_PUBLIC_KEYS
                            | RNP_LOAD_SAVE_SECRET_KEYS),
                (RNP_SUCCESS, vec![("new".into(), "new".into(), fp.clone())]),
                "{}", v.section);
            assert_eq!(
                import_keys(ctx, v.tsk, RNP_LOAD_SAVE_PUBLIC_KEYS
                            | RNP_LOAD_SAVE_SECRET_KEYS),
                (RNP_SUCCESS,
                 vec![("unchanged".into(), "unchanged".into(), fp.clone())]),
                "{}", v.section);
            assert_eq!(key_counts(ctx), (0, 1), "{}", v.section);

            for (i, k) in v.keys().into_iter().enumerate() {
                let key = locate_by(ctx, "fingerprint", k.fingerprint);
                assert!(! key.is_null(), "{}", v.section);
                assert!(have_secret(key), "{}", v.section);
                assert!(! get_bool(|b| unsafe {
                    rnp_key_is_protected(key, b)
                }), "{}", v.section);
                assert_eq!(get_protection_type(key), "None",
                           "{}", v.section);
                assert_eq!(KeyState::of(key), expected(i == 1),
                           "{}", v.section);
                let r = unsafe { rnp_key_handle_destroy(key) };
                assert_eq!(r, RNP_SUCCESS);
            }

            let r = unsafe { rnp_ffi_destroy(ctx) };
            assert_eq!(r, RNP_SUCCESS);

            // Without the secret key material.
            let ctx = new_ctx();
            assert_eq!(
                import_keys(ctx, v.tsk, RNP_LOAD_SAVE_PUBLIC_KEYS),
                (RNP_SUCCESS,
                 vec![("new".into(), "unknown".into(), fp.clone())]),
                "{}", v.section);
            assert_eq!(key_counts(ctx), (1, 0), "{}", v.section);

            for (i, k) in v.keys().into_iter().enumerate() {
                let key = locate_by(ctx, "fingerprint", k.fingerprint);
                assert!(! key.is_null(), "{}", v.section);
                assert!(! have_secret(key), "{}", v.section);
                assert_eq!(get_protection_type(key), "Unknown",
                           "{}", v.section);
                assert_eq!(KeyState::of(key), expected(i == 1),
                           "{}", v.section);
                let r = unsafe { rnp_key_handle_destroy(key) };
                assert_eq!(r, RNP_SUCCESS);
            }

            // The secret key material can be added later.
            assert_eq!(
                import_keys(ctx, v.tsk, RNP_LOAD_SAVE_PUBLIC_KEYS
                            | RNP_LOAD_SAVE_SECRET_KEYS),
                (RNP_SUCCESS,
                 vec![("updated".into(), "updated".into(), fp.clone())]),
                "{}", v.section);
            assert_eq!(key_counts(ctx), (0, 1), "{}", v.section);

            let r = unsafe { rnp_ffi_destroy(ctx) };
            assert_eq!(r, RNP_SUCCESS);
        }
        Ok(())
    }

    /// What rnp_supports_feature says about the algorithm of a
    /// primary key must agree with what we report about its
    /// certificate: the Transferable Secret Keys of RFC 9980,
    /// Appendix A, are usable if and only if the algorithm of their
    /// primary key is reported as supported.
    ///
    /// Whether we can use the encryption subkeys is not tested here.
    #[test]
    fn rfc9980_supported_algorithms() -> openpgp::Result<()> {
        use crate::features::rnp_supports_feature;
        use crate::testdata::rfc9980;

        let supports = |name: &str| {
            let name = CString::new(name).unwrap();
            get_bool(|b| unsafe {
                rnp_supports_feature(
                    b"public key algorithm\x00".as_ptr() as *const c_char,
                    name.as_ptr(), b)
            })
        };

        // The primary keys in Appendix A.
        let mut seen = std::collections::BTreeSet::new();

        for v in rfc9980::VECTORS {
            let ctx = new_ctx();
            assert_eq!(
                import_keys(ctx, v.tsk, RNP_LOAD_SAVE_PUBLIC_KEYS
                            | RNP_LOAD_SAVE_SECRET_KEYS).0,
                RNP_SUCCESS, "{}", v.section);

            let key = locate_by(ctx, "fingerprint", v.primary.fingerprint);
            assert!(! key.is_null(), "{}", v.section);
            let alg = get_alg(key);
            assert_eq!(alg, v.primary.name, "{}", v.section);
            seen.insert(alg.clone());

            if supports(&alg) {
                assert_eq!(KeyState::of(key),
                           KeyState::valid(true, true, false, RFC9980_USERID),
                           "{}: {} is reported as supported",
                           v.section, alg);
            } else {
                assert_eq!(KeyState::of(key), KeyState::unusable(),
                           "{}: {} is reported as not supported",
                           v.section, alg);
            }
            let r = unsafe { rnp_key_handle_destroy(key) };
            assert_eq!(r, RNP_SUCCESS);

            // The subkeys are ML-KEM-768+X25519 or ML-KEM-1024+X448
            // keys.  We can ask about the name that we report for
            // them, whether or not the algorithm is supported.
            let key = locate_by(ctx, "fingerprint", v.subkey.fingerprint);
            assert!(! key.is_null(), "{}", v.section);
            let alg = get_alg(key);
            assert_eq!(alg, v.subkey.name, "{}", v.section);
            assert!(alg.starts_with("ML-KEM-"), "{}", v.section);
            let _ = supports(&alg);
            let r = unsafe { rnp_key_handle_destroy(key) };
            assert_eq!(r, RNP_SUCCESS);

            let r = unsafe { rnp_ffi_destroy(ctx) };
            assert_eq!(r, RNP_SUCCESS);
        }

        // Every signing algorithm of RFC 9980 has been asked about.
        assert_eq!(seen.into_iter().collect::<Vec<_>>(),
                   &["ED25519", "ML-DSA-65+ED25519", "ML-DSA-87+ED448",
                     "SLH-DSA-SHAKE-128f", "SLH-DSA-SHAKE-128s",
                     "SLH-DSA-SHAKE-256s"]);
        Ok(())
    }

    /// Exports the keys of RFC 9980, Appendix A, and imports what has
    /// been exported.
    #[test]
    fn rfc9980_export() -> openpgp::Result<()> {
        use crate::testdata::rfc9980;

        for v in rfc9980::VECTORS {
            let tsk = Cert::from_bytes(v.tsk)?;
            assert!(tsk.is_tsk());
            let fp = v.primary.fingerprint.to_string();

            let ctx = new_ctx();
            assert_eq!(
                import_keys(ctx, v.tsk, RNP_LOAD_SAVE_PUBLIC_KEYS
                            | RNP_LOAD_SAVE_SECRET_KEYS).0,
                RNP_SUCCESS);
            let key = locate_by(ctx, "fingerprint", v.primary.fingerprint);
            assert!(! key.is_null(), "{}", v.section);

            for (armored, secret) in [(false, false), (false, true),
                                      (true, false), (true, true)]
            {
                let what = format!("{}, armored: {}, secret: {}",
                                   v.section, armored, secret);
                let flags = RNP_KEY_EXPORT_SUBKEYS
                    | if secret { RNP_KEY_EXPORT_SECRET }
                      else { RNP_KEY_EXPORT_PUBLIC }
                    | if armored { RNP_KEY_EXPORT_ARMORED } else { 0 };
                let exported = export_key(key, flags);

                if ! can_verify(v) {
                    // Sequoia does not export what it cannot verify.
                    // We cannot expect to get the certificate, but we
                    // must not get anything else, and no secret key
                    // material unless we asked for it.
                    if ! exported.is_empty() {
                        assert_eq!(parse_keyring(&exported)?.iter()
                                   .map(|c| c.fingerprint().to_hex())
                                   .collect::<Vec<_>>(),
                                   &[fp.clone()], "{}", what);
                        assert!(secret || ! has_secret_key_packets(&exported),
                                "{}", what);
                    }
                    continue;
                }

                if armored {
                    let label = if secret { "PRIVATE" } else { "PUBLIC" };
                    assert!(exported.starts_with(
                        format!("-----BEGIN PGP {} KEY BLOCK-----\r\n", label)
                            .as_bytes()), "{}", what);
                }

                let cert = Cert::from_bytes(&exported)?;
                if secret {
                    assert!(cert.is_tsk(), "{}", what);
                    assert!(cert.as_tsk() == tsk.as_tsk(), "{}", what);
                } else {
                    assert!(! has_secret_key_packets(&exported), "{}", what);
                    assert_eq!(cert, v.cert(), "{}", what);
                }

                // And back.
                let other = new_ctx();
                assert_eq!(
                    import_keys(other, &exported, RNP_LOAD_SAVE_PUBLIC_KEYS
                                | RNP_LOAD_SAVE_SECRET_KEYS),
                    (RNP_SUCCESS,
                     vec![("new".into(),
                           if secret { "new" } else { "unknown" }.into(),
                           fp.clone())]),
                    "{}", what);
                assert_eq!(key_counts(other),
                           if secret { (0, 1) } else { (1, 0) }, "{}", what);
                assert_eq!(identifiers(other, "grip"), &[v.primary.grip],
                           "{}", what);
                let r = unsafe { rnp_ffi_destroy(other) };
                assert_eq!(r, RNP_SUCCESS);
            }

            // Without the subkeys.
            if can_verify(v) {
                let exported = export_key(key, RNP_KEY_EXPORT_PUBLIC);
                let cert = Cert::from_bytes(&exported)?;
                assert_eq!(cert.fingerprint().to_hex(), fp, "{}", v.section);
                assert_eq!(cert.keys().count(), 1, "{}", v.section);
                assert_eq!(cert.userids().count(), 1, "{}", v.section);
            }

            let r = unsafe { rnp_key_handle_destroy(key) };
            assert_eq!(r, RNP_SUCCESS);
            let r = unsafe { rnp_ffi_destroy(ctx) };
            assert_eq!(r, RNP_SUCCESS);
        }
        Ok(())
    }

    /// Saves the keyrings with the keys of RFC 9980, Appendix A, and
    /// loads them again.
    ///
    /// The keyrings are written as they are, whether or not the
    /// backend supports the algorithms.
    #[test]
    fn rfc9980_save_and_load() -> openpgp::Result<()> {
        use crate::testdata::rfc9980;

        // Every other key is imported without its secret key
        // material.
        let with_secret = |i: usize| i % 2 == 0;

        let ctx = new_ctx();
        let mut expected_pub = Vec::new();
        let mut expected_sec = Vec::new();
        for (i, v) in rfc9980::VECTORS.iter().enumerate() {
            let flags = RNP_LOAD_SAVE_PUBLIC_KEYS
                | if with_secret(i) { RNP_LOAD_SAVE_SECRET_KEYS } else { 0 };
            assert_eq!(import_keys(ctx, v.tsk, flags).0, RNP_SUCCESS,
                       "{}", v.section);
            if with_secret(i) {
                expected_sec.push(Cert::from_bytes(v.tsk)?);
            } else {
                expected_pub.push(v.cert());
            }
        }
        expected_pub.sort_by_key(|c| c.fingerprint());
        expected_sec.sort_by_key(|c| c.fingerprint());
        assert_eq!(expected_pub.len(), 3);
        assert_eq!(expected_sec.len(), 4);

        let check = |ctx: *mut RnpContext|
                     -> openpgp::Result<(Vec<u8>, Vec<u8>)>
        {
            assert_eq!(key_counts(ctx), (3, 4));

            let pubring = save_keys(ctx, RNP_LOAD_SAVE_PUBLIC_KEYS);
            assert!(! has_secret_key_packets(&pubring));
            assert_eq!(parse_keyring(&pubring)?, expected_pub);

            let secring = save_keys(ctx, RNP_LOAD_SAVE_SECRET_KEYS);
            let certs = parse_keyring(&secring)?;
            assert_eq!(certs.len(), expected_sec.len());
            for (cert, expected) in certs.iter().zip(expected_sec.iter()) {
                assert!(cert.is_tsk());
                assert!(cert.as_tsk() == expected.as_tsk());
            }

            let mut grips = identifiers(ctx, "grip");
            grips.sort();
            let mut expected_grips = rfc9980::VECTORS.iter()
                .map(|v| v.primary.grip.to_string()).collect::<Vec<_>>();
            expected_grips.sort();
            assert_eq!(grips, expected_grips);

            for (i, v) in rfc9980::VECTORS.iter().enumerate() {
                for k in v.keys() {
                    let key = locate_by(ctx, "grip", k.grip);
                    assert!(! key.is_null(), "{}", v.section);
                    assert_eq!(get_fprint(key), k.fingerprint,
                               "{}", v.section);
                    assert_eq!(get_alg(key), k.name, "{}", v.section);
                    assert_eq!(have_secret(key), with_secret(i),
                               "{}", v.section);
                    let r = unsafe { rnp_key_handle_destroy(key) };
                    assert_eq!(r, RNP_SUCCESS);
                }
            }

            Ok((pubring, secring))
        };

        let (pubring, secring) = check(ctx)?;
        let r = unsafe { rnp_ffi_destroy(ctx) };
        assert_eq!(r, RNP_SUCCESS);

        // Load what we saved, twice.
        let ctx = load_keys(&pubring, &secring);
        let (pubring, secring) = check(ctx)?;
        let r = unsafe { rnp_ffi_destroy(ctx) };
        assert_eq!(r, RNP_SUCCESS);

        let ctx = load_keys(&pubring, &secring);
        check(ctx)?;
        let r = unsafe { rnp_ffi_destroy(ctx) };
        assert_eq!(r, RNP_SUCCESS);

        // Secret key material in the public keyring is not loaded.
        let ctx = load_keys(&secring, &[]);
        assert_eq!(key_counts(ctx), (4, 0));
        let pubring = save_keys(ctx, RNP_LOAD_SAVE_PUBLIC_KEYS);
        assert!(! has_secret_key_packets(&pubring));
        assert_eq!(parse_keyring(&pubring)?,
                   expected_sec.iter().cloned()
                   .map(|c| c.strip_secret_key_material())
                   .collect::<Vec<_>>());
        let r = unsafe { rnp_ffi_destroy(ctx) };
        assert_eq!(r, RNP_SUCCESS);
        Ok(())
    }

    /// Returns a v6 certificate with secret key material and a
    /// subkey using an algorithm that we do not know, and the
    /// fingerprint of that subkey.
    ///
    /// 37 is not assigned by RFC 9580 or RFC 9980.  The key material
    /// is not key material of any algorithm.
    fn cert_with_unknown_subkey(secret: bool)
                                -> openpgp::Result<(Cert, Fingerprint)>
    {
        use openpgp::Profile;
        use openpgp::cert::CertBuilder;
        use openpgp::cert::SubkeyBuilder;
        use openpgp::crypto::mpi;
        use openpgp::packet::key::{Key6, SubordinateRole};
        use openpgp::types::{KeyFlags, PublicKeyAlgorithm};

        let (cert, _) = CertBuilder::general_purpose(Some("alice"))
            .set_profile(Profile::RFC9580)?
            .generate()?;
        let n = cert.keys().count();

        let creation_time = std::time::SystemTime::now()
            - std::time::Duration::new(60, 0);
        let public = mpi::PublicKey::Unknown {
            mpis: vec![].into_boxed_slice(),
            rest: vec![0x42; 64].into_boxed_slice(),
        };
        let unknown: Key<UnspecifiedParts, SubordinateRole> = if secret {
            Key6::with_secret(
                creation_time, PublicKeyAlgorithm::Unknown(37), public,
                mpi::SecretKeyMaterial::Unknown {
                    mpis: vec![].into_boxed_slice(),
                    rest: vec![0x17; 32].into(),
                }.into())?.parts_into_unspecified().into()
        } else {
            Key6::new(creation_time, PublicKeyAlgorithm::Unknown(37), public)?
                .parts_into_unspecified().into()
        };
        let unknown_fp = unknown.fingerprint();

        let signer = cert.primary_key().key().clone()
            .parts_into_secret()?.into_keypair()?;
        let cert = SubkeyBuilder::new(
            cert.with_policy(crate::NP, None)?,
            unknown,
            KeyFlags::empty().set_transport_encryption())?
            .set_primary_key_signer(signer)
            .attach_cert()?;
        assert!(cert.is_tsk());
        assert_eq!(cert.keys().count(), n + 1);
        Ok((cert, unknown_fp))
    }

    /// Removes the signatures that are not self-signatures, like
    /// Thunderbird does.
    fn remove_non_self_signatures(key: *mut RnpKey) {
        let r = unsafe {
            rnp_key_remove_signatures(
                key, RNP_KEY_SIGNATURE_NON_SELF_SIG,
                std::ptr::null_mut(), std::ptr::null_mut())
        };
        assert_eq!(r, RNP_SUCCESS);
    }

    /// A subkey using an algorithm that we do not know survives
    /// import, export, removing signatures, and saving and loading
    /// the keyring.
    #[test]
    fn unknown_algorithm_subkey_is_kept() -> openpgp::Result<()> {
        use openpgp::cert::CertBuilder;
        use openpgp::packet::signature::SignatureBuilder;
        use openpgp::types::SignatureType;

        let (cert, unknown_fp) = cert_with_unknown_subkey(false)?;
        let n = cert.keys().count();

        // Bob certifies Alice's user ID.
        let (bob, _) = CertBuilder::general_purpose(Some("bob")).generate()?;
        let mut bob_signer = bob.primary_key().key().clone()
            .parts_into_secret()?.into_keypair()?;
        let certification =
            SignatureBuilder::new(SignatureType::GenericCertification)
            .sign_userid_binding(
                &mut bob_signer, Some(cert.primary_key().key()),
                cert.userids().next().unwrap().userid())?;
        let (certified, _) = cert.clone().insert_packets(certification)?;
        assert_eq!(certified.userids().next().unwrap()
                   .certifications().count(), 1);

        let ctx = new_ctx();
        assert_eq!(
            import_keys(ctx, &certified.as_tsk().to_vec()?,
                        RNP_LOAD_SAVE_PUBLIC_KEYS | RNP_LOAD_SAVE_SECRET_KEYS),
            (RNP_SUCCESS, vec![("new".into(), "new".into(),
                                cert.fingerprint().to_hex())]));

        // The keyring has what we imported.
        let secring = save_keys(ctx, RNP_LOAD_SAVE_SECRET_KEYS);
        let saved = parse_keyring(&secring)?;
        assert_eq!(saved.len(), 1);
        assert!(saved[0].as_tsk() == certified.as_tsk());

        // The subkey cannot be used, although its binding signature
        // is valid and says that it is for encryption.
        let key = locate(ctx, &unknown_fp);
        let state = KeyState::of(key);
        assert!(state.revoked);
        assert_eq!(state.expiration, 1);
        assert!(! state.sign && ! state.certify && ! state.encrypt);
        let r = unsafe { rnp_key_handle_destroy(key) };
        assert_eq!(r, RNP_SUCCESS);

        // The others can.
        let key = locate(ctx, &cert.fingerprint());
        let state = KeyState::of(key);
        assert!(! state.revoked);
        assert!(state.certify);
        assert_eq!(state.primary_uid.as_deref(), Some("alice"));
        let r = unsafe { rnp_key_handle_destroy(key) };
        assert_eq!(r, RNP_SUCCESS);

        // It is exported.
        let key = locate(ctx, &cert.fingerprint());
        let exported = Cert::from_bytes(&export_key(
            key, RNP_KEY_EXPORT_PUBLIC | RNP_KEY_EXPORT_SUBKEYS))?;
        assert_eq!(exported,
                   certified.clone().strip_secret_key_material());
        assert!(exported.keys().any(|k| k.key().fingerprint() == unknown_fp));

        // Removing the certification leaves the subkey, and its
        // binding signature, alone.
        remove_non_self_signatures(key);
        let r = unsafe { rnp_key_handle_destroy(key) };
        assert_eq!(r, RNP_SUCCESS);

        let secring = save_keys(ctx, RNP_LOAD_SAVE_SECRET_KEYS);
        let saved = parse_keyring(&secring)?;
        assert_eq!(saved.len(), 1);
        assert!(saved[0].as_tsk() == cert.as_tsk());
        assert_eq!(saved[0].keys().count(), n);
        assert_eq!(saved[0].keys().subkeys()
                   .filter(|k| k.key().fingerprint() == unknown_fp)
                   .map(|k| k.self_signatures().count())
                   .collect::<Vec<_>>(),
                   &[1]);
        let r = unsafe { rnp_ffi_destroy(ctx) };
        assert_eq!(r, RNP_SUCCESS);

        // And it is loaded again.
        let ctx = load_keys(&[], &secring);
        assert_eq!(key_counts(ctx), (0, 1));
        let key = locate(ctx, &unknown_fp);
        assert!(is_sub(key));
        assert_eq!(get_alg(key), "unknown");
        let r = unsafe { rnp_key_handle_destroy(key) };
        assert_eq!(r, RNP_SUCCESS);
        assert!(parse_keyring(&save_keys(ctx, RNP_LOAD_SAVE_SECRET_KEYS))?[0]
                .as_tsk() == cert.as_tsk());
        let r = unsafe { rnp_ffi_destroy(ctx) };
        assert_eq!(r, RNP_SUCCESS);
        Ok(())
    }

    /// A secret subkey using an algorithm that we do not know is not
    /// a key to Sequoia, but a packet that it does not understand.
    /// It stays in the secret keyring, and it is never part of a
    /// public key that we export.
    #[test]
    fn unknown_algorithm_secret_subkey_is_kept() -> openpgp::Result<()> {
        use openpgp::cert::CertBuilder;
        use openpgp::packet::Tag;

        let (cert, unknown_fp) = cert_with_unknown_subkey(true)?;
        let n = cert.keys().count();
        let tsk = cert.as_tsk().to_vec()?;

        // This is how Sequoia reads it.
        let parsed = Cert::from_bytes(&tsk)?;
        assert_eq!(parsed.keys().count(), n - 1);
        assert_eq!(parsed.unknowns().map(|u| u.unknown().tag())
                   .collect::<Vec<_>>(),
                   &[Tag::SecretSubkey]);
        let count_secret_subkeys = |data: &[u8]| {
            packet_tags(data).into_iter()
                .filter(|t| *t == Tag::SecretSubkey).count()
        };
        assert_eq!(count_secret_subkeys(&tsk), n - 1);

        let ctx = new_ctx();
        assert_eq!(
            import_keys(ctx, &tsk,
                        RNP_LOAD_SAVE_PUBLIC_KEYS | RNP_LOAD_SAVE_SECRET_KEYS),
            (RNP_SUCCESS, vec![("new".into(), "new".into(),
                                cert.fingerprint().to_hex())]));
        assert_eq!(key_counts(ctx), (0, 1));

        // The keys that we know are there, the other one is not a
        // key.
        let key = locate(ctx, &cert.fingerprint());
        let mut subkeys: usize = 0;
        let r = unsafe {
            rnp_key_get_subkey_count(key, &mut subkeys as *mut _)
        };
        assert_eq!(r, RNP_SUCCESS);
        assert_eq!(subkeys, n - 2);
        assert!(locate_by(ctx, "fingerprint", &unknown_fp.to_hex())
                .is_null());

        // The secret keyring has all of it.
        let check_secring = |ctx: *mut RnpContext, expected: &Cert|
                             -> openpgp::Result<()>
        {
            let secring = save_keys(ctx, RNP_LOAD_SAVE_SECRET_KEYS);
            assert_eq!(count_secret_subkeys(&secring), n - 1);
            let saved = parse_keyring(&secring)?;
            assert_eq!(saved.len(), 1);
            assert!(saved[0].as_tsk() == expected.as_tsk());
            assert_eq!(saved[0].unknowns().count(), 1);
            Ok(())
        };
        check_secring(ctx, &parsed)?;

        // A public key that we export has no secret key material.
        for flags in [RNP_KEY_EXPORT_PUBLIC | RNP_KEY_EXPORT_SUBKEYS,
                      RNP_KEY_EXPORT_PUBLIC | RNP_KEY_EXPORT_SUBKEYS
                      | RNP_KEY_EXPORT_ARMORED]
        {
            let exported = Cert::from_bytes(&export_key(key, flags))?;
            assert!(! exported.is_tsk());
            assert!(! has_secret_key_packets(&exported.to_vec()?));
            assert_eq!(exported.keys().count(), n - 1);
            assert_eq!(exported.unknowns().count(), 0);
        }

        // Removing signatures does not remove it.
        remove_non_self_signatures(key);
        check_secring(ctx, &parsed)?;

        // A signature that someone else made, and that follows the
        // packet that we do not understand, is kept with it, unless
        // we are asked to remove such signatures.
        let (bob, _) = CertBuilder::general_purpose(Some("bob")).generate()?;
        let mut with_sig = parsed.as_tsk().to_vec()?;
        Packet::from(bob.userids().next().unwrap()
                     .self_signatures().next().unwrap().clone())
            .serialize(&mut with_sig)?;
        let with_sig = Cert::from_bytes(&with_sig)?;
        assert_eq!(with_sig.unknowns().next().unwrap()
                   .certifications().count(), 1);
        assert_eq!(
            import_keys(ctx, &with_sig.as_tsk().to_vec()?,
                        RNP_LOAD_SAVE_PUBLIC_KEYS | RNP_LOAD_SAVE_SECRET_KEYS),
            (RNP_SUCCESS, vec![("updated".into(), "updated".into(),
                                cert.fingerprint().to_hex())]));
        check_secring(ctx, &with_sig)?;

        let r = unsafe {
            rnp_key_remove_signatures(
                key, 0, std::ptr::null_mut(), std::ptr::null_mut())
        };
        assert_eq!(r, RNP_SUCCESS);
        check_secring(ctx, &with_sig)?;

        remove_non_self_signatures(key);
        check_secring(ctx, &parsed)?;

        let r = unsafe { rnp_key_handle_destroy(key) };
        assert_eq!(r, RNP_SUCCESS);

        // And it is loaded again.
        let secring = save_keys(ctx, RNP_LOAD_SAVE_SECRET_KEYS);
        let r = unsafe { rnp_ffi_destroy(ctx) };
        assert_eq!(r, RNP_SUCCESS);

        let ctx = load_keys(&[], &secring);
        assert_eq!(key_counts(ctx), (0, 1));
        check_secring(ctx, &parsed)?;
        let r = unsafe { rnp_ffi_destroy(ctx) };
        assert_eq!(r, RNP_SUCCESS);
        Ok(())
    }

    /// Pretends to sign with an algorithm that we do not know.
    ///
    /// What it returns is not a signature of any algorithm, and
    /// nothing can verify it.
    struct UnknownAlgorithmSigner(Key<PublicParts, UnspecifiedRole>);

    impl openpgp::crypto::Signer for UnknownAlgorithmSigner {
        fn public(&self) -> &Key<PublicParts, UnspecifiedRole> {
            &self.0
        }

        fn sign(&mut self, _: HashAlgorithm, _: &[u8])
                -> openpgp::Result<openpgp::crypto::mpi::Signature>
        {
            Ok(openpgp::crypto::mpi::Signature::Unknown {
                mpis: vec![].into_boxed_slice(),
                rest: vec![0x55; 64].into_boxed_slice(),
            })
        }
    }

    /// A certificate with a primary key using an algorithm that we do
    /// not know cannot be used, and Thunderbird does not see it.  It
    /// does not get in the way of the other certificates, and it
    /// stays in the keyring.
    #[test]
    fn unknown_algorithm_primary_key_is_kept() -> openpgp::Result<()> {
        use openpgp::Profile;
        use openpgp::cert::CertBuilder;
        use openpgp::crypto::mpi;
        use openpgp::packet::UserID;
        use openpgp::packet::key::{Key6, PrimaryRole};
        use openpgp::packet::signature::SignatureBuilder;
        use openpgp::types::{KeyFlags, PublicKeyAlgorithm, SignatureType};

        // 37 is not assigned by RFC 9580 or RFC 9980.
        let primary: Key<PublicParts, PrimaryRole> =
            Key6::new(std::time::SystemTime::now()
                      - std::time::Duration::new(60, 0),
                      PublicKeyAlgorithm::Unknown(37),
                      mpi::PublicKey::Unknown {
                          mpis: vec![].into_boxed_slice(),
                          rest: vec![0x99; 48].into_boxed_slice(),
                      })?.into();
        let mut signer =
            UnknownAlgorithmSigner(primary.clone().role_into_unspecified());
        let userid = UserID::from("future <future@example.org>");
        let direct = SignatureBuilder::new(SignatureType::DirectKey)
            .set_key_flags(KeyFlags::empty().set_certification())?
            .sign_direct_key(&mut signer, Some(&primary))?;
        let binding =
            SignatureBuilder::new(SignatureType::PositiveCertification)
            .sign_userid_binding(&mut signer, Some(&primary), &userid)?;
        let future = Cert::from_packets(
            vec![Packet::from(primary), direct.into(),
                 userid.into(), binding.into()].into_iter())?;
        assert_eq!(future.userids().count(), 1);
        assert_eq!(future.bad_signatures().count(), 2);

        let (v4, _) = CertBuilder::general_purpose(Some("v4"))
            .set_profile(Profile::RFC4880)?
            .generate()?;
        let (v6, _) = CertBuilder::general_purpose(Some("v6"))
            .set_profile(Profile::RFC9580)?
            .generate()?;
        let v4 = v4.strip_secret_key_material();
        let v6 = v6.strip_secret_key_material();

        // One keyring, the certificate that we do not understand in
        // the middle.
        let mut keyring = v4.to_vec()?;
        keyring.extend_from_slice(&future.to_vec()?);
        keyring.extend_from_slice(&v6.to_vec()?);

        let mut expected = vec![v4.clone(), future.clone(), v6.clone()];
        expected.sort_by_key(|c| c.fingerprint());

        let ctx = new_ctx();
        assert_eq!(
            import_keys(ctx, &keyring, RNP_LOAD_SAVE_PUBLIC_KEYS),
            (RNP_SUCCESS,
             [&v4, &future, &v6].iter().map(|c| {
                 ("new".into(), "unknown".into(), c.fingerprint().to_hex())
             }).collect()));

        let check = |ctx: *mut RnpContext| -> openpgp::Result<Vec<u8>> {
            assert_eq!(key_counts(ctx), (3, 0));

            // Thunderbird enumerates the keys by keygrip, and there
            // is none for a key that we do not understand.
            assert_eq!(identifiers(ctx, "grip").len(), 2);
            assert_eq!(identifiers(ctx, "fingerprint").len(), 3);

            let key = locate(ctx, &future.fingerprint());
            assert_eq!(get_alg(key), "unknown");
            assert_eq!(get_bits(key), Err(RNP_ERROR_NO_SUITABLE_KEY));
            assert_eq!(get_string(|s| unsafe { rnp_key_get_grip(key, s) }),
                       Err(RNP_ERROR_GENERIC));
            assert!(! have_secret(key));
            assert_eq!(KeyState::of(key), KeyState::unusable());
            let r = unsafe { rnp_key_handle_destroy(key) };
            assert_eq!(r, RNP_SUCCESS);

            // The others are as usable as they are without it.
            for cert in [&v4, &v6] {
                let key = locate(ctx, &cert.fingerprint());
                let state = KeyState::of(key);
                assert!(! state.revoked);
                assert!(state.certify);
                assert!(state.valid_till > 0);
                assert_eq!(state.primary_uid.as_deref(),
                           Some(if cert == &v4 { "v4" } else { "v6" }));
                let r = unsafe { rnp_key_handle_destroy(key) };
                assert_eq!(r, RNP_SUCCESS);
            }

            // It is saved as it is.
            let pubring = save_keys(ctx, RNP_LOAD_SAVE_PUBLIC_KEYS);
            assert_eq!(parse_keyring(&pubring)?, expected);
            Ok(pubring)
        };

        let pubring = check(ctx)?;

        // Removing signatures does not remove what we cannot verify.
        let key = locate(ctx, &future.fingerprint());
        remove_non_self_signatures(key);
        let r = unsafe { rnp_key_handle_destroy(key) };
        assert_eq!(r, RNP_SUCCESS);
        check(ctx)?;

        let r = unsafe { rnp_ffi_destroy(ctx) };
        assert_eq!(r, RNP_SUCCESS);

        // And it is loaded again.
        let ctx = load_keys(&pubring, &[]);
        check(ctx)?;
        let r = unsafe { rnp_ffi_destroy(ctx) };
        assert_eq!(r, RNP_SUCCESS);
        Ok(())
    }

    const RNP_ERROR_KEY_NOT_FOUND: u32 =
        crate::error::RNP_ERROR_KEY_NOT_FOUND.as_u32();

    /// Returns what rnp_op_encrypt_add_recipient says about the key.
    fn add_recipient(ctx: *mut RnpContext, key: *mut RnpKey) -> RnpResult {
        use crate::op_encrypt::*;

        let message = b"Hello";
        let mut input: *mut RnpInput = std::ptr::null_mut();
        let r = unsafe {
            rnp_input_from_memory(
                &mut input as *mut *mut _,
                message.as_ptr(), message.len(), false)
        };
        assert_eq!(r, RNP_SUCCESS);
        let output = output_to_memory();

        let mut op: *mut RnpOpEncrypt = std::ptr::null_mut();
        let r = unsafe {
            rnp_op_encrypt_create(&mut op as *mut *mut _, ctx, input, output)
        };
        assert_eq!(r, RNP_SUCCESS);

        let result = unsafe { rnp_op_encrypt_add_recipient(op, key) };

        let r = unsafe { rnp_op_encrypt_destroy(op) };
        assert_eq!(r, RNP_SUCCESS);
        let r = unsafe { rnp_input_destroy(input) };
        assert_eq!(r, RNP_SUCCESS);
        let r = unsafe { rnp_output_destroy(output) };
        assert_eq!(r, RNP_SUCCESS);
        result
    }

    /// Returns the version of the key packet.
    fn get_version(key: *mut RnpKey) -> u32 {
        let mut version: u32 = 0;
        let r = unsafe { rnp_key_get_version(key, &mut version as *mut _) };
        assert_eq!(r, RNP_SUCCESS);
        version
    }

    /// RFC 9980, Section 3.5: the algorithms of RFC 9980 are to be
    /// used only in v6 keys, except for ML-KEM-768+X25519, which is
    /// also allowed in v4 encryption subkeys.
    ///
    /// A v4 subkey using one of the other algorithms is kept, it is
    /// listed, and it is reported as unusable, although its binding
    /// signature is valid.  The rest of the certificate is not
    /// affected.
    ///
    /// The subkeys in this test are not keys, so this test does the
    /// same with every cryptographic backend, with one exception that
    /// is marked.
    #[test]
    fn rfc9980_key_version_binding_subkeys() -> openpgp::Result<()> {
        use openpgp::types::PublicKeyAlgorithm;
        use crate::testdata::key_version_binding::*;

        for version in [4, 6] {
            for algo in ALGORITHMS {
                let (cert, fp) = cert_with_subkey(version, algo)?;
                let allowed = version == 6
                    || algo == PublicKeyAlgorithm::MLKEM768_X25519;

                let ctx = new_ctx();
                assert_eq!(
                    import_keys(ctx, &cert.to_vec()?,
                                RNP_LOAD_SAVE_PUBLIC_KEYS),
                    (RNP_SUCCESS,
                     vec![("new".into(), "unknown".into(),
                           cert.fingerprint().to_hex())]),
                    "v{} {}", version, algo);
                assert_eq!(key_counts(ctx), (1, 0));

                // The subkey is there.
                let key = locate(ctx, &fp);
                assert!(is_sub(key));
                assert_eq!(get_version(key), version as u32);

                // rnp_key_valid_till64 does not ask the policy, see
                // there.  The binding signature is valid, so the
                // result is not 0.  Whether the key can be used is a
                // question to the policy.
                let state = KeyState::of(key);
                assert!(state.valid_till > 0, "v{} {}", version, algo);
                assert_eq!(state.primary_uid.as_deref(), Some(USERID));
                assert!(! state.sign && ! state.certify);
                if allowed {
                    assert!(! state.revoked, "v{} {}", version, algo);
                    assert_ne!(state.expiration, 1, "v{} {}", version, algo);
                    assert_eq!(state.encrypt, is_kem(algo),
                               "v{} {}", version, algo);
                } else {
                    // This is how we report a key that the policy
                    // rejects.
                    assert!(state.revoked, "v{} {}", version, algo);
                    assert_eq!(state.expiration, 1, "v{} {}", version, algo);
                    assert!(! state.encrypt, "v{} {}", version, algo);
                }
                let r = unsafe { rnp_key_handle_destroy(key) };
                assert_eq!(r, RNP_SUCCESS);

                // The primary key is usable either way.
                let key = locate(ctx, &cert.fingerprint());
                let state = KeyState::of(key);
                assert!(! state.revoked, "v{} {}", version, algo);
                assert_ne!(state.expiration, 1, "v{} {}", version, algo);
                assert!(state.valid_till > 0, "v{} {}", version, algo);
                assert!(state.certify, "v{} {}", version, algo);
                assert_eq!(state.primary_uid.as_deref(), Some(USERID));

                // The subkey is the only key of the certificate that
                // is for encryption, if it is.  We encrypt to it if
                // the policy accepts it, and, this is the exception,
                // if the cryptographic backend supports the
                // algorithm.
                assert_eq!(
                    add_recipient(ctx, key),
                    if allowed && is_kem(algo) && algo.is_supported() {
                        RNP_SUCCESS
                    } else {
                        RNP_ERROR_KEY_NOT_FOUND
                    },
                    "v{} {}", version, algo);
                let r = unsafe { rnp_key_handle_destroy(key) };
                assert_eq!(r, RNP_SUCCESS);

                // The certificate is saved as it is, and it is loaded
                // again.
                let pubring = save_keys(ctx, RNP_LOAD_SAVE_PUBLIC_KEYS);
                assert_eq!(parse_keyring(&pubring)?, vec![cert.clone()]);
                let r = unsafe { rnp_ffi_destroy(ctx) };
                assert_eq!(r, RNP_SUCCESS);

                let ctx = load_keys(&pubring, &[]);
                assert_eq!(key_counts(ctx), (1, 0));
                let key = locate(ctx, &fp);
                assert_eq!(KeyState::of(key).revoked, ! allowed,
                           "v{} {}", version, algo);
                let r = unsafe { rnp_key_handle_destroy(key) };
                assert_eq!(r, RNP_SUCCESS);
                let r = unsafe { rnp_ffi_destroy(ctx) };
                assert_eq!(r, RNP_SUCCESS);
            }
        }
        Ok(())
    }

    /// RFC 9980, Section 3.5: no algorithm of RFC 9980 is allowed in
    /// a v4 primary key.
    ///
    /// If the cryptographic backend supports the algorithms, a v4
    /// certificate with such a primary key and valid self-signatures
    /// can be made.  It is kept, it is listed, and it is reported as
    /// unusable.
    ///
    /// Without valid self-signatures, which is all that we can make
    /// with the other backends, and all that there can be for the
    /// ML-KEM composites, such a certificate is not valid in the
    /// first place.  That is tested with every backend.
    #[test]
    fn rfc9980_key_version_binding_primary_keys() -> openpgp::Result<()> {
        use crate::testdata::key_version_binding::*;

        for algo in ALGORITHMS {
            // No self-signature.
            let cert = v4_primary_key_without_signature(algo)?;
            let ctx = new_ctx();
            assert_eq!(
                import_keys(ctx, &cert.to_vec()?, RNP_LOAD_SAVE_PUBLIC_KEYS),
                (RNP_SUCCESS,
                 vec![("new".into(), "unknown".into(),
                       cert.fingerprint().to_hex())]),
                "{}", algo);
            let key = locate(ctx, &cert.fingerprint());
            assert_eq!(get_version(key), 4);
            assert_eq!(KeyState::of(key), KeyState::unusable(), "{}", algo);
            assert_eq!(add_recipient(ctx, key), RNP_ERROR_KEY_NOT_FOUND,
                       "{}", algo);
            let r = unsafe { rnp_key_handle_destroy(key) };
            assert_eq!(r, RNP_SUCCESS);
            assert_eq!(
                parse_keyring(&save_keys(ctx, RNP_LOAD_SAVE_PUBLIC_KEYS))?,
                vec![cert]);
            let r = unsafe { rnp_ffi_destroy(ctx) };
            assert_eq!(r, RNP_SUCCESS);

            // A valid self-signature.
            if ! FAST_SIGNATURE_ALGORITHMS.contains(&algo) {
                // The ML-KEM composites cannot make signatures, and
                // two of the SLH-DSA variants are too slow.
                continue;
            }
            if ! algo.is_supported() {
                assert!(v4_cert_with_primary_key(algo).is_err());
                eprintln!("{} is not supported by the cryptographic \
                           backend, not testing a valid v4 certificate",
                          algo);
                continue;
            }

            let cert = v4_cert_with_primary_key(algo)?;
            let fp = cert.fingerprint();
            let ctx = new_ctx();
            assert_eq!(
                import_keys(ctx, &cert.as_tsk().to_vec()?,
                            RNP_LOAD_SAVE_PUBLIC_KEYS
                            | RNP_LOAD_SAVE_SECRET_KEYS),
                (RNP_SUCCESS,
                 vec![("new".into(), "new".into(), fp.to_hex())]),
                "{}", algo);
            assert_eq!(key_counts(ctx), (0, 1));

            let key = locate(ctx, &fp);
            assert!(! is_sub(key));
            assert_eq!(get_version(key), 4);
            assert!(have_secret(key));
            // The self-signature is valid, and rnp_key_valid_till64
            // does not ask the policy, see there.  The policy
            // rejects the key, so it is reported as revoked and
            // expired, and it allows nothing.
            assert_eq!(KeyState::of(key),
                       KeyState {
                           revoked: true,
                           expiration: 1,
                           valid_till: u32::MAX as u64,
                           sign: false,
                           certify: false,
                           encrypt: false,
                           primary_uid: Some(USERID.into()),
                       },
                       "{}", algo);
            let r = unsafe { rnp_key_handle_destroy(key) };
            assert_eq!(r, RNP_SUCCESS);

            // It is saved as it is, and it is loaded again.
            let secring = save_keys(ctx, RNP_LOAD_SAVE_SECRET_KEYS);
            let saved = parse_keyring(&secring)?;
            assert_eq!(saved.len(), 1);
            assert!(saved[0].as_tsk() == cert.as_tsk());
            let r = unsafe { rnp_ffi_destroy(ctx) };
            assert_eq!(r, RNP_SUCCESS);

            let ctx = load_keys(&[], &secring);
            assert_eq!(key_counts(ctx), (0, 1));
            let key = locate(ctx, &fp);
            let state = KeyState::of(key);
            assert!(state.revoked, "{}", algo);
            assert!(! state.sign && ! state.certify, "{}", algo);
            let r = unsafe { rnp_key_handle_destroy(key) };
            assert_eq!(r, RNP_SUCCESS);
            let r = unsafe { rnp_ffi_destroy(ctx) };
            assert_eq!(r, RNP_SUCCESS);
        }
        Ok(())
    }
}
