use std::{
    time::{
        UNIX_EPOCH,
    },
};

use libc::{
    c_char,
};

use sequoia_openpgp as openpgp;
use openpgp::{
    KeyID,
    packet::{
        Signature,
    },
};

use crate::{
    RnpResult,
    RnpContext,
    RnpKey,
    str_to_rnp_buffer,
    conversions::ToRnpId,
    error::*,
};

pub struct RnpSignature {
    ctx: *const RnpContext,
    sig: Signature,
    // Whether the signature is known to be good.  If None, then we
    // don't know.
    valid: Option<bool>,
}

impl std::ops::Deref for RnpSignature {
    type Target = Signature;

    fn deref(&self) -> &Self::Target {
        &self.sig
    }
}

impl RnpSignature {
    pub fn new(ctx: *const RnpContext, sig: Signature, valid: Option<bool>)
        -> Self
    {
        Self {
            ctx,
            sig,
            valid,
        }
    }
}

#[no_mangle] pub unsafe extern "C"
fn rnp_signature_handle_destroy(sig: *mut RnpSignature) -> RnpResult {
    rnp_function!(rnp_signature_handle_destroy, crate::TRACE);
    if ! sig.is_null() {
        drop(Box::from_raw(sig));
    }
    rnp_success!()
}

#[no_mangle] pub unsafe extern "C"
fn rnp_signature_get_hash_alg(sig: *const RnpSignature,
                              hash_alg: *mut *mut c_char)
                           -> RnpResult {
    rnp_function!(rnp_signature_get_keyid, crate::TRACE);
    let sig = assert_ptr_ref!(sig);
    assert_ptr!(hash_alg);

    *hash_alg = str_to_rnp_buffer(sig.hash_algo().to_rnp_id());
    rnp_success!()
}


// XXX: This interface is terrible.  It retrieves issuer information
// from the signature in an unsafe way.
#[no_mangle] pub unsafe extern "C"
fn rnp_signature_get_keyid(sig: *const RnpSignature,
                           keyid: *mut *mut c_char)
                           -> RnpResult {
    rnp_function!(rnp_signature_get_keyid, crate::TRACE);
    assert_ptr!(sig);
    assert_ptr!(keyid);
    *keyid =
        if let Some(issuer) = (*sig).get_issuers().get(0) {
            str_to_rnp_buffer(format!("{:X}", KeyID::from(issuer)))
        } else {
            std::ptr::null_mut()
        };
    rnp_success!()
}

#[no_mangle] pub unsafe extern "C"
fn rnp_signature_get_creation(sig: *const RnpSignature,
                              creation: *mut u32)
                              -> RnpResult {
    rnp_function!(rnp_signature_get_creation, crate::TRACE);
    assert_ptr!(sig);
    assert_ptr!(creation);

    *creation =
        (*sig).signature_creation_time()
        .map(|t| t.duration_since(UNIX_EPOCH)
             .expect("creation time is representable as epoch")
             .as_secs() as u32)
        .unwrap_or(0);
    rnp_success!()
}

#[no_mangle] pub unsafe extern "C"
fn rnp_signature_get_signer(sig: *const RnpSignature,
                            key: *mut *mut RnpKey)
                            -> RnpResult {
    rnp_function!(rnp_signature_get_signer, crate::TRACE);
    assert_ptr!(sig);
    assert_ptr!(key);
    let sig = &*sig;

    for issuer in sig.get_issuers() {
        if let Some(cert) = (*sig.ctx).cert(&issuer.clone().into()) {
            let k = cert.keys().key_handle(issuer).nth(0)
                .expect("must be there").key().clone()
                .parts_into_unspecified();
            *key = Box::into_raw(Box::new(
                RnpKey::new((*sig).ctx as *mut _, k, &cert)));
            rnp_success!();
        }
    }
    *key = std::ptr::null_mut();
    rnp_success!()
}

#[no_mangle] pub unsafe extern "C"
fn rnp_signature_is_valid(sig: *const RnpSignature,
                          flags: u32)
                          -> RnpResult {
    rnp_function!(rnp_signature_is_valid, crate::TRACE);
    assert_ptr!(sig);
    let sig = &*sig;

    // According to the rnp documentation, flags must currently be
    // zero.
    if flags != 0 {
        rnp_return_status!(RNP_ERROR_BAD_PARAMETERS);
    }

    if let Some(valid) = sig.valid {
        if valid {
            // The signature could have expired in the meantime.  (In
            // fact, the key that created the signature could have
            // expired, but we ignore that :/.)
            if sig.signature_alive(None, None).is_ok() {
                rnp_return_status!(RNP_SUCCESS);
            } else {
                rnp_return_status!(RNP_ERROR_SIGNATURE_EXPIRED);
            }
        } else {
            rnp_return_status!(RNP_ERROR_SIGNATURE_INVALID);
        }
    }

    // XXX: We need to check the signature, but we don't have enough
    // context.  This only effects third-party certifications and
    // third-party revocations (right now, all other places where an
    // RnpSignature is created include set the signature's validity).
    // As Thunderbird doesn't appear to care about the validity of
    // these signatures, don't complicate the implementation... yet.
    rnp_return_status!(RNP_ERROR_SIGNATURE_INVALID)
}

#[no_mangle] pub unsafe extern "C"
fn rnp_signature_get_features(sig: *const RnpSignature,
                              features: *mut u32)
                              -> RnpResult {
    rnp_function!(rnp_signature_get_features, crate::TRACE);
    let sig = assert_ptr_ref!(sig);
    let features = assert_ptr_mut!(features);

    // Note: as of now, RNP only considers the first 8 bits, which is
    // hopefully enough for the time being, but we consider the first
    // 32 bits, in the hope that we'll never use as many.
    *features = sig.sig.features()
        .map(|f| 0
             | (*f.as_bitfield().as_ref().get(0).unwrap_or(&0) as u32) << 0
             | (*f.as_bitfield().as_ref().get(1).unwrap_or(&0) as u32) << 8
             | (*f.as_bitfield().as_ref().get(2).unwrap_or(&0) as u32) << 16
             | (*f.as_bitfield().as_ref().get(3).unwrap_or(&0) as u32) << 24)
        .unwrap_or(0);

    rnp_success!()
}

/// Replacement for ComponentAmalgamation::signatures.
///
/// This started out as a replacement for a function that was not
/// available in sequoia-openpgp 1.0.  However, we now mark
/// self-signatures as valid, a functionality that is not available in
/// the stock version of the function.
use openpgp::cert::amalgamation::ComponentAmalgamation;
pub fn ca_signatures<'a, T>(ca: &ComponentAmalgamation<'a, T>)
                            -> impl Iterator<Item = (&'a Signature, Option<bool>)>
{
    use openpgp::packet::signature::subpacket::SubpacketTag;
    ca.signatures().map(|sig| {
        // If Sequoia verified a signature, it will set the
        // authenticated flag of subpackets to true.  Thus, we know a
        // signature is "valid" iff the signature creation time has
        // been authenticated.
        let valid = sig.subpacket(SubpacketTag::SignatureCreationTime)
            .map(|sct| if sct.authenticated() { Some(true) } else { None })
            .unwrap_or(None);

        (sig, valid)
    })
}
