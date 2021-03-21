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
    error::*,
};

pub struct RnpSignature {
    ctx: *const RnpContext,
    sig: Signature,
}

impl std::ops::Deref for RnpSignature {
    type Target = Signature;

    fn deref(&self) -> &Self::Target {
        &self.sig
    }
}

impl RnpSignature {
    pub fn new(ctx: *const RnpContext, sig: Signature) -> Self {
        Self {
            ctx,
            sig
        }
    }
}

#[no_mangle] pub unsafe extern "C"
fn rnp_signature_handle_destroy(sig: *mut RnpSignature) -> RnpResult {
    if ! sig.is_null() {
        drop(Box::from_raw(sig));
    }
    RNP_SUCCESS
}

// XXX: This interface is terrible.  It retrieves issuer information
// from the signature in an unsafe way.
#[no_mangle] pub unsafe extern "C"
fn rnp_signature_get_keyid(sig: *const RnpSignature,
                           keyid: *mut *mut c_char)
                           -> RnpResult {
    assert_ptr!(sig);
    assert_ptr!(keyid);
    *keyid =
        if let Some(issuer) = (*sig).get_issuers().get(0) {
            str_to_rnp_buffer(format!("{:X}", KeyID::from(issuer)))
        } else {
            std::ptr::null_mut()
        };
    RNP_SUCCESS
}

#[no_mangle] pub unsafe extern "C"
fn rnp_signature_get_creation(sig: *const RnpSignature,
                              creation: *mut u32)
                              -> RnpResult {
    assert_ptr!(sig);
    assert_ptr!(creation);

    *creation =
        (*sig).signature_creation_time()
        .map(|t| t.duration_since(UNIX_EPOCH)
             .expect("creation time is representable as epoch")
             .as_secs() as u32)
        .unwrap_or(0);
    RNP_SUCCESS
}

#[no_mangle] pub unsafe extern "C"
fn rnp_signature_get_signer(sig: *const RnpSignature,
                            key: *mut *mut RnpKey)
                            -> RnpResult {
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
            return RNP_SUCCESS;
        }
    }
    *key = std::ptr::null_mut();
    RNP_SUCCESS
}
