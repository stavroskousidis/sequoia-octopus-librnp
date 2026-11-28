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
    c_str_to_rnp_buffer_lossy,
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
    arg!(sig);

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
    let hash_alg = assert_ptr_mut!(hash_alg);

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
    let sig = assert_ptr_ref!(sig);
    let keyid = assert_ptr_mut!(keyid);

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
    let sig = assert_ptr_ref!(sig);
    let creation = assert_ptr_mut!(creation);

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
    let sig = assert_ptr_ref!(sig);
    let key = assert_ptr_mut!(key);

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
    let sig = assert_ptr_ref!(sig);
    arg!(flags);

    // According to the rnp documentation, flags must currently be
    // zero.
    if flags != 0 {
        rnp_return_status!(RNP_ERROR_BAD_PARAMETERS);
    }

    if let Some(valid) = sig.valid {
        if valid {
            // We know that the signature is cryptographically valid,
            // but whoever established that did not necessarily ask
            // the policy: for the signatures of a certificate, we
            // report what Sequoia verified.  RFC 9980 requires us to
            // reject signatures that violate its rules.
            if let Err(err) = crate::policy::check_signature(sig) {
                warn!("{}", err);
                rnp_return_status!(RNP_ERROR_SIGNATURE_INVALID);
            }

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

/// Returns the code and the text of the signature's Reason for
/// Revocation subpacket.
///
/// `code` and `reason` may each be NULL.  Like RNP, we return empty
/// strings if the signature has no such subpacket, and an empty
/// string for a code that RNP has no name for.  We do not check that
/// the signature is a revocation.
#[no_mangle] pub unsafe extern "C"
fn rnp_signature_get_revocation_reason(sig: *const RnpSignature,
                                       code: *mut *mut c_char,
                                       reason: *mut *mut c_char)
                                       -> RnpResult {
    rnp_function!(rnp_signature_get_revocation_reason, crate::TRACE);
    let sig = assert_ptr_ref!(sig);
    arg!(code);
    arg!(reason);

    let rfr = sig.reason_for_revocation();
    if ! code.is_null() {
        *code = str_to_rnp_buffer(
            rfr.as_ref().map(|(c, _)| c.to_rnp_id()).unwrap_or(""));
    }
    if ! reason.is_null() {
        *reason = c_str_to_rnp_buffer_lossy(
            rfr.as_ref().map(|(_, r)| *r).unwrap_or(&[]));
    }
    rnp_success!()
}

/// Replacement for ComponentAmalgamation::signatures.
///
/// This started out as a replacement for a function that was not
/// available in sequoia-openpgp 1.0.  However, we now mark
/// self-signatures as valid, a functionality that is not available in
/// the stock version of the function.
pub fn ca_signatures<'a>(sigs: impl Iterator<Item = &'a Signature>)
                         -> impl Iterator<Item = (&'a Signature, Option<bool>)>
{
    use openpgp::packet::signature::subpacket::SubpacketTag;
    sigs.map(|sig| {
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

#[cfg(test)]
mod tests {
    use super::*;

    use openpgp::types::HashAlgorithm;

    use crate::testdata::rfc9980;
    use crate::testdata::signatures::dummy_signature;

    /// rnp_signature_is_valid applies the rules of RFC 9980 for
    /// signatures (RFC 9980, Sections 5.3.1 and 6.2.1) to a signature
    /// that is known to be cryptographically valid.
    ///
    /// The signatures are not signatures, see `dummy_signature`, so
    /// this does the same with every cryptographic backend.  See
    /// `rfc9980_self_signatures` for signatures that Sequoia
    /// verified.
    #[test]
    fn rfc9980_signature_rules() -> openpgp::Result<()> {
        let issuer = rfc9980::VECTORS[0].cert().fingerprint();
        let v4_issuer = rfc9980::VECTORS[1].cert().fingerprint();

        // Returns what rnp_signature_is_valid says about the
        // signature if it is known to be valid, known to be invalid,
        // and if nothing is known.
        let is_valid = |sig: &Signature| {
            [Some(true), Some(false), None].map(|valid| {
                let sig =
                    RnpSignature::new(std::ptr::null(), sig.clone(), valid);
                unsafe { rnp_signature_is_valid(&sig as *const _, 0) }
            })
        };

        let ok = RNP_SUCCESS.as_u32();
        let invalid = RNP_ERROR_SIGNATURE_INVALID.as_u32();

        for pk_algo in [30, 31, 32, 33, 34] {
            // A v6 signature using a hash algorithm with a digest
            // size of at least 256 bits.
            for hash_algo in [HashAlgorithm::SHA256,
                              HashAlgorithm::SHA384,
                              HashAlgorithm::SHA512,
                              HashAlgorithm::SHA3_256,
                              HashAlgorithm::SHA3_512]
            {
                let sig = dummy_signature(pk_algo, hash_algo, &issuer)?;
                assert_eq!(sig.version(), 6);
                assert_eq!(is_valid(&sig), [ok, invalid, invalid],
                           "{} {}", pk_algo, hash_algo);
            }

            // A smaller digest size.
            let sig = dummy_signature(pk_algo, HashAlgorithm::SHA224, &issuer)?;
            assert_eq!(is_valid(&sig), [invalid, invalid, invalid],
                       "{}", pk_algo);

            // A v4 signature.
            let sig =
                dummy_signature(pk_algo, HashAlgorithm::SHA512, &v4_issuer)?;
            assert_eq!(sig.version(), 4);
            assert_eq!(is_valid(&sig), [invalid, invalid, invalid],
                       "{}", pk_algo);
        }

        // Other algorithms are not affected: Ed25519, and an
        // algorithm that we do not know.
        for pk_algo in [27, 37] {
            for hash_algo in [HashAlgorithm::SHA1,
                              HashAlgorithm::SHA224,
                              HashAlgorithm::SHA512]
            {
                for issuer in [&issuer, &v4_issuer] {
                    let sig = dummy_signature(pk_algo, hash_algo, issuer)?;
                    assert_eq!(is_valid(&sig), [ok, invalid, invalid],
                               "{} {}", pk_algo, hash_algo);
                }
            }
        }
        Ok(())
    }
}
