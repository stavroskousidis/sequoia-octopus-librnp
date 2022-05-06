use std::fmt;

use libc::{
    size_t,
};

use sequoia_openpgp as openpgp;
use openpgp::{
    cert::{
        Cert,
        amalgamation::{
            ValidAmalgamation,
            ValidateAmalgamation,
            ValidUserIDAmalgamation,
        },
    },
    packet::{
        UserID,
    },
};

use crate::{
    P,
    RnpResult,
    RnpContext,
    RnpSignature,
    error::*,
};

pub struct RnpUserID {
    ctx: *const RnpContext,
    uid: UserID,
    cert: Cert,
    nth_uid: usize,
}

impl fmt::Debug for RnpUserID {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("RnpUserID")
            .field("ctx", &self.ctx)
            .field("uid", &String::from_utf8_lossy(self.uid.value()))
            .field("cert", &self.cert.fingerprint().to_hex())
            .field("nth_uid", &self.nth_uid)
            .finish()
    }
}

impl RnpUserID {
    pub fn new(ctx: *const RnpContext, uid: UserID, cert: Cert)
               -> Option<Self>
    {
        cert.userids().position(|u| u.userid() == &uid)
            .map(|nth_uid|
                 RnpUserID {
                     ctx,
                     uid,
                     cert,
                     nth_uid
                 })
    }

    /// Returns the User ID.
    pub fn userid(&self) -> &UserID {
        &self.uid
    }

    /// Returns whether the User ID is safe to display.
    ///
    /// A User ID is safe to display if it is valid under the standard
    /// policy or the certificate is NOT valid under the standard
    /// policy.
    ///
    /// This function does not return whether a User ID is safe to use
    /// if
    fn safe_to_display<'a>(&'a self) -> Option<ValidUserIDAmalgamation<'a>> {
        if let Ok(vc) = self.cert.with_policy(P, None) {
            // The certificate is valid under the standard policy.  Is
            // the User ID?
            vc.userids().filter(|u| u.userid() == &self.uid).nth(0)
        } else if let Ok(vua) = self.cert.userids().nth(self.nth_uid)
            .expect("we know it's there")
            .with_policy(crate::NP, None)
        {
            // The certificate is not valid under the standard policy.
            // It is safe to treat the User ID as if it wre valid
            // under the NULL policy.
            Some(vua)
        } else {
            // The certificate is not even valid under the null
            // policy.  Treat it as invalid.
            None
        }
    }
}

#[no_mangle] pub unsafe extern "C"
fn rnp_uid_handle_destroy(uid: *mut RnpUserID)
                          -> RnpResult {
    if ! uid.is_null() {
        drop(Box::from_raw(uid));
    }
    RNP_SUCCESS
}

/// Replacement for ComponentAmalgamation::signatures.
///
/// This started out as a replacement for a function that was not
/// available in sequoia-openpgp 1.0.  However, we now mark
/// self-signatures as valid, a functionality that is not available in
/// the stock version of the function.
use openpgp::cert::amalgamation::ComponentAmalgamation;
use openpgp::packet::Signature;
fn signatures<'a>(ca: ComponentAmalgamation<'a, UserID>)
                  -> impl Iterator<Item = (&'a Signature, Option<bool>)> {
    ca.self_revocations().map(|sig| (sig, Some(true)))
        .chain(ca.self_signatures().map(|sig| (sig, Some(true))))
        .chain(ca.certifications().map(|sig| (sig, None)))
        .chain(ca.other_revocations().map(|sig| (sig, None)))
}

// XXX: what signatures to consider?  all of them?
#[no_mangle] pub unsafe extern "C"
fn rnp_uid_get_signature_at(uid: *const RnpUserID,
                            idx: size_t,
                            sig: *mut *mut RnpSignature)
                            -> RnpResult {
    rnp_function!(rnp_uid_get_signature_at, crate::TRACE);
    let uid = assert_ptr_ref!(uid);
    let sig = assert_ptr_mut!(sig);

    if let Some((s, valid)) = signatures(
        uid.cert.userids().nth(uid.nth_uid)
            .expect("we know it's there")
    ).nth(idx)
    {
        *sig = Box::into_raw(Box::new(
            RnpSignature::new(uid.ctx, s.clone(), valid)));
        RNP_SUCCESS
    } else {
        RNP_ERROR_BAD_PARAMETERS
    }
}

// XXX: what signatures to consider?  all of them?
#[no_mangle] pub unsafe extern "C"
fn rnp_uid_get_signature_count(uid: *const RnpUserID,
                               count: *mut size_t)
                               -> RnpResult {
    rnp_function!(rnp_uid_get_signature_count, crate::TRACE);
    let uid = assert_ptr_ref!(uid);
    let count = assert_ptr_mut!(count);

    *count = signatures(
        uid.cert.userids().nth(uid.nth_uid)
            .expect("we know it's there")
    ).count();
    RNP_SUCCESS
}

// XXX: Revocation is a lot less binary than RNP would like it to be.
// How should we handle third-party revocations here?
#[no_mangle] pub unsafe extern "C"
fn rnp_uid_is_revoked(uid: *const RnpUserID,
                      result: *mut bool)
                      -> RnpResult {
    rnp_function!(rnp_uid_is_revoked, crate::TRACE);
    let uid = assert_ptr_ref!(uid);
    let result = assert_ptr_mut!(result);

    if let Some(vua) = uid.safe_to_display() {
        use openpgp::types::RevocationStatus::*;
        *result =
            match vua.revocation_status() {
                Revoked(_) => true,
                CouldBe(_) => false, // XXX
                NotAsFarAsWeKnow => false,
            };
    } else {
        // The User ID is not safe to display (it may or may not
        // actually be revoked).  Treat it as revoked.
        *result = true;
    }

    t!("{}:{:?}: is{} revoked",
       uid.cert.fingerprint(), String::from_utf8_lossy(uid.uid.value()),
       if *result { "" } else { " not" });

    RNP_SUCCESS
}

#[no_mangle] pub unsafe extern "C"
fn rnp_uid_is_valid(uid: *const RnpUserID,
                    result: *mut bool)
                    -> RnpResult {
    rnp_function!(rnp_uid_is_valid, crate::TRACE);
    let uid = assert_ptr_ref!(uid);
    let result = assert_ptr_mut!(result);

    if let Some(_) = uid.safe_to_display() {
        *result = true;
    } else {
        // The User ID is not safe to display.  Treat as invalid.
        *result = false;
    }

    t!("{}:{:?}: is{} valid",
       uid.cert.fingerprint(), String::from_utf8_lossy(uid.uid.value()),
       if *result { "" } else { " not" });

    RNP_SUCCESS
}


#[no_mangle] pub unsafe extern "C"
fn rnp_uid_is_primary(uid: *const RnpUserID,
                      result: *mut bool)
                      -> RnpResult {
    rnp_function!(rnp_uid_is_primary, crate::TRACE);
    let uid = assert_ptr_ref!(uid);
    let result = assert_ptr_mut!(result);

    if let Ok(vc) = uid.cert.with_policy(P, None) {
        if let Ok(ua) = vc.primary_userid() {
            *result = ua.userid() == &uid.uid
        } else {
            *result = false;
        }
    } else {
        // Not valid.
        *result = false;
    };

    t!("{}:{:?}: is{} primary",
       uid.cert.fingerprint(), String::from_utf8_lossy(uid.uid.value()),
       if *result { "" } else { " not" });

    RNP_SUCCESS
}

