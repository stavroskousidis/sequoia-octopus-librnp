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

#[derive(Debug)]
pub struct RnpUserID {
    ctx: *const RnpContext,
    uid: UserID,
    cert: Cert,
    nth_uid: usize,
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
/// XXX: This is not available in sequoia-openpgp 1.0.  Drop this
/// workaround once we depend on >= 1.1.
use openpgp::cert::amalgamation::ComponentAmalgamation;
use openpgp::packet::Signature;
fn signatures<'a>(ca: ComponentAmalgamation<'a, UserID>)
                  -> impl Iterator<Item = &'a Signature> {
    ca.self_revocations()
        .chain(ca.self_signatures())
        .chain(ca.certifications())
        .chain(ca.other_revocations())
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

    if let Some(s) = signatures(
        uid.cert.userids().nth(uid.nth_uid)
            .expect("we know it's there")
    ).nth(idx)
    {
        *sig = Box::into_raw(Box::new(
            RnpSignature::new(uid.ctx, s.clone())));
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

    if let Ok(vua) = uid.cert.userids().nth(uid.nth_uid)
        .expect("we know it's there")
        .with_policy(P, None)
    {
        use openpgp::types::RevocationStatus::*;
        *result =
            match vua.revocation_status() {
                Revoked(_) => true,
                CouldBe(_) => false, // XXX
                NotAsFarAsWeKnow => false,
            };
    } else {
        // Not valid under the policy.  Treat as revoked.
        t!("UserID not valid under the standard policy, treating as revoked");
        *result = true;
    }
    RNP_SUCCESS
}

#[no_mangle] pub unsafe extern "C"
fn rnp_uid_is_valid(uid: *const RnpUserID,
                    result: *mut bool)
                    -> RnpResult {
    rnp_function!(rnp_uid_is_valid, crate::TRACE);
    let uid = assert_ptr_ref!(uid);
    let result = assert_ptr_mut!(result);

    let vc = if let Ok(vc) = uid.cert.with_policy(P, None) {
        vc
    } else {
        // Not valid.
        *result = false;
        return RNP_SUCCESS;
    };

    // Make sure the User ID is valid.
    if vc.userids().filter(|ua| *ua.userid() == uid.uid).nth(0).is_some() {
        *result = true;
    } else {
        *result = false;
    };

    RNP_SUCCESS
}


#[no_mangle] pub unsafe extern "C"
fn rnp_uid_is_primary(uid: *const RnpUserID,
                      result: *mut bool)
                      -> RnpResult {
    rnp_function!(rnp_uid_is_primary, crate::TRACE);
    let uid = assert_ptr_ref!(uid);
    let result = assert_ptr_mut!(result);

    let vc = if let Ok(vc) = uid.cert.with_policy(P, None) {
        vc
    } else {
        // Not valid.
        *result = false;
        return RNP_SUCCESS;
    };

    if let Ok(ua) = vc.primary_userid() {
        *result = ua.userid() == &uid.uid
    } else {
        *result = false;
    }
    RNP_SUCCESS
}

