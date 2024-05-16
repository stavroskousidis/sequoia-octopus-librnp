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
        },
    },
    packet::{
        UserID,
    },
};

use crate::{
    RnpResult,
    RnpContext,
    RnpSignature,
    error::*,
    signature::ca_signatures,
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

    /// Returns whether the User ID is considered revoked.
    ///
    /// A User ID is considered revoked:
    /// - if it is valid under the standard policy and is revoked
    /// - it is not valid under the standard policy, but is valid under the
    ///   null policy, and is revoked
    /// - is not valid under either the standard or null policy.
    fn revoked<'a>(&'a self) -> bool {
        let ctx = unsafe { &*self.ctx };

        let userid = self.cert.userids().nth(self.nth_uid)
            .expect("we know it's there");

        if let Ok(vu) = userid.clone()
            .with_policy(&*ctx.policy(), None)
            .or_else(|_| userid.with_policy(crate::NP, None)) {
            // The certificate is valid under a policy

            use openpgp::types::RevocationStatus::*;

            match vu.revocation_status() {
                Revoked(_) => true,
                CouldBe(_) => false, // XXX
                NotAsFarAsWeKnow => false,
            }
        } else {
            // The certificate is not even valid under the null
            // policy.  Treat it as invalid.
            true
        }
    }
}

#[no_mangle] pub unsafe extern "C"
fn rnp_uid_handle_destroy(uid: *mut RnpUserID)
                          -> RnpResult {
    rnp_function!(rnp_uid_handle_destroy, crate::TRACE);
    arg!(uid);

    if ! uid.is_null() {
        drop(Box::from_raw(uid));
    }
    rnp_success!()
}

// XXX: what signatures to consider?  all of them?
#[no_mangle] pub unsafe extern "C"
fn rnp_uid_get_signature_at(uid: *const RnpUserID,
                            idx: size_t,
                            sig: *mut *mut RnpSignature)
                            -> RnpResult {
    rnp_function!(rnp_uid_get_signature_at, crate::TRACE);
    let uid = assert_ptr_ref!(uid);
    arg!(idx);
    let sig = assert_ptr_mut!(sig);

    rnp_return_status!(if let Some((s, valid)) = ca_signatures(
        &uid.cert.userids().nth(uid.nth_uid)
            .expect("we know it's there")
    ).nth(idx)
    {
        *sig = Box::into_raw(Box::new(
            RnpSignature::new(uid.ctx, s.clone(), valid)));
        RNP_SUCCESS
    } else {
        RNP_ERROR_BAD_PARAMETERS
    })
}

// XXX: what signatures to consider?  all of them?
#[no_mangle] pub unsafe extern "C"
fn rnp_uid_get_signature_count(uid: *const RnpUserID,
                               count: *mut size_t)
                               -> RnpResult {
    rnp_function!(rnp_uid_get_signature_count, crate::TRACE);
    let uid = assert_ptr_ref!(uid);
    let count = assert_ptr_mut!(count);

    *count = ca_signatures(
        &uid.cert.userids().nth(uid.nth_uid)
            .expect("we know it's there")
    ).count();
    rnp_success!()
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

    *result = uid.revoked();

    t!("{}:{:?}: is{} revoked",
       uid.cert.fingerprint(), String::from_utf8_lossy(uid.uid.value()),
       if *result { "" } else { " not" });

    rnp_success!()
}

#[no_mangle] pub unsafe extern "C"
fn rnp_uid_is_valid(uid: *const RnpUserID,
                    result: *mut bool)
                    -> RnpResult {
    rnp_function!(rnp_uid_is_valid, crate::TRACE);
    let uid = assert_ptr_ref!(uid);
    let result = assert_ptr_mut!(result);

    let ctx = &*uid.ctx;
    let userid = uid.cert.userids().nth(uid.nth_uid)
        .expect("we know it's there");

    // A User ID is safe to display if it is valid under the standard
    // policy or the null policy.
    *result = userid.clone()
        .with_policy(&*ctx.policy(), None)
        .or_else(|_| userid.with_policy(crate::NP, None))
        .is_ok();

    t!("{}:{:?}: is{} valid",
       uid.cert.fingerprint(), String::from_utf8_lossy(uid.uid.value()),
       if *result { "" } else { " not" });

    rnp_success!()
}


#[no_mangle] pub unsafe extern "C"
fn rnp_uid_is_primary(uid: *const RnpUserID,
                      result: *mut bool)
                      -> RnpResult {
    rnp_function!(rnp_uid_is_primary, crate::TRACE);
    let uid = assert_ptr_ref!(uid);
    let ctx = &*uid.ctx;
    let result = assert_ptr_mut!(result);

    if let Ok(vc) = uid.cert.with_policy(&*ctx.policy(), None) {
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

    rnp_success!()
}

