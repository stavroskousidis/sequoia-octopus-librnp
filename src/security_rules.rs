//! This is RNP's version of the Policy.
//!
//! XXX: Currently, we map rnp_get_security_rule and
//! rnp_add_security_rule directly to our StandardPolicy.  This
//! mapping is somewhat lossy, and if we ever implement
//! rnp_remove_security_rule, we need to explicitly track the rules
//! and obey RNP_SECURITY_OVERRIDE.

use std::{
    ffi::CStr,
    time::{Duration, UNIX_EPOCH},
};

use libc::{
    c_char,
};

use sequoia_openpgp as openpgp;
use openpgp::{
    policy::{AsymmetricAlgorithm, HashAlgoSecurity},
    types::{
        HashAlgorithm,
        SymmetricAlgorithm,
    },
};

use crate::{
    RnpResult,
    RnpContext,
    conversions::{AsymmetricAlgorithmExt, FromRnpId},
    error::*,
    flags::*,
};

pub const RNP_FEATURE_SYMM_ALG: &'static str = "symmetric algorithm";
pub const RNP_FEATURE_AEAD_ALG: &'static str = "aead algorithm";
pub const RNP_FEATURE_PROT_MODE: &'static str = "protection mode";
pub const RNP_FEATURE_PK_ALG: &'static str = "public key algorithm";
pub const RNP_FEATURE_HASH_ALG: &'static str = "hash algorithm";
pub const RNP_FEATURE_COMP_ALG: &'static str = "compression algorithm";
pub const RNP_FEATURE_CURVE: &'static str = "elliptic curve";

#[no_mangle] pub unsafe extern "C"
fn rnp_get_security_rule(ctx: *const RnpContext,
                         typ: *const c_char,
                         name: *const c_char,
                         time: u64,
                         flags_out: *mut RnpSecurityFlags,
                         from_out: *mut u64,
                         level_out: *mut RnpSecurityLevel)
                         -> RnpResult {
    rnp_function!(rnp_get_security_rule, crate::TRACE);
    let ctx = assert_ptr_ref!(ctx);
    assert_ptr!(typ);
    assert_ptr!(name);
    assert_ptr!(level_out);

    // "If there is no matching rule, return defaults."
    let flags = 0;
    let mut from = 0;
    let mut level = RNP_SECURITY_DEFAULT;


    let typ =
        rnp_try_or!(CStr::from_ptr(typ).to_str(), RNP_ERROR_BAD_PARAMETERS);
    let time = UNIX_EPOCH + Duration::new(time, 0);
    t!("typ: {}, name: {}, time: {:?}",
       typ, CStr::from_ptr(name).to_str().unwrap_or("invalid str"), time);

    match typ {
        RNP_FEATURE_PK_ALG => {
            match AsymmetricAlgorithm::from_rnp_id(name) {
                Ok(algo) => if let Some(cutoff) =
                    ctx.policy.asymmetric_algo_cutoff(algo)
                {
                    // RNP only returns rules that apply to `time`.
                    if time > cutoff {
                        from = cutoff.duration_since(UNIX_EPOCH)
                            .expect("cutoff time is representable as epoch")
                            .as_secs();
                        level = RNP_SECURITY_INSECURE;
                    }
                },
                Err(_) => {
                    // We didn't recognize the algorithm.
                    // Conservatively consider it prohibited.
                    level = RNP_SECURITY_PROHIBITED;
                },
            }
        },
        RNP_FEATURE_SYMM_ALG => {
            match SymmetricAlgorithm::from_rnp_id(name) {
                Ok(algo) => if let Some(cutoff) =
                    ctx.policy.symmetric_algo_cutoff(algo)
                {
                    // RNP only returns rules that apply to `time`.
                    if time > cutoff {
                        from = cutoff.duration_since(UNIX_EPOCH)
                            .expect("cutoff time is representable as epoch")
                            .as_secs();
                        level = RNP_SECURITY_INSECURE;
                    }
                },
                Err(_) => {
                    // We didn't recognize the algorithm.
                    // Conservatively consider it prohibited.
                    level = RNP_SECURITY_PROHIBITED;
                },
            }
        },
        RNP_FEATURE_HASH_ALG => {
            match HashAlgorithm::from_rnp_id(name) {
                Ok(hash) => if let Some(cutoff) =
                    ctx.policy.hash_cutoff(
                        hash,
                        // Somewhat arbitrarily pick the weaker
                        // property.  RNP doesn't differentiate.
                        HashAlgoSecurity::CollisionResistance)
                {
                    // RNP only returns rules that apply to `time`.
                    if time > cutoff {
                        from = cutoff.duration_since(UNIX_EPOCH)
                            .expect("cutoff time is representable as epoch")
                            .as_secs();
                        level = RNP_SECURITY_INSECURE;
                    }
                },
                Err(_) => {
                    // We didn't recognize the algorithm.
                    // Conservatively consider it prohibited.
                    level = RNP_SECURITY_PROHIBITED;
                },
            }
        },
        // XXX: Implement more features if RNP does.
        _ => (),
    }

    t!("=> flags: {}, from: {}, level: {}", flags, from, level);
    if ! flags_out.is_null() {
        *flags_out = flags;
    }
    if ! from_out.is_null() {
        *from_out = from;
    }
    *level_out = level;
    RNP_SUCCESS
}

#[no_mangle] pub unsafe extern "C"
fn rnp_add_security_rule(ctx: *mut RnpContext,
                         typ: *const c_char,
                         name: *const c_char,
                         flags: RnpSecurityFlags,
                         time: u64,
                         level: RnpSecurityLevel)
                         -> RnpResult {
    rnp_function!(rnp_add_security_rule, crate::TRACE);
    let ctx = assert_ptr_mut!(ctx);
    assert_ptr!(typ);
    assert_ptr!(name);

    let typ =
        rnp_try_or!(CStr::from_ptr(typ).to_str(), RNP_ERROR_BAD_PARAMETERS);
    let time = UNIX_EPOCH + Duration::new(time, 0);
    t!("typ: {}, name: {}, flags: {:?}, time: {:?}, level: {:?}",
       typ, CStr::from_ptr(name).to_str().unwrap_or("invalid str"),
       flags, time, level);

    match typ {
        RNP_FEATURE_PK_ALG => {
            match AsymmetricAlgorithm::all_from_rnp_id(name) {
                Ok(algos) => for algo in algos {
                    if level == RNP_SECURITY_DEFAULT {
                        // XXX: We don't model the time from when the
                        // algorithm should be allowed, unlike RNP.
                        ctx.policy.accept_asymmetric_algo(algo);
                    } else {
                        // XXX: We lose the distinction between
                        // RNP_SECURITY_INSECURE and
                        // RNP_SECURITY_PROHIBITED here, but currently
                        // RNP treats them the same.
                        ctx.policy.reject_asymmetric_algo_at(algo, time);
                    }
                },
                Err(_) => {
                    // We didn't recognize the algorithm.
                    // There is nothing we can do, really.
                },
            }
        },
        RNP_FEATURE_SYMM_ALG => {
            match SymmetricAlgorithm::from_rnp_id(name) {
                Ok(algo) => {
                    if level == RNP_SECURITY_DEFAULT {
                        // XXX: We don't model the time from when the
                        // algorithm should be allowed, unlike RNP.
                        ctx.policy.accept_symmetric_algo(algo);
                    } else {
                        // XXX: We lose the distinction between
                        // RNP_SECURITY_INSECURE and
                        // RNP_SECURITY_PROHIBITED here, but currently
                        // RNP treats them the same.
                        ctx.policy.reject_symmetric_algo_at(algo, time);
                    }
                },
                Err(_) => {
                    // We didn't recognize the algorithm.
                    // There is nothing we can do, really.
                },
            }
        },
        RNP_FEATURE_HASH_ALG => {
            match HashAlgorithm::from_rnp_id(name) {
                Ok(algo) => {
                    if level == RNP_SECURITY_DEFAULT {
                        // XXX: We don't model the time from when the
                        // algorithm should be allowed, unlike RNP.
                        ctx.policy.accept_hash(algo);
                    } else {
                        // XXX: We lose the distinction between
                        // RNP_SECURITY_INSECURE and
                        // RNP_SECURITY_PROHIBITED here, but currently
                        // RNP treats them the same.
                        ctx.policy.reject_hash_at(algo, time);
                    }
                },
                Err(_) => {
                    // We didn't recognize the algorithm.
                    // There is nothing we can do, really.
                },
            }
        },
        // XXX: Implement more features if RNP does.
        _ => (),
    }

    RNP_SUCCESS
}
