//! This is RNP's version of the Policy.
//!
//! XXX: Currently, we map rnp_get_security_rule and
//! rnp_add_security_rule directly to our StandardPolicy.  This
//! mapping is somewhat lossy, and if we ever implement
//! rnp_remove_security_rule, we need to explicitly track the rules
//! and obey RNP_SECURITY_OVERRIDE.

use std::{
    convert::TryFrom,
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
                         flags_inout: *mut RnpSecurityFlags,
                         from_out: *mut u64,
                         level_out: *mut RnpSecurityLevel)
                         -> RnpResult {
    rnp_function!(rnp_get_security_rule, crate::TRACE);
    let ctx = assert_ptr_ref!(ctx);
    let typ = assert_str!(typ);
    let name_ = assert_str!(name);
    arg!(time);
    arg!(flags_inout);
    arg!(from_out);
    let level_out = assert_ptr_mut!(level_out);

    let query_flags = if flags_inout.is_null() {
        None
    } else {
        Some(*flags_inout)
    };

    // "If there is no matching rule, return defaults."
    let mut flags = 0;
    let mut from = 0;
    let mut level = RNP_SECURITY_DEFAULT;

    let time = UNIX_EPOCH + Duration::new(time, 0);
    t!("typ: {}, name: {}, time: {:?}, query flags: {:?}",
       typ, name_, time, query_flags);

    match typ {
        RNP_FEATURE_PK_ALG => {
            match AsymmetricAlgorithm::from_rnp_id(name) {
                Ok(algo) => if let Some(cutoff) =
                    ctx.policy().asymmetric_algo_cutoff(algo)
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
                    ctx.policy().symmetric_algo_cutoff(algo)
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
            let verify_data = query_flags.map(|f| {
                f & RNP_SECURITY_VERIFY_KEY == 0
                    && f & RNP_SECURITY_VERIFY_DATA > 0
            }).unwrap_or(false);
            let verify_key = query_flags.map(|f| {
                f & RNP_SECURITY_VERIFY_KEY > 0
                    && f & RNP_SECURITY_VERIFY_DATA == 0
            }).unwrap_or(false);

            let hash_security = if verify_key {
                HashAlgoSecurity::SecondPreImageResistance
            } else {
                HashAlgoSecurity::CollisionResistance
            };

            match HashAlgorithm::from_rnp_id(name) {
                Ok(hash) => if let Some(cutoff) =
                    ctx.policy().hash_cutoff(hash, hash_security)
                {
                    // RNP only returns rules that apply to `time`.
                    if time > cutoff {
                        from = cutoff.duration_since(UNIX_EPOCH)
                            .expect("cutoff time is representable as epoch")
                            .as_secs();
                        level = RNP_SECURITY_INSECURE;
                    }
                    flags |=
                        if verify_data { RNP_SECURITY_VERIFY_DATA } else { 0 }
                        | if verify_key { RNP_SECURITY_VERIFY_KEY } else { 0 };
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
    if ! flags_inout.is_null() {
        *flags_inout = flags;
    }
    if ! from_out.is_null() {
        *from_out = from;
    }
    *level_out = level;
    rnp_success!()
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
    let typ = assert_str!(typ);
    let name_ = assert_str!(name);
    arg!(flags);
    arg!(time);
    arg!(level);

    let time = UNIX_EPOCH + Duration::new(time, 0);
    t!("typ: {}, name: {}, flags: {:?}, time: {:?}, level: {:?}",
       typ, name_, flags, time, level);

    match typ {
        RNP_FEATURE_PK_ALG => {
            match AsymmetricAlgorithm::all_from_rnp_id(name) {
                Ok(algos) => for algo in algos {
                    if level == RNP_SECURITY_DEFAULT {
                        // XXX: We don't model the time from when the
                        // algorithm should be allowed, unlike RNP.
                        ctx.policy.write().unwrap().accept_asymmetric_algo(algo);
                    } else {
                        // XXX: We lose the distinction between
                        // RNP_SECURITY_INSECURE and
                        // RNP_SECURITY_PROHIBITED here, but currently
                        // RNP treats them the same.
                        ctx.policy.write().unwrap().reject_asymmetric_algo_at(algo, time);
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
                        ctx.policy.write().unwrap().accept_symmetric_algo(algo);
                    } else {
                        // XXX: We lose the distinction between
                        // RNP_SECURITY_INSECURE and
                        // RNP_SECURITY_PROHIBITED here, but currently
                        // RNP treats them the same.
                        ctx.policy.write().unwrap().reject_symmetric_algo_at(algo, time);
                    }
                },
                Err(_) => {
                    // We didn't recognize the algorithm.
                    // There is nothing we can do, really.
                },
            }
        },
        RNP_FEATURE_HASH_ALG => {
            // If the rule should *only* apply to keys, use the weaker
            // property.
            let hash_security =
                if flags & RNP_SECURITY_VERIFY_KEY > 0
                && flags & RNP_SECURITY_VERIFY_DATA == 0
            {
                HashAlgoSecurity::SecondPreImageResistance
            } else {
                HashAlgoSecurity::CollisionResistance
            };

            match HashAlgorithm::from_rnp_id(name) {
                Ok(algo) => {
                    if level == RNP_SECURITY_DEFAULT {
                        // XXX: We don't model the time from when the
                        // algorithm should be allowed, unlike RNP.

                        // XXX: We don't have a accept_hash_property,
                        // so we (ab)use reject_hash_property_at with
                        // a time later than what is representable in
                        // OpenPGP, which the StandardPolicy will
                        // interpret as being goodlisted.
                        //
                        // See https://gitlab.com/sequoia-pgp/sequoia/-/issues/938.
                        let the_future = UNIX_EPOCH.checked_add(Duration::new(
                            (2161 - 1970) * 365 * 24 * 60 * 60, 0))
                            .expect("the year 2161 is representable");
                        assert!(openpgp::types::Timestamp::try_from(the_future)
                                .is_err());
                        ctx.policy.write().unwrap().reject_hash_property_at(algo, hash_security,
                                                           the_future);
                    } else {
                        // XXX: We lose the distinction between
                        // RNP_SECURITY_INSECURE and
                        // RNP_SECURITY_PROHIBITED here, but currently
                        // RNP treats them the same.
                        ctx.policy.write().unwrap().reject_hash_property_at(algo, hash_security,
                                                           time);
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

    rnp_success!()
}
