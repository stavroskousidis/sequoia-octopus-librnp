//! This is RNP's version of the Policy.

use std::{
    ffi::CStr,
    time::{Duration, UNIX_EPOCH},
};

use libc::{
    c_char,
};

use sequoia_openpgp as openpgp;
use openpgp::{
    policy::HashAlgoSecurity,
    types::HashAlgorithm,
};

use crate::{
    RnpResult,
    RnpContext,
    conversions::FromRnpId,
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
        // "Only RNP_FEATURE_HASH_ALG is supported right now."
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
