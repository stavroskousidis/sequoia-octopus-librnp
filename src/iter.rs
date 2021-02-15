use std::{
    collections::{
        HashSet,
    },
};

use libc::{
    c_char,
};

use sequoia_openpgp as openpgp;
use openpgp::{
    cert::{
        Cert,
    },
    packet::{
        UserID,
    },
};

use crate::{
    P,
    RnpContext,
    RnpResult,
    Keygrip,
    str_to_rnp_buffer,
    error::*,
    conversions::*,
};

pub struct RnpIdentifierIterator<'a> {
    ctx: &'a RnpContext,
    typ: RnpIdentifierType,
    cert_iter: Box<dyn Iterator<Item = &'a Cert> + 'a>,
    uid_iter: Option<Box<dyn Iterator<Item = &'a UserID> + 'a>>,
    seen: HashSet<String>,
}

#[no_mangle] pub unsafe extern "C"
fn rnp_identifier_iterator_create(ctx: *mut RnpContext,
                                  iter: *mut *mut RnpIdentifierIterator,
                                  typ: *const c_char)
                                  -> RnpResult {
    rnp_function!(rnp_identifier_iterator_create, crate::TRACE);
    let ctx = assert_ptr_ref!(ctx);
    assert_ptr!(iter);
    assert_ptr!(typ);

    let typ = rnp_try!(RnpIdentifierType::from_rnp_id(typ));
    t!("type = {:?}", typ);

    *iter = Box::into_raw(Box::new(RnpIdentifierIterator {
        ctx,
        typ,
        cert_iter: Box::new(ctx.certs.iter().chain(ctx.keys.iter())),
        uid_iter: None,
        seen: Default::default(),
    }));

    RNP_SUCCESS
}

#[no_mangle] pub unsafe extern "C"
fn rnp_identifier_iterator_destroy(iter: *mut RnpIdentifierIterator)
                                   -> RnpResult {
    if ! iter.is_null() {
        drop(Box::from_raw(iter));
    }
    RNP_SUCCESS
}

// XXX: Do we want to return subkeys?  I guess RNP does, but TB
// filters out subkeys anyway.
#[no_mangle] pub unsafe extern "C"
fn rnp_identifier_iterator_next(iter: *mut RnpIdentifierIterator,
                                item: *mut *const c_char)
                                -> RnpResult {
    rnp_function!(rnp_identifier_iterator_next, crate::TRACE);
    let iter = assert_ptr_mut!(iter);
    t!("type = {:?}", iter.typ);
    assert_ptr!(item);

    loop {
        let next = match iter.typ {
            RnpIdentifierType::UserID => {
                if iter.uid_iter.is_none() {
                    if let Some(cert) = iter.cert_iter.next() {
                        let vcert = match cert.with_policy(P, None) {
                            Ok(v) => v,
                            Err(_) => {
                                // Cert is not valid under P now.
                                // Skip it.
                                continue;
                            },
                        };

                        iter.uid_iter = Some(Box::new(
                            vcert.userids().map(|u| u.userid())));
                    } else {
                        // Exhausted cert iterator.
                        *item = std::ptr::null();
                        break RNP_ERROR_GENERIC;
                    }
                }

                let n =
                    iter.uid_iter.as_mut().unwrap().next()
                    .and_then(|u| std::str::from_utf8(u.value()).ok())
                    .map(|u| u.to_string());
                if let Some(n) = n {
                    n
                } else {
                    // Exhausted the current uid iterator, drop it and
                    // see if there is a next certificate.
                    iter.uid_iter = None;
                    continue;
                }
            },

            RnpIdentifierType::KeyID => {
                assert!(iter.uid_iter.is_none());
                if let Some(cert) = iter.cert_iter.next() {
                    format!("{:X}", cert.keyid())
                } else {
                    // Exhausted cert iterator.
                    *item = std::ptr::null();
                    break RNP_ERROR_GENERIC;
                }
            },

            RnpIdentifierType::Fingerprint => {
                assert!(iter.uid_iter.is_none());
                if let Some(cert) = iter.cert_iter.next() {
                    format!("{:X}", cert.fingerprint())
                } else {
                    // Exhausted cert iterator.
                    *item = std::ptr::null();
                    break RNP_ERROR_GENERIC;
                }
            },

            RnpIdentifierType::Keygrip => {
                assert!(iter.uid_iter.is_none());
                if let Some(cert) = iter.cert_iter.next() {
                    if let Ok(grip) = Keygrip::of(cert.primary_key().mpis()) {
                        t!("(If we yield a keygrip, the fingerprint is {})",
                           cert.primary_key().fingerprint());
                        grip.to_string()
                    } else {
                        // We don't know how to compute the keygrip
                        // over that key.  This should be unlikely,
                        // and the user wouldn't be able to do
                        // anything with the key anyway.  Skip it.
                        continue;
                    }
                } else {
                    // Exhausted cert iterator.
                    *item = std::ptr::null();
                    break RNP_ERROR_GENERIC;
                }
            },
        };

        if iter.seen.contains(&next) {
            // Already returned this item.
            continue;
        }

        t!("Yielding {:?} = {}", iter.typ, next);
        *item = str_to_rnp_buffer(&next);
        iter.seen.insert(next);
        break RNP_SUCCESS;
    }
}
