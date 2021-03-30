use libc::{
    c_char,
};

use crate::{
    P,
    RnpContext,
    RnpResult,
    str_to_rnp_buffer,
    error::*,
    conversions::*,
    wot,
};

pub struct RnpIdentifierIterator {
    typ: RnpIdentifierType,
    iter: std::vec::IntoIter<String>,
}

// XXX: Do we want to return subkeys?  I guess RNP does, but TB
// filters out subkeys anyway.
#[no_mangle] pub unsafe extern "C"
fn rnp_identifier_iterator_create(ctx: *mut RnpContext,
                                  iter: *mut *mut RnpIdentifierIterator,
                                  typ: *const c_char)
                                  -> RnpResult {
    rnp_function!(rnp_identifier_iterator_create, crate::TRACE);
    let ctx = assert_ptr_mut!(ctx);
    assert_ptr!(iter);
    assert_ptr!(typ);

    let typ = rnp_try!(RnpIdentifierType::from_rnp_id(typ));
    t!("type = {:?}", typ);

    // Thunderbird is doing a scan.  Now is a good time to check for
    // WoT updates.
    if let Err(err) = wot::WoT::queue_update() {
        t!("Queuing wot update: {}", err);
    }

    // There are a few good reasons why we eagerly evaluate the
    // iterator:
    //
    //   - We'd have to keep the keystore lock for the life of the
    //     iterator.  That could be a very long time.  In particular,
    //     if the caller forgets to destroy it we deadlock.  It's
    //     probably better to just leak the iterator.  Also, it would
    //     not be possible to modify the keystore, which is
    //     inconvenient.
    //
    //   - Because we don't want to return duplicates, we'd have to
    //     keep a list of certificates that we've already seen.  At
    //     that point, we use O(n) memory anyway!

    let ks = ctx.certs.read();
    let results: Vec<String> = match typ {
        RnpIdentifierType::UserID => {
            let mut userids: Vec<String>
                = Vec::with_capacity(2 * ks.count());
            for cert in ks.iter() {
                if let Ok(vcert) = cert.with_policy(P, None) {
                    userids.extend(vcert.userids()
                                   .filter_map(|u| {
                                       String::from_utf8(
                                           u.userid().value().to_vec()).ok()
                                   }))
                }
            }

            // We need to dedup.
            userids.sort();
            userids.dedup();
            userids
        }

        RnpIdentifierType::KeyID => {
            // by_primary_id is by definition deduped.
            ks.keyids()
                .map(|keyid| format!("{:X}", keyid))
                .collect()
        }

        RnpIdentifierType::Fingerprint => {
            // by_primary_fp is by definition deduped.
            ks.fingerprints()
                .map(|fpr| format!("{:X}", fpr))
                .collect()
        }

        RnpIdentifierType::Keygrip => {
            // by_primary_grip is by definition deduped.
            ks.keygrips()
                .map(|grip| grip.to_string())
                .collect()
        }
    };

    *iter = Box::into_raw(Box::new(RnpIdentifierIterator {
        typ,
        iter: results.into_iter(),
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

#[no_mangle] pub unsafe extern "C"
fn rnp_identifier_iterator_next(iter: *mut RnpIdentifierIterator,
                                item: *mut *const c_char)
                                -> RnpResult {
    rnp_function!(rnp_identifier_iterator_next, crate::TRACE);
    let iter = assert_ptr_mut!(iter);
    t!("type = {:?}", iter.typ);

    let result = if let Some(id) = iter.iter.next() {
        t!("Yielding {:?} = {}", iter.typ, id);
        *item = str_to_rnp_buffer(&id);
        RNP_SUCCESS
    } else {
        // Exhausted the iterator.
        *item = std::ptr::null();
        RNP_ERROR_GENERIC
    };

    assert_ptr!(item);

    result
}
