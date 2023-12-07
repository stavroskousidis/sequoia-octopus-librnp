//! Parcimonie support.
//!
//! If a user publishes a revocation certificate or a certificate
//! update, we don't want to wait more than a week to find out about
//! it.
//!
//! If the user has N certificates that they are monitoring for
//! updates, and we check if there are updates for them all at once,
//! then we reveal all of the certificates that the client is
//! interested in to the keyserver.  Further, the keyserver is able to
//! fingerprint the client, because most users have different sets of
//! keys.  A key server could use this information to withhold some
//! information from an individual, such as a revocation certificate,
//! for instance.
//!
//! That's not good, and we can do better.  First, we can stagger the
//! updates.  Then, the keyserver operator has to do more work to link
//! the individual requests together.  Second, we can obscure the
//! origin of the request so that it is more difficult to determine
//! what request came from what client.
//!
//! Staggering updates is straightforward: the implementation just
//! needs to be adjusted.  Hiding the client is more difficult.  An
//! effective way to do this is to use Tor.  But, even without Tor, a
//! user can still hide in the crowd.  For instance, if the client is
//! behind a NAT (relative to the attacker) and there are other
//! clients performing updates on the same network, then it will be
//! harder for the key server to distinguish the different clients
//! behind the NAT.
//!
//! If we distribute updates evenly, i.e., waiting 1 week / N time
//! between updates, then once the attacker sees two updates, they
//! know when the client will do the next update.
//!
//! We can improve upon this by instead using a random update
//! interval.  In particular, we want to sample from a memoryless
//! distribution.  This prevents an attacker predicting when we will
//! do our next update.
//!
//! This isn't a cure all.  If a client uses this approach, an
//! attacker who can observe the network and attribute requests to a
//! single client can still determine N after observing many requests.
//!
//! Poisson is a memory-less distribution.  Its parameter lambda is the
//! mean time between events.  In our case, an event is an update.
//! Since we want to update every certificate once a week, and we have
//! N certificates, we set lambda to 1 week / N.
//!
//! To further obscure N, we round N to the next power of 1.5.
//!
//! To avoid flooding the network, we set a lower bound to 5 minutes.
//! Because the user may add new certificates and we only recompute
//! the time to sleep after doing an update, we limit lambda to 19
//! hours.
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::sync::Arc;
use std::sync::RwLock;
use std::sync::RwLockReadGuard;
use std::thread;
use std::time::Duration;

use sequoia_openpgp as openpgp;
use openpgp::Fingerprint;
use openpgp::cert::prelude::*;
use openpgp::types::RevocationStatus;
use openpgp::packet::prelude::*;
use openpgp::policy::Policy;

use sequoia_net as net;
use net::KeyServer;
use net::Policy as NetPolicy;
use net::wkd;

use rand::prelude::*;
use rand_distr::{Poisson, Distribution};

use crate::Keystore;
use crate::keystore::KeystoreData;

// This is a simple heuristic to check whether a certificate might be
// flooded.  If a User ID or attribute has more than this number of
// third-party certificates that we prune ones that are not useful.
const THIRD_PARTY_SIG_THRESHOLD: usize = 250;

pub struct Parcimonie {
}

impl Parcimonie {
    /// Creates a new parcimonie instance.
    ///
    /// This starts a work thread, which looks for updates for the
    /// specified certificates.
    ///
    /// You can poll for updates using `Parcimonie::updates`.  To
    /// watch additional certificates, use `Parcimonie::monitor`.
    pub fn new<P>(policy: P, ks: &Keystore) -> Self
    where P: Policy + 'static
    {
        ParcimonieServer::new(policy, ks.create_ref());
        Parcimonie {
        }
    }
}

pub struct ParcimonieServer<P: Policy + 'static> {
    policy: P,
    ks: Arc<RwLock<KeystoreData>>,
}

impl<P: Policy + 'static> ParcimonieServer<P> {
    // Instantiates a new parcimonie server, which keeps the key store
    // up to date.
    fn new(policy: P, ks: Arc<RwLock<KeystoreData>>)
    {
        let pdata = ParcimonieServer {
            ks: ks,
            policy,
        };

        thread::spawn(move || ParcimonieServer::run(pdata));
    }

    fn run(mut self) {
        rnp_function!(ParcimonieServer::run, super::TRACE);

        loop {
            let r = self.worker();

            // This shouldn't happen.  If it does, sleep a while and
            // then restart.
            t!("worker returned unexpectedly: {:?}", r);
            thread::sleep(Duration::new(5 * 60, 0));
        }
    }

    fn worker(&mut self) -> openpgp::Result<()> {
        rnp_function!(Parcimonie::woker, super::TRACE);

        // Sleep for a while to avoid interfering with TB's startup.
        let delay = if super::TRACE { 300 } else { 5 * 60 };
        thread::sleep(Duration::new(delay, 0));

        let mut rng = rand::thread_rng();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()?;

        let mut n = self.ks.read().unwrap().count();
        loop {
            {
                let bucket = 1.5f32.powf((n as f32).log(1.5).round());
                t!("n: {} => bucket: {}", n, bucket);

                const LOWER_BOUND: f32 = 5. * 60.;
                const UPPER_BOUND: f32 = 19. * 60. * 60.;
                let lambda: f32 = match
                    (7. * 24. * 60. * 60.)
                    / if bucket > 1. { bucket } else { 1. }
                {
                    lambda if lambda < LOWER_BOUND => LOWER_BOUND,
                    lambda if lambda > UPPER_BOUND => UPPER_BOUND,
                    lambda => lambda,
                };

                let poi = Poisson::new(lambda).expect("valid argument");
                let s = poi.sample(&mut rng) as u64;

                t!("poisson({:?}) sample: {:?}",
                          Duration::new(lambda as u64, 0),
                          Duration::new(s, 0));

                // An extra, extra safety measure: wait at least a few
                // seconds between updates.
                let s = std::cmp::max(s, 5);
                let duration = Duration::new(s, 0);

                t!("Waiting {:?} seconds before checking for \
                           next update",
                          duration);

                // Now sleep.
                thread::sleep(duration);
            }

            // Extract the information we need to do the update and
            // then drop the lock.
            let (fpr, emails) = {
                let ks = self.ks.read().unwrap();

                // While sleeping, the number of certificates that we
                // monitor may have changed.
                n = ks.count();
                if n == 0 {
                    // The key store is empty.  Go back to sleep.
                    continue;
                }

                // If everything is revoked, don't spin forever.
                let mut cert = None;
                for _ in 0..20 {
                    let i = rng.gen_range(0..n);
                    let c = ks.iter().nth(i).unwrap();

                    match c.with_policy(&self.policy, None) {
                        Ok(vc) => {
                            if let RevocationStatus::Revoked(_)
                                = vc.revocation_status()
                            {
                                // The certificate is revoked.  Don't
                                // bother looking for updates.
                                continue;
                            } else {
                                cert = Some(c);
                                break;
                            }
                        }
                        Err(_) => {
                            // Don't bother to look for updates for
                            // certificates that are not valid under
                            // the standard policy.
                            //
                            // Note: this also means that we won't
                            // look for updates to stripped keys,
                            // e.g., those returned by
                            // keys.openpgp.org whose User IDs have
                            // been stripped, and that don't have a
                            // direct key signature.
                            continue;
                        }
                    }
                }
                let cert = if let Some(cert) = cert {
                    cert
                } else {
                    t!("Not bothering to update an invalid or \
                        revoked certificate, sleeping.");
                    continue;
                };

                let fpr = cert.fingerprint();
                t!("Checking for updates to {}!", fpr);

                // Get all of the valid, non-revoked email addresses.
                let emails: Vec<String>
                    = match cert.with_policy(&self.policy, None) {
                        Ok(vcert) => {
                            let mut emails: Vec<String> = vcert.userids()
                                .filter_map(|ua| {
                                    if let RevocationStatus::Revoked(_)
                                        = ua.revocation_status()
                                    {
                                        None
                                    } else {
                                        ua.userid().email2().unwrap_or(None)
                                            .map(ToString::to_string)
                                    }
                                })
                                .collect();

                            emails.sort();
                            emails.dedup();
                            emails
                        }
                        Err(_) => Vec::with_capacity(0),
                    };

                (fpr, emails)
            };

            // Do this is parallel.  Not to be fast, but to overlap I/O.
            let certs: openpgp::Result<Vec<Cert>> = rt.block_on(async move {
                let mut jhs = Vec::with_capacity(emails.len());
                let mut certs: Vec<Cert> = Vec::new();

                for email in emails.into_iter() {
                    jhs.push(tokio::spawn(async move {
                        let r: openpgp::Result<Vec<Cert>>
                            = wkd::get(&email).await;
                        t!("wkd for {}: {:?}",
                                  email,
                                  r.as_ref().map(|certs| {
                                      certs.iter().map(|cert| cert.fingerprint())
                                          .collect::<Vec<Fingerprint>>()
                                  }));
                        r
                    }));
                }

                // This should be in its own task, but it's missing a
                // Send.  It doesn't actually matter in practice as
                // this is the last thing we do before collecting the
                // other results.
                match KeyServer::keys_openpgp_org(NetPolicy::Encrypted) {
                    Ok(mut ks) => {
                        match ks.get(fpr).await {
                            Ok(cert) => certs.push(cert),
                            Err(err) =>
                                t!("key server: {:?}", err),
                        };
                    }
                    Err(err) => t!("key server: {:?}", err),
                }

                for jh in jhs.into_iter() {
                    if let Ok(c) = jh.await.unwrap() {
                        certs.extend(c);
                    }
                }

                Ok(certs)
            });

            // Merge the certificates.  Because we also looked up keys
            // by email address, we may have multiple certificates.
            let certs = match certs {
                Ok(mut certs) => {
                    certs.sort_by_key(|cert| cert.fingerprint());
                    let l = certs.len();
                    certs.into_iter().fold(
                        Vec::with_capacity(l),
                        |mut agg, cert| {
                            let l = agg.len();
                            if l == 0 {
                                agg.push(cert);
                            } else if agg[l - 1].fingerprint()
                                == cert.fingerprint()
                            {
                                let r = agg.pop()
                                    .expect("not empty")
                                    .merge_public(cert)
                                    .expect("Same certificate");
                                agg.push(r);
                            } else {
                                agg.push(cert);
                            }
                            agg
                        })
                }
                Err(err) => {
                    t!("Fetching updates: {}", err);
                    continue;
                }
            };

            if certs.len() > 0 {
                let ks = self.ks.read().unwrap();

                let certs = certs.into_iter()
                    .filter_map(|cert| {
                        let cert = cert.strip_secret_key_material();

                        // Merge the update into the existing key
                        // material, if any.
                        let cert = if let Some(existing)
                            = ks.by_primary_fp(&cert.fingerprint())
                        {
                            existing.clone().merge_public(cert)
                                .expect("same certificate")
                        } else {
                            cert
                        };

                        // See if it needs cleaning.
                        self.clean(cert)
                    })
                    .collect::<Vec<Cert>>();

                // Upgrade the lock.
                drop(ks);
                let mut ks = self.ks.write().unwrap();

                for cert in certs.into_iter() {
                    ks.insert(cert);
                }
            }
        }
    }


    /// Cleans a certificate.
    ///
    /// This tries to detect if a certificate is flooded and if so,
    /// tries to recover.  If the certificate is flooded and not valid
    /// under the policy, then it is simply dropped.
    ///
    /// This function takes a read lock on the keystore.
    fn clean(&self, cert: Cert) -> Option<Cert> {
        rnp_function!(Parcimonie::clean, super::TRACE);

        // Check for an excess of third-party signatures.
        let flooded_uids = cert.userids()
            .any(|ua| {
                let c = ua.certifications().count();
                if c > THIRD_PARTY_SIG_THRESHOLD {
                    t!("{}, {} appears to be flooded ({} certifications)",
                       cert.fingerprint(), ua.userid(), c);
                    true
                } else {
                    false
                }
            });
        let flooded_uas = cert.user_attributes().enumerate()
            .any(|(i, ua)| {
                let c = ua.certifications().count();
                if c > THIRD_PARTY_SIG_THRESHOLD {
                    t!("{}, UA #{} appears to be flooded ({} certifications)",
                       cert.fingerprint(), i, c);
                    true
                } else {
                    false
                }
            });
        if ! flooded_uids && ! flooded_uas {
            t!("Certificate does not appear to be flooded");
            return Some(cert);
        }

        t!("Certificate might be flooded, \
            dropping 3rd party certifications that we can't check");

        // Iterate over all of the Cert components, pushing
        // packets we want to keep into the accumulator.
        let vc = match cert.with_policy(&self.policy, None) {
            Ok(vc) => vc,
            Err(err) => {
                t!("Cert is not valid under the policy, ignoring: {}", err);
                return None;
            }
        };

        fn filter<'a>(userid: Option<&UserID>,
                      ks: &RwLockReadGuard<KeystoreData>,
                      sigs: impl Iterator<Item=&'a Signature>) -> Vec<Signature> {
            let mut most_recent: HashMap<Fingerprint, Signature>
                = Default::default();

            // Only keep certifications from keys in our keyring.
            for sig in sigs {
                // We only consider certifications with an Issuer
                // Fingerprint subpacket.  This automatically strips
                // very old certifications.
                for issuer in sig.issuer_fingerprints() {
                    // Do we have an issuer?
                    if let Some(_) = ks.by_fp(&issuer).nth(0) {
                        // Do we already have a sig from this issuer?
                        match most_recent.entry(issuer.clone()) {
                            Entry::Occupied(mut e) => {
                                // Take the newest one.
                                if sig.signature_creation_time()
                                    > e.get().signature_creation_time()
                                {
                                    *e.get_mut() = sig.clone();
                                }
                            }
                            Entry::Vacant(v) => {
                                v.insert(sig.clone());
                            }
                        }
                    }
                }
            }

            let sigs: Vec<Signature> = most_recent.into_iter()
                .map(|(_, sig)| sig.clone())
                .collect();

            if sigs.len() > THIRD_PARTY_SIG_THRESHOLD {
                // Still too many.

                if userid.is_none() {
                    // No one really cares about user attributes, so
                    // just drop any third party signatures.
                    t!("After pruning from user attribute, \
                        still have {} certifications, dropping all.",
                       sigs.len());
                    Vec::with_capacity(0)
                } else {
                    // This could happen if the certifications are
                    // forged.  We could try and validate them.  But,
                    // we may not have access to the certificates from
                    // this thread.
                    t!("{:?}: Keeping {} certifications",
                       userid.unwrap(), sigs.len());
                    sigs
                }
            } else {
                t!("{:?}: Keeping {} certifications",
                   userid
                      .map(|uid| String::from_utf8_lossy(uid.value()))
                      .unwrap_or("User Attribute".into()),
                   sigs.len());
                sigs
            }
        }

        // We exclude third party signatures and revocations on
        // components except for UserIDs and User Attributes where we
        // filter them.

        let ks = self.ks.read().unwrap();

        // Primary key and related signatures.
        let mut p: Vec<Packet> = Vec::with_capacity(64);
        let pk = vc.primary_key();
        p.push(pk.key().clone().into());
        for s in pk.self_signatures()        { p.push(s.clone().into()) }
        // for s in pk.certifications()         { p.push(s.clone().into()) }
        for s in pk.self_revocations()       { p.push(s.clone().into()) }
        for s in pk.other_revocations()      { p.push(s.clone().into()) }

        // UserIDs and related signatures.
        for ua in vc.userids() {
            p.push(ua.userid().clone().into());
            for s in ua.self_signatures()   { p.push(s.clone().into()) }
            for s in filter(Some(ua.userid()), &ks, ua.certifications())
                                            { p.push(s.clone().into()) }
            for s in ua.self_revocations()  { p.push(s.clone().into()) }
            //for s in ua.other_revocations() { p.push(s.clone().into()) }
        }

        // UserAttributes and related signatures.
        for ua in vc.user_attributes() {
            p.push(ua.user_attribute().clone().into());
            for s in ua.self_signatures()   { p.push(s.clone().into()) }
            for s in filter(None, &ks, ua.certifications())
                                            { p.push(s.clone().into()) }
            for s in ua.self_revocations()  { p.push(s.clone().into()) }
            //for s in ua.other_revocations() { p.push(s.clone().into()) }
        }

        // Subkeys and related signatures.
        for ka in vc.keys().subkeys() {
            p.push(ka.key().clone().into());
            for s in ka.self_signatures()   { p.push(s.clone().into()) }
            //for s in ka.certifications()    { p.push(s.clone().into()) }
            for s in ka.self_revocations()  { p.push(s.clone().into()) }
            //for s in ka.other_revocations() { p.push(s.clone().into()) }
        }

        // We exclude unknown components.
        //for ua in vc.unknowns() {
        //    p.push(ua.unknown().clone().into());
        //    for s in ua.self_signatures()   { p.push(s.clone().into()) }
        //    for s in ua.certifications()    { p.push(s.clone().into()) }
        //    for s in ua.self_revocations()  { p.push(s.clone().into()) }
        //    for s in ua.other_revocations() { p.push(s.clone().into()) }
        //}

        // We exclude bad signatures.
        //for s in cert.bad_signatures()     { p.push(s.clone().into()) }

        // Finally, parse into Cert.
        Some(Cert::from_packets(p.into_iter()).expect("still valid"))
    }
}
