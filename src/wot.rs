use std::collections::HashSet;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use std::time::SystemTime;

use rusqlite::{
    Connection,
    types::ToSql,
    OptionalExtension,
    params,
};

use sequoia_openpgp as openpgp;
use openpgp::{Cert, Fingerprint};
use openpgp::packet::UserID;
use sequoia_openpgp::policy::Policy;
use sequoia_wot::{Root, Roots, store::Store};


use crate::gpg;
use crate::gpg::Validity;
use crate::keystore::KeystoreData;
use crate::tbprofile::TBProfile;

/// Controls tracing in this module.
const TRACE: bool = crate::TRACE;

pub struct WoT {
    conn: rusqlite::Connection,
    _gpg_ctx: gpg::Ctx,
    last_update: SystemTime,

    /// Known last_update stamp from the KeyStore.
    last_keystore_update: usize,

    /// Time at which our WoT calculation possibly go stale and need
    /// to be recomputed, provided the KeyStore wasn't modified.
    next_wot_change_at: Option<SystemTime>,
}

impl WoT {
    // Return a locked WoTData.
    //
    // If WoT hasn't been initialized, do it now.
    pub(crate) fn new() -> openpgp::Result<WoT> {
        let gpg_ctx = gpg::Ctx::new()?;

        let path = TBProfile::path()
            .ok_or(anyhow::anyhow!("TB Profile directory not found"))?;

        // The tables that TB creates:
        //
        // Note the unfortunate lack of a version number :/.
        //
        //   CREATE TABLE acceptance_email
        //     (fpr text not null, email text not null, unique(fpr, email));
        //   CREATE TABLE acceptance_decision
        //     (fpr text not null, decision text not null, unique(fpr));
        //
        // Make sure the DB meets our expectations DB before continuing.
        let mut conn = Connection::open(path.join("openpgp.sqlite"))?;
        conn.query_row("SELECT fpr, email FROM acceptance_email LIMIT 1",
                       params![], |_| Ok(()))
            .optional()
            .map_err(|err| {
                let err: anyhow::Error = err.into();
                let err = err.context(
                    "openpgp.sqlite: \
                     Unexpected schema (querying acceptance_email)");
                global_warn!("openpgp.sqlite: {}", err);
                err
            })?;
        conn.query_row("SELECT fpr, decision FROM acceptance_decision LIMIT 1",
                       params![], |_| Ok(()))
            .optional()
            .map_err(|err| {
                let err: anyhow::Error = err.into();
                let err = err.context(
                    "openpgp.sqlite:\
                     Unexpected schema (querying acceptance_decision)");
                global_warn!("openpgp.sqlite: {}", err);
                err
            })?;

        let tx = conn.transaction()?;

        // Be extra careful to not override user decisions.
        //
        // A given certificate can be in one of three states:
        //
        //   1. Not in acceptance_decision and thus not managed by the user
        //      or us.
        //
        //   2. In acceptance_decision and not in managed_by_sequoia and
        //      thus managed by the user.
        //
        //   3. In acceptance_decision and in managed_by_sequoia and
        //      thus managed by us.
        //
        // Using triggers, we cause the managed_by_sequoia entry to be
        // deleted when the user (via TB) sets the acceptance.
        //
        // When updating the acceptance criteria, we don't touch
        // certificates that fall into category 2.  Everything else is
        // fair game.
        tx.execute("CREATE TABLE IF NOT EXISTS managed_by_sequoia \
                    (fpr text not NULL, unique(fpr))",
                   params![])?;
        tx.execute("CREATE INDEX IF NOT EXISTS managed_by_sequoia_i \
                    ON managed_by_sequoia (fpr)",
                   params![])?;
        tx.execute("CREATE TRIGGER IF NOT EXISTS user_update \
                    UPDATE on acceptance_decision \
                    FOR EACH ROW \
                    BEGIN \
                    DELETE FROM managed_by_sequoia \
                    WHERE managed_by_sequoia.fpr = NEW.fpr; \
                    END",
                   params![])?;
        tx.execute("CREATE TRIGGER IF NOT EXISTS user_insert \
                    INSERT on acceptance_decision \
                    FOR EACH ROW \
                    BEGIN \
                    DELETE FROM managed_by_sequoia \
                    WHERE managed_by_sequoia.fpr = NEW.fpr; \
                    END",
                   params![])?;

        tx.commit()?;

        Ok(WoT {
            _gpg_ctx: gpg_ctx,
            conn,
            last_update: std::time::UNIX_EPOCH,
            last_keystore_update: 0,
            next_wot_change_at: None,
        })
    }

    // Do an update of the WoT validities.
    //
    // Carefully update TB's acceptance DB with GPG's validity.
    pub fn update(&mut self, ksd: Arc<RwLock<KeystoreData>>, p: &dyn Policy) -> openpgp::Result<()>
    {
        rnp_function!(WoT::update, TRACE);

        let now = SystemTime::now();
        let elapsed = now.duration_since(self.last_update);
        match elapsed {
            Err(err) => {
                t!("Error computing time since last update: {}", err);
                return Ok(());
            }
            Ok(elapsed) => {
                if elapsed < Duration::new(10, 0) {
                    t!("Throttling updates.");
                    return Ok(());
                }
            }
        }

        // Read lock the key store, do a scan across the certs, and
        // release it as soon as possible.
        let keystore_data = ksd.read().unwrap();

        // Check the stored key store timestamp.
        let last_keystore_update = keystore_data.last_update();
        if self.last_keystore_update == last_keystore_update
            && self.next_wot_change_at.map(|t| now < t).unwrap_or(false)
        {
            t!("Keystore has not changed, and no known cert component \
                or signature could have possibly changed, skipping.");
            return Ok(());
        }

        // We compute the next time at which a cert component or
        // signature is valid or invalid.
        let mut next_wot_change_at: SystemTime =
            openpgp::types::Timestamp::from(u32::MAX).into();

        // We clone the certificates in the key store to be able to drop the
        // keystore lock as soon as possible.
        let certs: Vec<Cert> = keystore_data.iter()
            .map(|c| {
                // Considers time `t`.
                let mut consider = |t| {
                    if t > now && t < next_wot_change_at {
                        next_wot_change_at = t;
                    }
                };

                // All possible certification (sub)keys.
                for skb in c.keys().filter(|k| k.pk_algo().for_signing()) {
                    for sig in skb.signatures() {
                        consider(sig.signature_creation_time().unwrap());
                        if let Some(t) = sig.signature_expiration_time() {
                            consider(t);
                        }
                        if let Some(t) = sig.key_expiration_time(skb.key()) {
                            consider(t);
                        }
                    }
                }

                // All possible certification user IDs.
                for sig in c.userids().flat_map(|u| u.signatures()) {
                    consider(sig.signature_creation_time().unwrap());
                    if let Some(t) = sig.signature_expiration_time() {
                        consider(t);
                    }
                    if let Some(t) = sig.key_expiration_time(&c.primary_key()) {
                        consider(t);
                    }
                }

                // All possible certification user attributes.
                for sig in c.user_attributes().flat_map(|u| u.signatures()) {
                    consider(sig.signature_creation_time().unwrap());
                    if let Some(t) = sig.signature_expiration_time() {
                        consider(t);
                    }
                    if let Some(t) = sig.key_expiration_time(&c.primary_key()) {
                        consider(t);
                    }
                }

                (*c).clone()
            })
            .collect();

        // Drop the lock.
        drop(keystore_data);

        t!("Checking for WoT updates...");
        t!("Keystore size: {}", certs.len());

        let reference_time = SystemTime::now();

        // GnuPG ownertrust "Ultimate"
        let mut trust_roots: Vec<Root> = Vec::new();

        // Possible roots: GnuPG ownertrust "Fully" and "Marginal"
        let mut possible_roots: Vec<Root> = Vec::new();

        // Get trust roots from GnuPG.
        let ownertrust = gpg::export_ownertrust()?;
        for (fpr, ownertrust) in ownertrust {
            match ownertrust {
                gpg::OwnerTrust::Ultimate => {
                    trust_roots.push(
                        Root::new(fpr, sequoia_wot::FULLY_TRUSTED));
                }
                gpg::OwnerTrust::Fully => {
                    possible_roots.push(
                        Root::new(fpr, sequoia_wot::FULLY_TRUSTED));
                }
                gpg::OwnerTrust::Marginal => {
                    possible_roots.push(
                        Root::new(fpr, sequoia_wot::PARTIALLY_TRUSTED));
                }
                _ => (),
            }
        }

        let roots = Roots::new(trust_roots.clone());
        t!("Trust roots (ultimate ownertrust): {:?}", roots);

        let network = sequoia_wot::Network::from_cert_refs(
            &certs, &*p, reference_time).unwrap();
        let mut query =
            sequoia_wot::Query::new(&network, roots);

        // Add GnuPG intermediate trust roots to 'trust_roots'
        let mut found_one = true;
        while found_one && !possible_roots.is_empty() {
            // For GnuPG to consider a non-ultimately trusted root as
            // valid, there must be a path from an ultimately trusted root
            // to the non-ultimately trusted root.  If this is the case,
            // add those roots.

            t!("Checking if any of {} are reachable from the current {} roots",
                possible_roots.iter()
                    .fold(String::new(), |mut s, pr| {
                        if ! s.is_empty() {
                            s.push_str(", ");
                        }
                        s.push_str(&pr.fingerprint().to_hex());
                        s
                    }),
                trust_roots.len());

            found_one = false;
            let pr = possible_roots;
            possible_roots = Vec::new();

            'root: for r in pr.into_iter() {
                let cert = match network.lookup_synopsis_by_fpr(&r.fingerprint()) {
                    Err(_e) => {
                        t!("Ignoring root {}: not in network.", r.fingerprint());
                        continue;
                    }
                    Ok(v) => v,
                };

                for u in cert.userids() {
                    if u.revocation_status().in_effect(reference_time) {
                        t!("Ignoring root {}'s User ID {:?}: revoked.",
                            r.fingerprint(), String::from_utf8_lossy(u.value()));
                        continue;
                    }

                    let authenticated_amount = query.authenticate(
                        u.userid(), r.fingerprint(), sequoia_wot::FULLY_TRUSTED)
                        .amount();

                    if authenticated_amount >= sequoia_wot::FULLY_TRUSTED {
                        // Authenticated!  We'll keep it.
                        t!("Non-ultimately trusted root <{}, {}> reachable, \
                            keeping at {}",
                            r.fingerprint(),
                            String::from_utf8_lossy(u.userid().value()),
                            r.amount());
                        found_one = true;
                        trust_roots.push(r);
                        query = sequoia_wot::Query::new(
                            &network, Roots::new(trust_roots.clone()));
                        continue 'root;
                    } else {
                        t!("Non-ultimately trusted binding <{}, {}> \
                            NOT fully trusted (amount: {})",
                            r.fingerprint(),
                            String::from_utf8_lossy(u.userid().value()),
                            authenticated_amount);
                    }
                }

                t!("Non-ultimately trusted root {} NOT fully trusted. Ignoring.",
                    r.fingerprint());
                possible_roots.push(r);
            }
        }

        let validity: Vec<(Fingerprint, Vec<(String, Validity)>)> =
            certs.iter().map(|c| {
                let fp = c.fingerprint();
                let userids: Vec<(String, Validity)> =
                    c.with_policy(&*p, reference_time).map(|vc| {
                        vc.userids().filter_map(|uid| {
                            if let Ok(s) = String::from_utf8(uid.value().to_vec()) {
                                let paths = query.authenticate(
                                    uid.userid(), &fp,
                                    sequoia_wot::FULLY_TRUSTED);

                                if let Some(validity) = match paths.amount() {
                                    amount if amount >= sequoia_wot::FULLY_TRUSTED => Some(Validity::Fully),
                                    amount if amount > 0 => Some(Validity::Marginal),
                                    _ => None
                                } {
                                    Some((s, validity))
                                } else {
                                    None
                                }
                            } else {
                                None
                            }
                        }).collect::<Vec<(String, Validity)>>()
                    }).unwrap_or(vec![]);
                (fp, userids)
            }).collect();

        t!("sequoia-wot validities: {:#?}", validity);

        let mut tx = self.conn.transaction()?;

        // See comment in `WoT::new` regarding what exactly is
        // considered managed by sequoia.
        let managed_by_tb: HashSet<String> = {
            let mut stmt =
                tx.prepare("SELECT fpr from acceptance_decision \
                            WHERE fpr NOT IN \
                            (SELECT fpr from managed_by_sequoia)")?;
            let rows = stmt
                .query_map(params![], |row| row.get::<_, String>(0).map(|fpr| {
                    fpr.to_ascii_lowercase()
                }));
            match rows {
                Ok(iter) => iter.filter_map(|fpr| fpr.ok()).collect(),
                Err(err) => {
                    warn!("Querying managed_by_sequoia: {}", err);
                    Default::default()
                }
            }
        };

        Self::import_validity(&mut tx, Some(managed_by_tb), validity)?;

        tx.commit()?;

        self.last_update = SystemTime::now();
        self.last_keystore_update = last_keystore_update;
        self.next_wot_change_at = Some(next_wot_change_at);

        Ok(())
    }


    // If managed_by_tb is None, then validity has already been
    // filtered to only contain keys managed by us.
    fn import_validity(tx: &mut rusqlite::Transaction,
                       managed_by_tb: Option<HashSet<String>>,
                       validity: Vec<(Fingerprint, Vec<(String, gpg::Validity)>)>)
                       -> openpgp::Result<()>
    {
        rnp_function!(WoT::import_validity, TRACE);

        // First, remove all assertions managed by sequoia
        // (they will get re-added below, if they are still valid).
        match tx.execute(
            "DELETE FROM acceptance_decision WHERE fpr IN \
            (SELECT fpr FROM managed_by_sequoia)",
            params![],
        ) {
            Ok(_) => t!("Removed sequoia-managed acceptance entries"),
            Err(e) => {
                warn!("Removing sequoia-managed acceptance failed: {}", e);
            }
        }

        for (fpr, key_validity) in validity {
            let key_validity: Vec<_> = key_validity
                .into_iter()
                .filter_map(|(uid, validity)| {
                    match UserID::from(uid.clone()).email2() {
                        Ok(Some(email)) => {
                            Some((email.to_ascii_lowercase(), validity))
                        },
                        Ok(None) => None,
                        Err(err) => {
                            warn!("Extracting email address from UserID: {:?}: {}",
                                  uid, err);
                            None
                        }
                    }
                })
                .collect();
            if key_validity.is_empty() {
                continue;
            }

            // We can only have two judgements per certificate: "none" or
            // "something else".  Unfortunately, the format isn't more
            // expressive.  If any are maginal, then we treat all verified
            // User IDs as maginal.
            let validity = if key_validity.iter().any(|(_uid, validity)| {
                *validity == Validity::Marginal
            }) {
                "unverified"
            } else {
                "verified"
            };

            let fpr = fpr.to_string().to_ascii_lowercase();
            if managed_by_tb.as_ref().map(|h| h.contains(&fpr)).unwrap_or(true) {
                t!("Not updating validity for {} to {:?}: \
                    validity managed by user",
                   fpr, validity);
            } else {
                t!("Setting {} to {}", fpr, validity);

                tx.execute(
                    "INSERT OR REPLACE INTO acceptance_decision \
                     (fpr, decision) VALUES (?1, ?2)",
                    &[&fpr as &dyn ToSql, &validity])?;

                tx.execute(
                    "INSERT OR REPLACE INTO managed_by_sequoia \
                     (fpr) VALUES (?1)",
                    &[&fpr as &dyn ToSql])?;

                for (email, _validity) in key_validity {
                    t!("Setting {}, {} to {}", fpr, email, validity);
                    tx.execute(
                        "INSERT OR REPLACE INTO acceptance_email \
                         (fpr, email) VALUES (?1, ?2)",
                        &[&fpr as &dyn ToSql, &email])?;
                }
            }
        }

        Ok(())
    }
}
