use std::{
    collections::{
        HashMap,
    },
    cell::{
        RefCell,
        Ref,
        RefMut,
    },
    rc::{
        Rc,
    },
};

use sequoia_openpgp as openpgp;
use openpgp::{
    Fingerprint,
    KeyID,
    Cert,
};

use crate::{
    Keygrip,
};

#[derive(Default)]
pub struct Keystore {
    // The bool indicates whether the key is considered external.
    by_primary_fp: HashMap<Fingerprint, (Rc<RefCell<Cert>>, bool)>,
    by_primary_id: HashMap<KeyID, Rc<RefCell<Cert>>>,
    by_primary_grip: HashMap<Keygrip, Rc<RefCell<Cert>>>,
    by_subkey_fp: HashMap<Fingerprint, Rc<RefCell<Cert>>>,
    by_subkey_id: HashMap<KeyID, Rc<RefCell<Cert>>>,
    by_subkey_grip: HashMap<Keygrip, Rc<RefCell<Cert>>>,
}

impl Keystore {
    /// Returns a reference to the cert with the given fingerprint, if
    /// any.
    pub fn by_primary_fp(&self, fp: &Fingerprint) -> Option<Ref<Cert>> {
        self.by_primary_fp.get(fp).map(|c| c.0.borrow())
    }

    /// Returns a mutable reference to the cert with the given
    /// fingerprint, if any.
    ///
    /// A stern warning: Do not use the mutable reference to remove
    /// subkeys.  Use Keystore::remove_all for that.
    pub fn by_primary_fp_mut(&self, fp: &Fingerprint) -> Option<RefMut<Cert>> {
        self.by_primary_fp.get(fp).map(|c| c.0.borrow_mut())
    }

    /// Returns a reference to the cert with the given keyid, if any.
    pub fn by_primary_id(&self, id: &KeyID) -> Option<Ref<Cert>> {
        self.by_primary_id.get(id).map(|c| c.borrow())
    }

    /// Returns a reference to the cert with the given keygrip, if
    /// any.
    pub fn by_primary_grip(&self, grip: &Keygrip) -> Option<Ref<Cert>> {
        self.by_primary_grip.get(grip).map(|c| c.borrow())
    }

    /// Returns a reference to the cert containing a subkey with the
    /// given fingerprint, if any.
    pub fn by_subkey_fp(&self, fp: &Fingerprint) -> Option<Ref<Cert>> {
        self.by_subkey_fp.get(fp).map(|c| c.borrow())
    }

    /// Returns a mutable reference to the cert containing a subkey
    /// with the given fingerprint, if any.
    ///
    /// A stern warning: Do not use the mutable reference to remove
    /// subkeys.  Use Keystore::remove_all for that.
    pub fn by_subkey_fp_mut(&self, fp: &Fingerprint) -> Option<RefMut<Cert>> {
        self.by_subkey_fp.get(fp).map(|c| c.borrow_mut())
    }

    /// Returns a reference to the cert containing a subkey with the
    /// given keyid, if any.
    pub fn by_subkey_id(&self, id: &KeyID) -> Option<Ref<Cert>> {
        self.by_subkey_id.get(id).map(|c| c.borrow())
    }

    /// Returns a reference to the cert containing a subkey with the
    /// given keygrip, if any.
    pub fn by_subkey_grip(&self, grip: &Keygrip) -> Option<Ref<Cert>> {
        self.by_subkey_grip.get(grip).map(|c| c.borrow())
    }

    /// Returns an iterator over the certs.
    pub fn iter(&self) -> impl Iterator<Item = Ref<Cert>> {
        self.by_primary_fp.values().map(|c| c.0.borrow())
    }

    /// Returns an iterator over the certs.
    pub fn to_save(&self) -> impl Iterator<Item = Ref<Cert>> {
        self.by_primary_fp.values().filter_map(|(cert, external)| {
            if *external {
                None
            } else {
                Some(cert.borrow())
            }
        })
    }

    /// Returns the number of certs in the keyring.
    pub fn len(&self) -> usize {
        self.by_primary_fp.len()
    }

    /// Inserts a cert.
    fn insert_(&mut self, mut cert: Cert, is_external: bool) {
        let fp = cert.fingerprint();
        let id = KeyID::from(&fp);
        let grip = Keygrip::of(cert.primary_key().mpis()).ok();

        let mut was_external = true;
        if let Some(ref mut existing) = self.by_primary_fp.get_mut(&fp) {
            assert_eq!(existing.0.borrow().fingerprint(), fp);
            cert = existing.0.borrow().clone().merge_public(cert)
                .expect("does not fail if the primary keys are equal");
            was_external = existing.1;
        }

        let cert = Rc::new(RefCell::new(cert));
        self.by_primary_fp.insert(fp,
                                  (cert.clone(),
                                   was_external && is_external));
        self.by_primary_id.insert(id, cert.clone());
        if let Some(g) = grip {
            self.by_primary_grip.insert(g, cert.clone());
        }

        // Add subkey indices.
        for sk in cert.borrow().keys().subkeys() {
            let fp = sk.fingerprint();
            let id = KeyID::from(&fp);
            let grip = Keygrip::of(sk.mpis()).ok();

            self.by_subkey_fp.insert(fp, cert.clone());
            self.by_subkey_id.insert(id, cert.clone());
            if let Some(g) = grip {
                self.by_subkey_grip.insert(g, cert.clone());
            }
        }
    }

    /// Inserts a cert.
    pub fn insert(&mut self, cert: Cert) {
        self.insert_(cert, false)
    }

    /// Inserts a cert, which comes from an external source.
    pub fn insert_external(&mut self, cert: Cert) {
        self.insert_(cert, true)
    }

    /// Removes the subkey or certificate with fingerprint `fp`.
    ///
    /// Returns true if at least one key/cert has been removed.
    pub fn remove_all(&mut self, fp: &Fingerprint) -> bool {
        let mut removed_one = false;

        // First, remove the cert with that fingerprint.
        if let Some(cert) = self.by_primary_fp.remove(fp) {
            removed_one = true;

            // Remove indices.
            let id = KeyID::from(fp);
            let grip = Keygrip::of(cert.0.borrow().primary_key().mpis()).ok();
            self.by_primary_id.remove(&id);
            if let Some(g) = grip {
                self.by_primary_grip.remove(&g);
            }

            // Remove subkey indices.
            for sk in cert.0.borrow().keys().subkeys() {
                let fp = sk.fingerprint();
                let id = KeyID::from(&fp);
                let grip = Keygrip::of(sk.mpis()).ok();

                self.by_subkey_fp.remove(&fp);
                self.by_subkey_id.remove(&id);
                if let Some(g) = grip {
                    self.by_subkey_grip.remove(&g);
                }
            }
        }

        // Then, remove all subkeys with that fingerprint.
        let mut remove_subkey_grip = None;
        self.by_primary_fp.values_mut().for_each(|c| {
            if c.0.borrow().keys().subkeys().key_handle(fp).count() == 0 {
                // Shortcut to avoid the clone.
                return;
            }

            let cert = c.0.borrow().clone();
            c.0.replace(cert.retain_subkeys(|ska| if ska.fingerprint() == *fp {
                removed_one = true;
                remove_subkey_grip = Keygrip::of(ska.mpis()).ok();
                false
            } else {
                true
            }));
        });

        // Finally, remove subkey indices.
        self.by_subkey_fp.remove(fp);
        self.by_subkey_id.remove(&fp.into());
        if let Some(g) = remove_subkey_grip {
            self.by_subkey_grip.remove(&g);
        }

        removed_one
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use openpgp::cert::prelude::*;
    use openpgp::packet::prelude::*;
    use openpgp::policy::StandardPolicy;

    // Makes sure the maps contain the specified number of keys.
    fn ks_count<P, S>(ks: &Keystore, n_pks: P, n_sks: S)
        where P: Into<Option<usize>>, S: Into<Option<usize>>
    {
        if let Some(n_pks) = n_pks.into() {
            assert_eq!(ks.by_primary_fp.len(), n_pks,
                       "Expected {} primary fps, got {}",
                       n_pks, ks.by_primary_fp.len());
            assert_eq!(ks.by_primary_id.len(), n_pks,
                       "Expected {} primary key ids, got {}",
                       n_pks, ks.by_primary_id.len());
            assert_eq!(ks.by_primary_grip.len(), n_pks,
                       "Expected {} primary grips, got {}",
                       n_pks, ks.by_primary_grip.len());
        }

        if let Some(n_sks) = n_sks.into() {
            assert_eq!(ks.by_subkey_fp.len(), n_sks,
                       "Expected {} subkey fps, got {}",
                       n_sks, ks.by_subkey_fp.len());
            assert_eq!(ks.by_subkey_id.len(), n_sks,
                       "Expected {} subkey key ids, got {}",
                       n_sks, ks.by_subkey_id.len());
            assert_eq!(ks.by_subkey_grip.len(), n_sks,
                       "Expected {} subkey grips, got {}",
                       n_sks, ks.by_subkey_grip.len());
        }
    }

    // Makes sure the keystore's maps contain the specified keys
    // either as primary keys (the first bool) or as subkeys (the
    // second bool).
    fn ks_contains(ks: &Keystore,
                   checks: &[(&ErasedKeyAmalgamation<key::PublicParts>,
                              bool, bool)])
    {
        for (ka, as_primary, as_sub) in checks.iter() {
            let fpr = ka.fingerprint();
            match ks.by_primary_fp(&fpr) {
                Some(_) if *as_primary => (),
                Some(_) =>
                    panic!("Found primary key for {}, expected nothing",
                           fpr),
                None if ! *as_primary => (),
                None =>
                    panic!("Primary key for {} not found, but expected",
                           fpr),
            }
            match ks.by_subkey_fp(&fpr) {
                Some(_) if *as_sub => (),
                Some(_) =>
                    panic!("Found subkey for {}, expected nothing",
                           fpr),
                None if ! *as_sub => (),
                None =>
                    panic!("Subkey for {} not found, but expected",
                           fpr),
            }
            let keyid = ka.keyid();
            match ks.by_primary_id(&keyid) {
                Some(_) if *as_primary => (),
                Some(_) =>
                    panic!("Found primary key for {}, expected nothing",
                           keyid),
                None if ! *as_primary => (),
                None =>
                    panic!("Primary key for {} not found, but expected",
                           keyid),
            }
            match ks.by_subkey_id(&keyid) {
                Some(_) if *as_sub => (),
                Some(_) =>
                    panic!("Found subkey for {}, expected nothing",
                           keyid),
                None if ! *as_sub => (),
                None =>
                    panic!("Subkey for {} not found, but expected",
                           keyid),
            }
            if let Ok(grip) = Keygrip::of(ka.mpis()) {
                match ks.by_primary_grip(&grip) {
                    Some(_) if *as_primary => (),
                    Some(_) =>
                        panic!("by_primary_keygrip({}) \
                                got something, expected nothing",
                               grip),
                    None if ! *as_primary => (),
                    None =>
                        panic!("by_primary_keygrip({}) \
                                got nothing, expected something",
                               grip),
                }
                match ks.by_subkey_grip(&grip) {
                    Some(_) if *as_sub => (),
                    Some(_) =>
                        panic!("by_subkey_keygrip({}) \
                                got something, expected nothing",
                               grip),
                    None if ! *as_sub => (),
                    None =>
                        panic!("by_subkey_keygrip({}) \
                                got nothing, expected something",
                               grip),
                }
            }
        }
    }

    // Asserts that a key does not appear in the key store, either in
    // the indices or in any of the certificates.
    fn ks_is_missing(ks: &Keystore,
                     ka: &ErasedKeyAmalgamation<key::PublicParts>)
    {
        // First check the maps.
        ks_contains(ks, &[ (&ka, false, false) ]);

        // Now iterate over everything and make sure it is really gone.
        for (table, cert) in
            ks.by_primary_fp.values().map(|v| ("by_primary_fp", Rc::clone(&v.0)))
                .chain(ks.by_primary_id.values().map(|v| {
                    ("by_primary_id", Rc::clone(v))
                }))
                .chain(ks.by_primary_grip.values().map(|v| {
                    ("by_primary_grip", Rc::clone(v))
                }))
                .chain(ks.by_subkey_fp.values().map(|v| {
                    ("by_subkey_fp", Rc::clone(v))
                }))
                .chain(ks.by_subkey_id.values().map(|v| {
                    ("by_subkey_id", Rc::clone(v))
                }))
                .chain(ks.by_subkey_grip.values().map(|v| {
                    ("by_subkey_grip", Rc::clone(v))
                }))
        {
            let cert = cert.borrow();
            for k in cert.keys() {
                assert!(k.fingerprint() != ka.fingerprint(),
                        "{}: {} still exists in {}, {:?}",
                        table,
                        ka.fingerprint(),
                        k.fingerprint(),
                        cert.with_policy(&StandardPolicy::new(), None)
                            .map(|cert| {
                                cert.primary_userid()
                                    .map(|ua| {
                                        String::from_utf8_lossy(ua.userid().value())
                                            .into_owned()
                                    })
                                    .unwrap_or("<No UserID>"[..].into())
                            })
                            .unwrap_or("<Invalid>".into()));
            }
        }
    }

    #[test]
    fn insert_remove() -> openpgp::Result<()> {
        let mut ks = Keystore::default();
        ks_count(&ks, 0, 0);

        // Generate a key and insert it.
        let (alice, revocation) = openpgp::cert::CertBuilder::general_purpose(
            None, Some("alice")).generate()?;
        ks.insert(alice.clone());

        let n_subkeys = alice.keys().subkeys().count();
        ks_count(&ks, 1, n_subkeys);
        ks_contains(&ks, &[
            (&alice.primary_key().into(), true, false)
        ]);
        for sk in alice.keys().subkeys() {
            // Try lookups.
            ks_contains(&ks, &[
                (&sk.into(), false, true)
            ]);
        }

        // Now, remove one subkey.
        let removed_sk = alice.keys().subkeys().nth(0).unwrap();
        let fp = removed_sk.fingerprint();
        let r = ks.remove_all(&fp);
        assert!(r);

        ks_is_missing(&ks, &removed_sk.into());

        // Remove the subkey from our copy of Alice's cert, and redo
        // all the lookups.
        let alice = alice.retain_subkeys(|sk| sk.fingerprint() != fp);
        let n_subkeys = alice.keys().subkeys().count();
        ks_count(&ks, 1, n_subkeys);
        ks_contains(&ks, &[
            (&alice.primary_key().into(), true, false)
        ]);
        for sk in alice.keys().subkeys() {
            // Try lookups.
            ks_contains(&ks, &[
                (&sk.into(), false, true)
            ]);
        }

        // Merge the revocation certificate.
        {
            let mut cert = ks.by_primary_fp_mut(&alice.fingerprint()).unwrap();
            *cert = cert.clone().insert_packets(Some(revocation))?;
        }
        use openpgp::types::RevocationStatus;
        let p = &openpgp::policy::StandardPolicy::new();

        let fp = alice.fingerprint();
        let id = KeyID::from(&fp);
        let grip = Keygrip::of(alice.primary_key().mpis())?;
        assert!(matches!(
            ks.by_primary_fp(&fp).unwrap().revocation_status(p, None),
            RevocationStatus::Revoked(_)));
        assert!(matches!(
            ks.by_primary_id(&id).unwrap().revocation_status(p, None),
            RevocationStatus::Revoked(_)));
        assert!(matches!(
            ks.by_primary_grip(&grip).unwrap().revocation_status(p, None),
            RevocationStatus::Revoked(_)));
        ks_contains(&ks, &[
            (&alice.primary_key().into(), true, false)
        ]);

        for sk in alice.keys().subkeys() {
            let fp = sk.fingerprint();
            let id = KeyID::from(&fp);
            let grip = Keygrip::of(sk.mpis())?;

            assert!(ks.by_primary_fp(&fp).is_none());
            assert!(ks.by_primary_id(&id).is_none());
            assert!(ks.by_primary_grip(&grip).is_none());
            assert!(matches!(
                ks.by_subkey_fp(&fp).unwrap().revocation_status(p, None),
                RevocationStatus::Revoked(_)));
            assert!(matches!(
                ks.by_subkey_id(&id).unwrap().revocation_status(p, None),
                RevocationStatus::Revoked(_)));
            assert!(matches!(
                ks.by_subkey_grip(&grip).unwrap().revocation_status(p, None),
                RevocationStatus::Revoked(_)));

            ks_contains(&ks, &[
                (&sk.into(), false, true)
            ]);
        }

        // Finally, remove the cert.
        let r = ks.remove_all(&alice.fingerprint());
        assert!(r);

        ks_count(&ks, 0, 0);

        Ok(())
    }
}
