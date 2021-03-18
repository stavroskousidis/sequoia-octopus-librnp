use std::{
    collections::{
        HashMap,
        hash_map::Entry,
    },
    cell::{
        RefCell,
        Ref,
        RefMut,
    },
    fmt,
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

struct MapEntry<E> {
    cert: Rc<RefCell<Cert>>,
    extra: E,
}

impl<E> MapEntry<E> {
    fn cert(&self) -> Ref<Cert> {
        self.cert.borrow()
    }

    fn cert_mut(&self) -> RefMut<Cert> {
        self.cert.borrow_mut()
    }

    fn extra(&self) -> &E {
        &self.extra
    }
}

impl MapEntry<()> {
    fn new(cert: &Rc<RefCell<Cert>>) -> Self {
        MapEntry {
            cert: Rc::clone(cert),
            extra: (),
        }
    }
}

impl MapEntry<Fingerprint> {
    fn new2(cert: &Rc<RefCell<Cert>>, referent: Fingerprint) -> Self {
        MapEntry {
            cert: Rc::clone(cert),
            extra: referent,
        }
    }
}

#[derive(Default)]
pub struct Keystore {
    // The bool indicates whether the key is considered external.
    by_primary_fp: HashMap<Fingerprint, MapEntry<bool>>,
    by_primary_id: HashMap<KeyID, Vec<MapEntry<()>>>,
    by_primary_grip: HashMap<Keygrip, Vec<MapEntry<()>>>,
    by_subkey_fp: HashMap<Fingerprint, Vec<MapEntry<()>>>,
    by_subkey_id: HashMap<KeyID, Vec<MapEntry<()>>>,
    // It is possible for there to be a certificate that has multiple
    // subkeys with the same grip!  If we remove one subkey, then the
    // grip should not be removed.  To distinguish this case, we also
    // track the subkey.
    by_subkey_grip: HashMap<Keygrip, Vec<MapEntry<Fingerprint>>>,
}

const VEC_MAP_ENTRY_EMPTY: Vec<MapEntry<()>> = Vec::new();
const VEC_MAP_ENTRY_EMPTY_REF: &Vec<MapEntry<()>> = &VEC_MAP_ENTRY_EMPTY;

const VEC_MAP_ENTRY_FPR_EMPTY: Vec<MapEntry<Fingerprint>> = Vec::new();
const VEC_MAP_ENTRY_FPR_EMPTY_REF: &Vec<MapEntry<Fingerprint>>
    = &VEC_MAP_ENTRY_FPR_EMPTY;

impl fmt::Debug for Keystore {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "Keystore {{")?;

        writeln!(f, "  by_primary_fp {{")?;
        for (k, e) in self.by_primary_fp.iter() {
            writeln!(f, "    {} => {}", k, e.extra())?;
        }
        writeln!(f, "  }}")?;
        writeln!(f, "  by_primary_id {{")?;
        for (k, v) in self.by_primary_id.iter() {
            writeln!(f, "    {} =>\n      {}",
                     k,
                     v.iter()
                        .map(|e| e.cert().fingerprint().to_string())
                        .collect::<Vec<String>>().join(",\n      "))?;
        }
        writeln!(f, "  }}")?;
        writeln!(f, "  by_primary_grip {{")?;
        for (g, v) in self.by_primary_grip.iter() {
            writeln!(f, "    {} =>\n      {}",
                     g,
                     v.iter()
                        .map(|e| {
                            format!("{}",
                                    e.cert().fingerprint().to_string())
                        })
                        .collect::<Vec<String>>().join(",\n      "))?;
        }
        writeln!(f, "  }}")?;

        writeln!(f, "  by_subkey_fp {{")?;
        for (k, v) in self.by_subkey_fp.iter() {
            writeln!(f, "    {} =>\n      {}",
                     k,
                     v.iter()
                        .map(|e| e.cert().fingerprint().to_string())
                        .collect::<Vec<String>>().join(",\n      "))?;
        }
        writeln!(f, "  }}")?;
        writeln!(f, "  by_subkey_id {{")?;
        for (k, v) in self.by_subkey_id.iter() {
            writeln!(f, "    {} =>\n      {}",
                     k,
                     v.iter()
                        .map(|e| e.cert().fingerprint().to_string())
                        .collect::<Vec<String>>().join(",\n      "))?;
        }
        writeln!(f, "  }}")?;
        writeln!(f, "  by_subkey_grip {{")?;
        for (g, v) in self.by_subkey_grip.iter() {
            writeln!(f, "    {} =>\n      {}",
                     g,
                     v.iter()
                        .map(|e| {
                            format!("{} (via {})",
                                    e.cert().fingerprint().to_string(),
                                    e.extra)
                        })
                        .collect::<Vec<String>>().join(",\n      "))?;
        }
        writeln!(f, "  }}")?;

        writeln!(f, "}}")?;
        Ok(())
    }
}

impl Keystore {
    /// Returns a reference to the cert with the given fingerprint, if
    /// any.
    pub fn by_primary_fp(&self, fp: &Fingerprint) -> Option<Ref<Cert>> {
        self.by_primary_fp.get(fp).map(|e| e.cert())
    }

    /// Returns a mutable reference to the cert with the given
    /// fingerprint, if any.
    ///
    /// A stern warning: Do not use the mutable reference to remove
    /// subkeys.  Use Keystore::remove_all for that.
    pub fn by_primary_fp_mut(&self, fp: &Fingerprint) -> Option<RefMut<Cert>> {
        self.by_primary_fp.get(fp).map(|e| e.cert_mut())
    }

    /// Returns a reference to each cert with the given keyid.
    pub fn by_primary_id(&self, id: &KeyID) -> impl Iterator<Item=Ref<Cert>> {
        self.by_primary_id.get(id)
            .unwrap_or(VEC_MAP_ENTRY_EMPTY_REF)
            .iter()
            .map(|e| e.cert())
    }

    /// Returns a reference to each cert for which the primary key has
    /// the given keygrip.
    pub fn by_primary_grip(&self, grip: &Keygrip) -> impl Iterator<Item=Ref<Cert>> {
        self.by_primary_grip.get(grip)
            .unwrap_or(VEC_MAP_ENTRY_EMPTY_REF)
            .iter()
            .map(|e| e.cert())
    }

    /// Returns a reference to each cert containing a subkey with the
    /// given fingerprint.
    pub fn by_subkey_fp(&self, fp: &Fingerprint) -> impl Iterator<Item=Ref<Cert>> {
        self.by_subkey_fp.get(fp)
            .unwrap_or(VEC_MAP_ENTRY_EMPTY_REF)
            .iter()
            .map(|e| e.cert())
    }

    /// Returns a mutable reference to each cert containing a subkey
    /// with the given fingerprint, if any.
    ///
    /// A stern warning: Do not use the mutable reference to remove
    /// subkeys.  Use Keystore::remove_all for that.
    pub fn by_subkey_fp_mut(&self, fp: &Fingerprint)
        -> impl Iterator<Item=RefMut<Cert>>
    {
        self.by_subkey_fp.get(fp)
            .unwrap_or(VEC_MAP_ENTRY_EMPTY_REF)
            .iter()
            .map(|e| e.cert_mut())
    }

    /// Returns a reference to each cert containing a subkey with the
    /// given keyid, if any.
    pub fn by_subkey_id(&self, id: &KeyID) -> impl Iterator<Item=Ref<Cert>> {
        self.by_subkey_id.get(id)
            .unwrap_or(VEC_MAP_ENTRY_EMPTY_REF)
            .iter()
            .map(|e| e.cert())
    }

    /// Returns a reference to each cert containing a subkey with the
    /// given keygrip, if any.
    ///
    /// If a certificate contains multiple subkeys with the same
    /// keygrip, then the certificate is returned multiple times, one
    /// for each such subkey.
    pub fn by_subkey_grip(&self, grip: &Keygrip) -> impl Iterator<Item=Ref<Cert>> {
        self.by_subkey_grip.get(grip)
            .unwrap_or(VEC_MAP_ENTRY_FPR_EMPTY_REF)
            .iter()
            .map(|e| e.cert())
    }

    /// Returns an iterator over all the certs in the key store.
    pub fn iter(&self) -> impl Iterator<Item = Ref<Cert>> {
        self.by_primary_fp.values().map(|e| e.cert())
    }

    /// Returns an iterator over the certs in the key store, which are
    /// not marked as external.
    pub fn to_save(&self) -> impl Iterator<Item = Ref<Cert>> {
        self.by_primary_fp.values().filter_map(|e| {
            if *e.extra() {
                None
            } else {
                Some(e.cert())
            }
        })
    }

    /// Returns the number of certs in the keyring.
    pub fn len(&self) -> usize {
        self.by_primary_fp.len()
    }

    /// Inserts a cert.
    fn insert_(&mut self, cert: Cert, is_external: bool) {
        rnp_function!(Keystore::insert_, super::TRACE);

        let fp = cert.fingerprint();
        let id = KeyID::from(&fp);
        let grip = Keygrip::of(cert.primary_key().mpis()).ok();

        t!("Inserting {}, {:?} (external: {})",
           fp, cert.userids().nth(0).map(|ua| ua.userid()), is_external);

        let cert_slot: Rc<RefCell<Cert>>;

        let is_update = match self.by_primary_fp.entry(fp.clone()) {
            Entry::Occupied(mut oe) => {
                t!("Already exists in keystore, merging.");

                let e = oe.get_mut();
                cert_slot = Rc::clone(&e.cert);

                let new = cert_slot.borrow().clone().merge_public(cert)
                    .expect("does not fail if the primary keys are equal");
                e.cert.replace(new);

                e.extra = e.extra && is_external;

                true
            }
            Entry::Vacant(ve) => {
                t!("New certificate, adding.");

                cert_slot = Rc::new(RefCell::new(cert));
                ve.insert(MapEntry {
                    cert: Rc::clone(&cert_slot),
                    extra: is_external,
                });

                false
            }
        };

        // If this is an update, then the primary key id and primary
        // key grip mapping exist and are correct.
        if ! is_update {
            self.by_primary_id
                .entry(id)
                .and_modify(|v| v.push(MapEntry::new(&cert_slot)))
                .or_insert(vec![ MapEntry::new(&cert_slot) ]);

            if let Some(g) = grip {
                self.by_primary_grip
                    .entry(g)
                    .and_modify(|v| v.push(MapEntry::new(&cert_slot)))
                    .or_insert(vec![ MapEntry::new(&cert_slot) ]);
            }
        }

        // Add subkey indices.  If this is an update, indices may
        // already exist.  Don't duplicate them.
        for sk in cert_slot.borrow().keys().subkeys() {
            macro_rules! add {
                ($v:expr, $id:expr) => ({
                    let present = $v.iter()
                        .position(|e| {
                            e.extra == $id
                                && e.cert().fingerprint() == fp
                        })
                        .is_some();
                    if present {
                        t!("Sub-x mapping already present");
                    } else {
                        t!("Sub-x mapping not yet present");
                    }

                    if is_update && ! present {
                        $v.push(MapEntry {
                            cert: Rc::clone(&cert_slot),
                            extra: $id,
                        });
                    } else if ! is_update {
                        assert!(! present);
                        $v.push(MapEntry {
                            cert: Rc::clone(&cert_slot),
                            extra: $id,
                        });
                    }
                });
            }

            t!("Adding subkey fingerprint mapping for {}", sk.fingerprint());
            self.by_subkey_fp.entry(sk.fingerprint())
                .and_modify(|v| add!(v, ()))
                .or_insert(vec![ MapEntry::new(&cert_slot) ]);

            t!("Adding subkey keyid mapping for {}", sk.keyid());
            self.by_subkey_id.entry(sk.keyid())
                .and_modify(|v| add!(v, ()))
                .or_insert(vec![ MapEntry::new(&cert_slot) ]);

            if let Ok(g) = Keygrip::of(sk.mpis()) {
                t!("Adding subkey keygrip mapping for {}", g);
                self.by_subkey_grip.entry(g)
                    .and_modify(|v| add!(v, sk.fingerprint()))
                    .or_insert(vec![ MapEntry::new2(&cert_slot, sk.fingerprint()) ]);
            }
        }

        t!("Done.");
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

        macro_rules! remove {
            ($fp:expr, $e:expr) => ({
                let fp: &Fingerprint = $fp;
                let e: Entry<_, Vec<MapEntry<_>>> = $e;

                match e {
                    Entry::Occupied(mut oe) => {
                        if let Some(i) = oe.get_mut()
                            .iter().position(|e| &e.cert().fingerprint() == fp)
                        {
                            if oe.get().len() == 1 {
                                assert_eq!(i, 0);
                                oe.remove_entry();
                            } else {
                                oe.get_mut().remove(i);
                            }
                        } else {
                            unreachable!("entry not present");
                        }
                    }
                    Entry::Vacant(_) => unreachable!("entry not present"),
                }
            });
        }

        // First, remove the cert with that fingerprint.
        if let Some(e) = self.by_primary_fp.remove(fp) {
            removed_one = true;

            // Remove other primary key indices.
            remove!(fp, self.by_primary_id.entry(KeyID::from(fp)));
            if let Ok(g) = Keygrip::of(e.cert().primary_key().mpis()) {
                remove!(fp, self.by_primary_grip.entry(g));
            }

            // And remove any subkey indices.
            for sk in e.cert().keys().subkeys() {
                remove!(fp, self.by_subkey_fp.entry(sk.fingerprint()));
                remove!(fp, self.by_subkey_id.entry(sk.keyid()));
                if let Ok(g) = Keygrip::of(sk.mpis()) {
                    remove!(fp, self.by_subkey_grip.entry(g));
                }
            }
        }

        // Remove all subkeys with that fingerprint.
        if let Some(subkeys) = self.by_subkey_fp.remove(fp) {
            for e in subkeys.into_iter() {
                let cert = e.cert().clone();
                let cert_fp = cert.fingerprint();

                // Strip the subkey.
                let mut had_one = false;
                e.cert.replace(cert.retain_subkeys(|ska| {
                    if ska.fingerprint() == *fp {
                        had_one = true;
                        removed_one = true;

                        remove!(&cert_fp, self.by_subkey_id.entry(ska.keyid()));
                        if let Ok(g) = Keygrip::of(ska.mpis()) {
                            remove!(&cert_fp, self.by_subkey_grip.entry(g));
                        }

                        false
                    } else {
                        true
                    }
                }));

                assert!(had_one);
            }
        }

        removed_one
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use anyhow::Context;

    use openpgp::cert::prelude::*;
    use openpgp::policy::StandardPolicy;
    use openpgp::types::SignatureType;
    use openpgp::packet::signature::subpacket::SubpacketTag;
    use openpgp::packet::prelude::*;

    // Makes sure the maps contain the specified number of keys.
    //
    // If a subkey appears on multiple certificates, it is only
    // counted once.
    fn ks_count<P, S>(ks: &Keystore, n_pks: P, n_sks: S, ignore_grips: bool)
        where P: Into<Option<usize>>, S: Into<Option<usize>>
    {
        if let Some(n_pks) = n_pks.into() {
            assert_eq!(ks.by_primary_fp.len(), n_pks,
                       "Expected {} primary fps, got {}\n{:?}",
                       n_pks, ks.by_primary_fp.len(), ks);
            assert_eq!(ks.by_primary_id.len(), n_pks,
                       "Expected {} primary key ids, got {}\n{:?}",
                       n_pks, ks.by_primary_id.len(), ks);
            if ! ignore_grips {
                assert_eq!(ks.by_primary_grip.len(), n_pks,
                           "Expected {} primary grips, got {}\n{:?}",
                           n_pks, ks.by_primary_grip.len(), ks);
            }
        }

        if let Some(n_sks) = n_sks.into() {
            assert_eq!(ks.by_subkey_fp.len(), n_sks,
                       "Expected {} subkey fps, got {}\n{:?}",
                       n_sks, ks.by_subkey_fp.len(), ks);
            assert_eq!(ks.by_subkey_id.len(), n_sks,
                       "Expected {} subkey key ids, got {}\n{:?}",
                       n_sks, ks.by_subkey_id.len(), ks);
            if ! ignore_grips {
                assert_eq!(ks.by_subkey_grip.len(), n_sks,
                           "Expected {} subkey grips, got {}\n{:?}",
                           n_sks, ks.by_subkey_grip.len(), ks);
            }
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
                    panic!("{} found in by_primary_fp, expected nothing\n{:?}",
                           fpr, ks),
                None if ! *as_primary => (),
                None =>
                    panic!("{} not found in by_primary_fp, but expected\n{:?}",
                           fpr, ks),
            }

            if ks.by_subkey_fp(&fpr)
                .any(|c| c.keys().any(|ka| ka.fingerprint() == fpr))
            {
                if ! *as_sub {
                    panic!("{} found in by_subkey_fp, expected nothing\n{:?}",
                           fpr, ks);
                }
            } else {
                if *as_sub {
                    panic!("{} not found in by_subkey_fp, but expected\n{:?}",
                           fpr, ks);
                }
            }

            // By keyid.
            let keyid = ka.keyid();
            if ks.by_primary_id(&keyid).any(|c| c.fingerprint() == fpr)
            {
                if ! *as_primary {
                    panic!("{} found in by_primary_id, expected nothing\n{:?}",
                           fpr, ks);
                }
            } else {
                if *as_primary {
                    panic!("{} not found in by_primary_id, but expected\n{:?}",
                           fpr, ks);
                }
            }

            if ks.by_subkey_id(&keyid)
                .any(|c| c.keys().any(|ka| ka.keyid() == keyid))
            {
                if ! *as_sub {
                    panic!("{} found in by_subkey_id, expected nothing\n{:?}",
                           fpr, ks);
                }
            } else {
                if *as_sub {
                    panic!("{} not found in by_subkey_id, but expected\n{:?}",
                           fpr, ks);
                }
            }

            // By grip.
            if let Ok(grip) = Keygrip::of(ka.mpis()) {
                if ks.by_primary_grip(&grip).any(|c| c.fingerprint() == fpr)
                {
                    if ! *as_primary {
                        panic!("Found {} in by_primary_grip, expected nothing\n{:?}",
                               fpr, ks);
                    }
                } else {
                    if *as_primary {
                        panic!("{} not found in by_primary_grip, but expected\n{:?}",
                               fpr, ks);
                    }
                }

                if ks.by_subkey_grip(&grip)
                    .any(|c| c.keys().any(|ka| ka.keyid() == keyid))
                {
                    if ! *as_sub {
                        panic!("Found {} in by_subkey_grip, expected nothing\n{:?}",
                               fpr, ks);
                    }
                } else {
                    if *as_sub {
                        panic!("{} not found in by_subkey_grip, but expected\n{:?}",
                               fpr, ks);
                    }
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
            ks.by_primary_fp.values()
                .map(|e| {
                    ("by_primary_fp", e.cert())
                })
                .chain(ks.by_primary_id.values().flat_map(|v| {
                    v.iter().map(|e| ("by_primary_id", e.cert()))
                }))
                .chain(ks.by_primary_grip.values().flat_map(|v| {
                    v.iter().map(|e| ("by_primary_grip", e.cert()))
                }))
                .chain(ks.by_subkey_fp.values().flat_map(|v| {
                    v.iter().map(|e| ("by_subkey_fp", e.cert()))
                }))
                .chain(ks.by_subkey_id.values().flat_map(|v| {
                    v.iter().map(|e| ("by_subkey_id", e.cert()))
                }))
                .chain(ks.by_subkey_grip.values().flat_map(|v| {
                    v.iter().map(|e| ("by_subkey_grip", e.cert()))
                }))
        {
            for k in cert.keys() {
                assert!(k.fingerprint() != ka.fingerprint(),
                        "{}: {} still exists in {}, {:?}\n{:?}",
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
                            .unwrap_or("<Invalid>".into()),
                        ks);
            }
        }
    }

    // Have cert adopt the specified key.  Uses template to create the
    // self signature.
    fn adopt(cert: Cert,
             key: Key<key::SecretParts, key::SubordinateRole>,
             template: &Signature)
             -> openpgp::Result<Cert>
    {
        let mut builder: SignatureBuilder = match template.typ() {
            SignatureType::SubkeyBinding =>
                template.clone().into(),
            SignatureType::DirectKey
                | SignatureType::PositiveCertification
                | SignatureType::CasualCertification
                | SignatureType::PersonaCertification
                | SignatureType::GenericCertification =>
            {
                // Convert to a binding
                // signature.
                let kf = template.key_flags()
                    .context("Missing required \
                              subpacket, KeyFlags")?;
                SignatureBuilder::new(
                    SignatureType::SubkeyBinding)
                    .set_key_flags(kf)?
            },
            _ => panic!("Unsupported binding \
                         signature: {:?}",
                        template),
        };

        // Get a signer.
        let pk = cert.primary_key().key();
        let mut pk_signer = pk.clone().parts_into_secret()?.into_keypair()?;


        // Add the keys and signatues to cert.
        let mut packets: Vec<Packet> = vec![];

        // If there is a valid backsig, recreate it.
        let need_backsig = builder.key_flags()
            .map(|kf| kf.for_signing() || kf.for_certification())
            .expect("Missing keyflags");

        if need_backsig {
            // Derive a signer.
            let mut subkey_signer
                = key.clone().parts_into_secret()?.into_keypair()?;

            let backsig = builder.embedded_signatures()
                .filter(|backsig| {
                    (*backsig).clone().verify_primary_key_binding(
                        &cert.primary_key(),
                        &key).is_ok()
                })
                .nth(0)
                .map(|sig| SignatureBuilder::from(sig.clone()))
                .unwrap_or_else(|| {
                    SignatureBuilder::new(SignatureType::PrimaryKeyBinding)
                })
                .sign_primary_key_binding(&mut subkey_signer, pk, &key)?;

            builder = builder.set_embedded_signature(backsig)?;
        } else {
            builder = builder.modify_hashed_area(|mut a| {
                a.remove_all(SubpacketTag::EmbeddedSignature);
                Ok(a)
            })?;
        }

        let mut sig = builder.sign_subkey_binding(&mut pk_signer, pk, &key)?;

        // Verify it.
        if let Err(err) = sig.verify_subkey_binding(pk_signer.public(), pk, &key) {
            panic!("invalid signature: {}", err);
        }

        packets.push(key.clone().into());
        packets.push(sig.into());

        let cert = cert.clone().insert_packets(packets.clone())?;

        Ok(cert)
    }

    #[test]
    fn insert_remove() -> openpgp::Result<()> {
        let mut ks = Keystore::default();
        ks_count(&ks, 0, 0, false);

        // Generate a key and insert it.
        let (alice, revocation) = openpgp::cert::CertBuilder::general_purpose(
            None, Some("alice")).generate()?;
        ks.insert(alice.clone());

        let n_subkeys = alice.keys().subkeys().count();
        ks_count(&ks, 1, n_subkeys, false);
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
        let removed_sk: ErasedKeyAmalgamation<key::PublicParts>
            = alice.keys().subkeys().nth(0).unwrap().into();
        let fp = removed_sk.fingerprint();
        let r = ks.remove_all(&fp);
        assert!(r);

        ks_is_missing(&ks, &removed_sk);

        // Remove the subkey from our copy of Alice's cert, and redo
        // all the lookups.
        let alice = alice.retain_subkeys(|sk| sk.fingerprint() != fp);
        let n_subkeys = alice.keys().subkeys().count();
        ks_count(&ks, 1, n_subkeys, false);
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
            ks.by_primary_id(&id).nth(0).unwrap().revocation_status(p, None),
            RevocationStatus::Revoked(_)));
        assert!(matches!(
            ks.by_primary_grip(&grip).nth(0).unwrap().revocation_status(p, None),
            RevocationStatus::Revoked(_)));
        ks_contains(&ks, &[
            (&alice.primary_key().into(), true, false)
        ]);

        for sk in alice.keys().subkeys() {
            let fp = sk.fingerprint();
            let id = KeyID::from(&fp);
            let grip = Keygrip::of(sk.mpis())?;

            assert!(ks.by_primary_fp(&fp).is_none());
            assert_eq!(ks.by_primary_id(&id).count(), 0);
            assert_eq!(ks.by_primary_grip(&grip).count(), 0);
            assert!(matches!(
                ks.by_subkey_fp(&fp).nth(0).unwrap().revocation_status(p, None),
                RevocationStatus::Revoked(_)));
            assert!(matches!(
                ks.by_subkey_id(&id).nth(0).unwrap().revocation_status(p, None),
                RevocationStatus::Revoked(_)));
            assert!(matches!(
                ks.by_subkey_grip(&grip).nth(0).unwrap().revocation_status(p, None),
                RevocationStatus::Revoked(_)));

            ks_contains(&ks, &[
                (&sk.into(), false, true)
            ]);
        }

        // Finally, remove the cert.
        let r = ks.remove_all(&alice.fingerprint());
        assert!(r);

        ks_count(&ks, 0, 0, false);

        Ok(())
    }

    // Given a certificate with multiple subkeys, add the subkeys one
    // at a time.
    #[test]
    fn add() -> openpgp::Result<()> {
        let mut ks = Keystore::default();
        ks_count(&ks, 0, 0, false);

        // Generate a key and insert it.
        let (alice, _) = openpgp::cert::CertBuilder::new()
            .add_userid("alice")
            .add_signing_subkey()
            .add_signing_subkey()
            .add_signing_subkey()
            .add_signing_subkey()
            .add_signing_subkey()
            .add_signing_subkey()
            .add_signing_subkey()
            .generate()?;

        for _ in 0..2 {
            let mut added: Vec<Fingerprint> = Vec::new();
            for i in 0..alice.keys().subkeys().count() {
                let subset = alice.clone().retain_subkeys(|sk| {
                    if added.iter().any(|fpr| fpr == &sk.fingerprint()) {
                        // Already present.  Ignore it.
                        false
                    } else if added.len() < i {
                        // Add it.
                        added.push(sk.fingerprint());
                        true
                    } else {
                        // We have enough.
                        false
                    }
                });

                // We should have just one subkey.
                if i > 0 {
                    assert!(subset.keys().subkeys().count() == 1);
                } else {
                    assert!(subset.keys().subkeys().count() == 0);
                }

                // Add it.
                ks.insert(subset.clone());

                // Make sure it was merged correctly.
                ks_count(&ks, 1, i, false);

                ks_contains(&ks, &[(&alice.primary_key().into(), true, false)]);
                for sk in alice.keys().subkeys() {
                    if added.iter().any(|fpr| fpr == &sk.fingerprint()) {
                        // Should have been added.
                        ks_contains(&ks, &[(&sk.into(), false, true)]);
                    } else {
                        // Hasn't been added yet.
                        ks_contains(&ks, &[(&sk.into(), false, false)]);
                    }
                }
            }

            // Finally, remove the cert.
            let r = ks.remove_all(&alice.fingerprint());
            assert!(r);

            ks_count(&ks, 0, 0, false);
        }

        Ok(())
    }

    // Two certificates with the same subkey.
    #[test]
    fn same_subkey() -> openpgp::Result<()> {
        let p = &openpgp::policy::StandardPolicy::new();

        let mut ks = Keystore::default();
        ks_count(&ks, 0, 0, false);
        ks_contains(&ks, &[]);

        // Generate the keys.
        let (alice, _) = openpgp::cert::CertBuilder::general_purpose(
            None, Some("alice")).generate()?;

        let (bob, _) = openpgp::cert::CertBuilder::new()
            .add_userid("bob")
            .add_signing_subkey()
            .generate()?;

        let alice_pk = alice.primary_key().into();
        let alice_enc = alice.with_policy(p, None)?
            .keys().subkeys().for_transport_encryption().nth(0)
            .expect("encryption-capable subkey");
        let alice_signing = alice.with_policy(p, None)?
            .keys().subkeys().for_signing().nth(0)
            .expect("signing-capable subkey")
            .into_key_amalgamation()
            .into();

        // Add Alice's encryption capable subkey to Bob's certificate.
        let key = alice_enc.key().clone();
        let bob = adopt(bob,
                        key.clone()
                            .parts_into_secret()
                            .expect("secret key material"),
                        alice_enc.binding_signature())?;
        let common: ErasedKeyAmalgamation<key::PublicParts>
            = alice_enc.into_key_amalgamation().into();

        let bob_pk = bob.primary_key().into();
        let bob_enc: ErasedKeyAmalgamation<key::PublicParts>
            = bob.with_policy(p, None)?
            .keys().subkeys().for_transport_encryption().nth(0)
            .expect("encryption-capable subkey")
            .into_key_amalgamation()
            .into();
        assert_eq!(common.fingerprint(), bob_enc.fingerprint());
        let bob_signing = bob.with_policy(p, None)?
            .keys().subkeys().for_signing().nth(0)
            .expect("encryption-capable subkey")
            .into_key_amalgamation()
            .into();

        ks.insert(alice.clone());
        assert_eq!(ks.by_subkey_fp(&common.fingerprint()).count(), 1);
        ks.insert(bob.clone());
        assert_eq!(ks.by_subkey_fp(&common.fingerprint()).count(), 2);

        // We have 3 subkeys, not 4.
        ks_count(&ks, 2, 3, false);
        // The common subkey appears twice.
        assert_eq!(ks.by_subkey_fp(&common.fingerprint()).count(), 2);
        ks_contains(&ks, &[
            (&alice_pk, true, false),
            (&alice_signing, false, true),
            (&bob_pk, true, false),
            (&bob_signing, false, true),
            (&common, false, true),
        ]);

        // Remove Bob's signing subkey.
        let r = ks.remove_all(&bob_signing.fingerprint());
        assert!(r);

        ks_count(&ks, 2, 2, false);
        assert_eq!(ks.by_subkey_fp(&common.fingerprint()).count(), 2);
        ks_contains(&ks, &[
            (&alice_pk, true, false),
            (&alice_signing, false, true),
            (&bob_pk, true, false),
            (&bob_signing, false, false),
            (&common, false, true),
        ]);

        let r = ks.remove_all(&common.fingerprint());
        assert!(r);

        ks_count(&ks, 2, 1, false);
        assert_eq!(ks.by_subkey_fp(&common.fingerprint()).count(), 0);
        ks_contains(&ks, &[
            (&alice_pk, true, false),
            (&alice_signing, false, true),
            (&bob_pk, true, false),
            (&bob_signing, false, false),
            (&common, false, false),
        ]);

        assert!(! ks.by_primary_fp(&alice.fingerprint()).unwrap()
            .keys().any(|ka| ka.fingerprint() == common.fingerprint()));
        assert!(! ks.by_primary_fp(&bob.fingerprint()).unwrap()
            .keys().any(|ka| ka.fingerprint() == common.fingerprint()));

        // Finally, remove the cert.
        let r = ks.remove_all(&alice.fingerprint());
        assert!(r);

        ks_is_missing(&ks, &common);

        let r = ks.remove_all(&bob.fingerprint());
        assert!(r);

        ks_count(&ks, 0, 0, false);


        // Add alice and bob.  Remove bob.  Make sure everything is
        // still sane.

        ks.insert(alice.clone());
        assert_eq!(ks.by_subkey_fp(&common.fingerprint()).count(), 1);
        ks.insert(bob.clone());
        assert_eq!(ks.by_subkey_fp(&common.fingerprint()).count(), 2);

        // We have 3 subkeys, not 4.
        ks_count(&ks, 2, 3, false);
        // The common subkey appears twice.
        assert_eq!(ks.by_subkey_fp(&common.fingerprint()).count(), 2);
        ks_contains(&ks, &[
            (&alice_pk, true, false),
            (&alice_signing, false, true),
            (&bob_pk, true, false),
            (&bob_signing, false, true),
            (&common, false, true),
        ]);

        eprintln!("{:?}", ks);

        // Remove Bob's key.
        let r = ks.remove_all(&bob.fingerprint());
        assert!(r);

        ks_count(&ks, 1, 2, false);
        assert_eq!(ks.by_subkey_fp(&common.fingerprint()).count(), 1);
        ks_contains(&ks, &[
            (&alice_pk, true, false),
            (&alice_signing, false, true),
            (&bob_pk, false, false),
            (&bob_signing, false, false),
            (&common, false, true),
        ]);

        Ok(())
    }

    // The same MPIs appear on two certificates (but the keys are
    // different!).
    #[test]
    fn same_grip() -> openpgp::Result<()> {
        let p = &openpgp::policy::StandardPolicy::new();

        let mut ks = Keystore::default();
        ks_count(&ks, 0, 0, false);
        ks_contains(&ks, &[]);

        // Generate the keys.
        let t = std::time::SystemTime::now() - std::time::Duration::new(10, 0);
        let (alice, _) = openpgp::cert::CertBuilder::general_purpose(
            None, Some("alice"))
            .set_creation_time(t)
            .generate()?;

        let (bob, _) = openpgp::cert::CertBuilder::new()
            .add_userid("bob")
            .add_signing_subkey()
            .set_creation_time(t)
            .generate()?;

        let alice_pk = alice.primary_key().into();
        let alice_enc = alice.with_policy(p, None)?
            .keys().subkeys().for_transport_encryption().nth(0)
            .expect("encryption-capable subkey");
        let alice_signing = alice.with_policy(p, None)?
            .keys().subkeys().for_signing().nth(0)
            .expect("signing-capable subkey")
            .into_key_amalgamation()
            .into();

        // Add the encryption subkey to Bob's key.  Change the
        // creation time so that it has the same grip, but a different
        // fingerprint.
        let mut key = alice_enc.key().clone();
        let ct = key.creation_time() + std::time::Duration::new(1, 0);
        key.set_creation_time(ct)?;

        let bob = adopt(bob,
                        key.clone()
                            .parts_into_secret()
                            .expect("secret key material"),
                        alice_enc.binding_signature())?;
        let alice_enc: ErasedKeyAmalgamation<key::PublicParts>
            = alice_enc.into_key_amalgamation().into();

        let bob_pk = bob.primary_key().into();
        let bob_enc: ErasedKeyAmalgamation<key::PublicParts>
            = bob.with_policy(p, None)?
            .keys().subkeys().for_transport_encryption().nth(0)
            .expect("encryption-capable subkey")
            .into_key_amalgamation()
            .into();
        let bob_signing = bob.with_policy(p, None)?
            .keys().subkeys().for_signing().nth(0)
            .expect("encryption-capable subkey")
            .into_key_amalgamation()
            .into();

        let common_grip = Keygrip::of(alice_enc.mpis()).unwrap();
        assert_eq!(common_grip,
                   Keygrip::of(bob_enc.mpis()).unwrap());

        ks.insert(alice.clone());
        assert_eq!(ks.by_subkey_grip(&common_grip).count(), 1);
        ks.insert(bob.clone());
        assert_eq!(ks.by_subkey_grip(&common_grip).count(), 2);

        // We have 4 subkeys: the two subkeys with the same grip have
        // different fingerprints.
        ks_count(&ks, 2, 4, true);
        // The common grip appears twice.
        assert_eq!(ks.by_subkey_grip(&common_grip).count(), 2);
        ks_contains(&ks, &[
            (&alice_pk, true, false),
            (&alice_signing, false, true),
            (&alice_enc, false, true),
            (&bob_pk, true, false),
            (&bob_signing, false, true),
            (&bob_enc, false, true),
        ]);

        // Remove Bob's encryption subkey, which is the one with the
        // shared grip.
        let r = ks.remove_all(&bob_enc.fingerprint());
        assert!(r);

        ks_count(&ks, 2, 3, true);
        assert_eq!(ks.by_subkey_grip(&common_grip).count(), 1);
        ks_contains(&ks, &[
            (&alice_pk, true, false),
            (&alice_signing, false, true),
            (&alice_enc, false, true),
            (&bob_pk, true, false),
            (&bob_signing, false, true),
            (&bob_enc, false, false),
        ]);

        let r = ks.remove_all(&alice_enc.fingerprint());
        assert!(r);

        ks_count(&ks, 2, 2, true);
        assert_eq!(ks.by_subkey_grip(&common_grip).count(), 0);
        ks_contains(&ks, &[
            (&alice_pk, true, false),
            (&alice_signing, false, true),
            (&alice_enc, false, false),
            (&bob_pk, true, false),
            (&bob_signing, false, true),
            (&bob_enc, false, false),
        ]);

        assert!(! ks.by_primary_fp(&alice.fingerprint()).unwrap()
            .keys().any(|ka| Keygrip::of(ka.mpis()).unwrap() == common_grip));
        assert!(! ks.by_primary_fp(&bob.fingerprint()).unwrap()
            .keys().any(|ka| Keygrip::of(ka.mpis()).unwrap() == common_grip));

        // Finally, remove the cert.
        let r = ks.remove_all(&alice.fingerprint());
        assert!(r);

        let r = ks.remove_all(&bob.fingerprint());
        assert!(r);

        ks_count(&ks, 0, 0, false);


        // Add alice and bob.  Remove bob.  Make sure everything is
        // still sane.

        ks.insert(alice.clone());
        assert_eq!(ks.by_subkey_grip(&common_grip).count(), 1);
        ks.insert(bob.clone());
        assert_eq!(ks.by_subkey_grip(&common_grip).count(), 2);

        // We have 4 subkeys.
        ks_count(&ks, 2, 4, true);
        // The common grip appears twice.
        assert_eq!(ks.by_subkey_grip(&common_grip).count(), 2);
        ks_contains(&ks, &[
            (&alice_pk, true, false),
            (&alice_signing, false, true),
            (&alice_enc, false, true),
            (&bob_pk, true, false),
            (&bob_signing, false, true),
            (&bob_enc, false, true),
        ]);

        eprintln!("{:?}", ks);

        // Remove Bob's key.
        let r = ks.remove_all(&bob.fingerprint());
        assert!(r);

        ks_count(&ks, 1, 2, false);
        assert_eq!(ks.by_subkey_grip(&common_grip).count(), 1);
        ks_contains(&ks, &[
            (&alice_pk, true, false),
            (&alice_signing, false, true),
            (&alice_enc, false, true),
            (&bob_pk, false, false),
            (&bob_signing, false, false),
            (&bob_enc, false, false),
        ]);

        Ok(())
    }

    // The same MPIs appear on same certificate as two different
    // subkeys.
    #[test]
    fn same_grip_same_cert() -> openpgp::Result<()> {
        let p = &openpgp::policy::StandardPolicy::new();

        let mut ks = Keystore::default();
        ks_count(&ks, 0, 0, false);
        ks_contains(&ks, &[]);

        // Generate the keys.
        let t = std::time::SystemTime::now() - std::time::Duration::new(10, 0);
        let (alice, _) = openpgp::cert::CertBuilder::new()
            .add_userid("alice")
            .add_signing_subkey()
            .set_creation_time(t)
            .generate()?;

        let alice_pk = alice.primary_key().into();
        let alice_signing = alice.with_policy(p, None)?
            .keys().subkeys().for_signing().nth(0)
            .expect("signing-capable subkey");

        ks.insert(alice.clone());

        // We have 1 key with 1 subkey.
        ks_count(&ks, 1, 1, false);
        ks_contains(&ks, &[
            (&alice_pk, true, false),
            (&alice_signing.clone().into_key_amalgamation().into(), false, true),
        ]);

        // Create a second subkey with the same grip.
        let mut key = alice_signing.key().clone();
        let ct = key.creation_time() + std::time::Duration::new(1, 0);
        key.set_creation_time(ct)?;
        let template = alice_signing.binding_signature().clone();

        let alice = adopt(alice,
                          key.clone()
                              .parts_into_secret()
                              .expect("secret key material"),
                          &template)?;
        let alice_pk = alice.primary_key().into();
        let alice_signing: ErasedKeyAmalgamation<key::PublicParts>
            = alice.keys().subkeys().nth(0).unwrap().into();
        let alice_signing2: ErasedKeyAmalgamation<key::PublicParts>
            = alice.keys().subkeys().nth(1).unwrap().into();

        let common_grip = Keygrip::of(alice_signing.mpis()).unwrap();
        assert_eq!(common_grip,
                   Keygrip::of(alice_signing2.mpis()).unwrap());

        ks.insert(alice.clone());

        // We have 2 subkeys with the same grip.
        ks_count(&ks, 1, 2, true);
        // The common grip appears twice.
        assert_eq!(ks.by_subkey_grip(&common_grip).count(), 2,
                   "{:?}", ks);
        ks_contains(&ks, &[
            (&alice_pk, true, false),
            (&alice_signing, false, true),
            (&alice_signing2, false, true),
        ]);

        // Remove one of the signing keys with the shared grip.
        let r = ks.remove_all(&alice_signing2.fingerprint());
        assert!(r);

        ks_count(&ks, 1, 1, false);
        assert_eq!(ks.by_subkey_grip(&common_grip).count(), 1);
        ks_contains(&ks, &[
            (&alice_pk, true, false),
            (&alice_signing, false, true),
            (&alice_signing2, false, false),
        ]);

        let r = ks.remove_all(&alice_signing.fingerprint());
        assert!(r);

        ks_count(&ks, 1, 0, false);
        assert_eq!(ks.by_subkey_grip(&common_grip).count(), 0);
        ks_contains(&ks, &[
            (&alice_pk, true, false),
            (&alice_signing, false, false),
            (&alice_signing2, false, false),
        ]);

        // Finally, remove the cert.
        let r = ks.remove_all(&alice.fingerprint());
        assert!(r);

        ks_count(&ks, 0, 0, false);


        // Add alice and bob.  Remove bob.  Make sure everything is
        // still sane.

        ks.insert(alice.clone());
        assert_eq!(ks.by_subkey_grip(&common_grip).count(), 2);

        // The common grip appears twice.
        ks_count(&ks, 1, 2, true);
        assert_eq!(ks.by_subkey_grip(&common_grip).count(), 2);
        ks_contains(&ks, &[
            (&alice_pk, true, false),
            (&alice_signing, false, true),
            (&alice_signing2, false, true),
        ]);

        eprintln!("{:?}", ks);

        Ok(())
    }
}
