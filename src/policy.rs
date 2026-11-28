//! The policy that we apply to certificates, keys, signatures, and
//! messages.
//!
//! This is Sequoia's [`StandardPolicy`], configured from the system's
//! crypto policy and by `rnp_add_security_rule`, plus the rules of
//! RFC 9980 that are neither cryptography nor encoding, and that
//! `sequoia-openpgp` therefore does not enforce.  Currently, these
//! are the key version binding, and the minimum digest size of
//! signatures.
//!
//! A key that violates a rule is treated like any other key that the
//! policy rejects: it is kept in the keyring, it is listed, and it is
//! not used where the policy is asked.  That is when we report a
//! key's state, select recipients, verify signatures, and decrypt.
//!
//! A signature that violates a rule is treated like any other
//! signature that the policy rejects: it is reported as invalid, and
//! a self-signature or a binding signature is not used to validate
//! a certificate.
//!
//! Note: we do not ask the policy before we sign.  Like for any other
//! key that the policy rejects, the caller is expected to check that
//! the key allows signing before it uses the key.

use sequoia_openpgp as openpgp;
use openpgp::{
    Error,
    Packet,
    Result,
    cert::prelude::*,
    packet::{
        Signature,
        key::PublicParts,
    },
    policy::{
        HashAlgoSecurity,
        Policy,
        StandardPolicy,
    },
    types::{
        AEADAlgorithm,
        HashAlgorithm,
        PublicKeyAlgorithm,
        SymmetricAlgorithm,
    },
};

/// The policy of a context.
///
/// This type does not dereference to the [`StandardPolicy`] that it
/// wraps, so that it cannot be handed to Sequoia in place of this
/// policy by accident.
#[derive(Clone, Debug, Default)]
pub struct OctopusPolicy {
    standard: StandardPolicy<'static>,
}

impl From<StandardPolicy<'static>> for OctopusPolicy {
    fn from(standard: StandardPolicy<'static>) -> Self {
        OctopusPolicy { standard }
    }
}

impl OctopusPolicy {
    /// Returns the standard policy for inspecting its cutoff times.
    ///
    /// Do not use the result to validate anything.
    pub fn standard(&self) -> &StandardPolicy<'static> {
        &self.standard
    }

    /// Returns the standard policy for changing its cutoff times.
    pub fn standard_mut(&mut self) -> &mut StandardPolicy<'static> {
        &mut self.standard
    }
}

/// Checks the key version binding of RFC 9980.
///
/// The algorithms of RFC 9980 are to be used only in v6 (and newer)
/// keys, with the single exception of ML-KEM-768+X25519, which is
/// also allowed in v4 encryption subkeys (RFC 9980, Section 3.5, and
/// for the individual algorithms Sections 4.3.2, 5.3.2, and 6.2.2).
///
/// This does not constrain any other algorithm, known or unknown.
pub fn check_key_version_binding(version: u8,
                                 algo: PublicKeyAlgorithm,
                                 primary: bool)
                                 -> Result<()>
{
    use PublicKeyAlgorithm::*;

    let ok = match algo {
        // RFC 9980, Sections 5.3.2 and 6.2.2.
        MLDSA65_Ed25519 | MLDSA87_Ed448
            | SLHDSA128s | SLHDSA128f | SLHDSA256s => version >= 6,

        // RFC 9980, Section 4.3.2.
        MLKEM1024_X448 => version >= 6,

        // RFC 9980, Sections 3.5 and 4.3.2.  ML-KEM-768+X25519 is
        // allowed in v4 keys, but only in encryption subkeys.
        MLKEM768_X25519 => version >= 6 || (version == 4 && ! primary),

        _ => true,
    };

    if ok {
        Ok(())
    } else {
        Err(Error::PolicyViolation(
            format!("{} (algorithm ID {}) in a v{} {} \
                     (RFC 9980, Section 3.5)",
                    algo, u8::from(algo), version,
                    if primary { "primary key" } else { "subkey" }),
            None).into())
    }
}

/// Checks the minimum digest size of RFC 9980.
///
/// A signature using one of the signature algorithms of RFC 9980 must
/// use a hash algorithm with a digest size of at least 256 bits, and
/// a verifying implementation must reject a signature that uses a
/// hash algorithm with a smaller digest size (RFC 9980, Section 5.3.1
/// for the ML-DSA composites, and Section 6.2.1 for SLH-DSA).
///
/// This does not constrain any other algorithm, known or unknown.
pub fn check_digest_size(pk_algo: PublicKeyAlgorithm,
                         hash_algo: HashAlgorithm)
                         -> Result<()>
{
    use PublicKeyAlgorithm::*;

    let section = match pk_algo {
        MLDSA65_Ed25519 | MLDSA87_Ed448 => "5.3.1",
        SLHDSA128s | SLHDSA128f | SLHDSA256s => "6.2.1",
        _ => return Ok(()),
    };

    // We do not know the digest size of a hash algorithm that we do
    // not know, so it does not satisfy the rule.
    match hash_algo.digest_size() {
        Ok(octets) if octets * 8 >= 256 => Ok(()),
        _ => Err(Error::PolicyViolation(
            format!("{} signature using {} (RFC 9980, Section {})",
                    pk_algo, hash_algo, section),
            None).into()),
    }
}

impl Policy for OctopusPolicy {
    fn signature(&self, sig: &Signature, sec: HashAlgoSecurity)
                 -> Result<()>
    {
        // RFC 9980, Sections 5.3.1 and 6.2.1 also restrict these
        // algorithms to v6 signatures.  There is nothing to check
        // here: Sequoia does not verify a signature that is older
        // than v6 using a v6 key, and we reject the keys that are
        // older than v6, see `check_key_version_binding`.
        check_digest_size(sig.pk_algo(), sig.hash_algo())?;
        self.standard.signature(sig, sec)
    }

    fn key(&self, ka: &ValidErasedKeyAmalgamation<PublicParts>)
           -> Result<()>
    {
        check_key_version_binding(
            ka.key().version(), ka.key().pk_algo(), ka.primary())?;
        self.standard.key(ka)
    }

    fn symmetric_algorithm(&self, algo: SymmetricAlgorithm) -> Result<()> {
        self.standard.symmetric_algorithm(algo)
    }

    fn aead_algorithm(&self, algo: AEADAlgorithm) -> Result<()> {
        self.standard.aead_algorithm(algo)
    }

    fn packet(&self, packet: &Packet) -> Result<()> {
        self.standard.packet(packet)
    }

    // Policy::s2k has been added in sequoia-openpgp 2.5.0, and its
    // default implementation rejects everything.  We do not forward
    // it, because we also build with sequoia-openpgp 2.4, which does
    // not have it.  Sequoia only consults it in functions that take a
    // policy for that purpose (e.g. SKESK::decrypt_with_policy), and
    // we call none of them.
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::NP;
    use crate::testdata::key_version_binding::*;
    use crate::testdata::rfc9980;

    /// What RFC 9980 says about each algorithm, key version, and
    /// role.
    #[test]
    fn key_version_binding() {
        use PublicKeyAlgorithm::*;

        // Returns whether the key version binding is satisfied.
        let ok = |version, algo, primary| {
            check_key_version_binding(version, algo, primary).is_ok()
        };

        // RFC 9980, Sections 5.3.2 and 6.2.2: "MUST be used only with
        // v6 keys [...] or newer versions", and Section 4.3.2 for
        // ML-KEM-1024+X448.
        for algo in [MLDSA65_Ed25519, MLDSA87_Ed448,
                     SLHDSA128s, SLHDSA128f, SLHDSA256s,
                     MLKEM1024_X448]
        {
            for primary in [true, false] {
                for version in [2, 3, 4, 5] {
                    assert!(! ok(version, algo, primary),
                            "v{} {}, primary: {}", version, algo, primary);
                }
                for version in [6, 7] {
                    assert!(ok(version, algo, primary),
                            "v{} {}, primary: {}", version, algo, primary);
                }
            }
        }

        // RFC 9980, Section 4.3.2: "MUST be used only with v4 or v6
        // keys [...] or newer versions", and Section 3.5: in v4 keys
        // only in "encryption-capable subkeys".
        for version in [2, 3, 5] {
            assert!(! ok(version, MLKEM768_X25519, true));
            assert!(! ok(version, MLKEM768_X25519, false));
        }
        assert!(! ok(4, MLKEM768_X25519, true));
        assert!(ok(4, MLKEM768_X25519, false));
        for version in [6, 7] {
            assert!(ok(version, MLKEM768_X25519, true));
            assert!(ok(version, MLKEM768_X25519, false));
        }

        // These are the algorithms of RFC 9980, and no others.
        for id in 0..=255 {
            let algo = PublicKeyAlgorithm::from(id);
            let rfc9980 = (30..=36).contains(&id);
            assert_eq!(ALGORITHMS.contains(&algo), rfc9980, "{}", id);

            // The rule says nothing about any other algorithm,
            // including those that we do not know.
            if ! rfc9980 {
                for version in [2, 3, 4, 5, 6, 7] {
                    assert!(ok(version, algo, true), "v{} {}", version, id);
                    assert!(ok(version, algo, false), "v{} {}", version, id);
                }
            }
        }
    }

    /// The error names what is wrong.
    #[test]
    fn key_version_binding_error() {
        let e = check_key_version_binding(
            4, PublicKeyAlgorithm::MLKEM768_X25519, true).unwrap_err();
        assert!(matches!(e.downcast_ref::<Error>(),
                         Some(Error::PolicyViolation(_, None))));
        let e = e.to_string();
        assert!(e.contains("(algorithm ID 35) in a v4 primary key \
                            (RFC 9980, Section 3.5)"),
                "{}", e);

        let e = check_key_version_binding(
            4, PublicKeyAlgorithm::SLHDSA256s, false).unwrap_err()
            .to_string();
        assert!(e.contains("(algorithm ID 34) in a v4 subkey \
                            (RFC 9980, Section 3.5)"),
                "{}", e);
    }

    /// The sample keys of RFC 9980, Appendix A satisfy the key
    /// version binding.  A.2 is the v4 certificate with a
    /// ML-KEM-768+X25519 subkey.
    #[test]
    fn key_version_binding_rfc9980_vectors() {
        let mut v4 = 0;
        for v in rfc9980::VECTORS {
            let cert = v.cert();
            assert_eq!(cert.keys().count(), 2, "{}", v.section);
            for (i, ka) in cert.keys().enumerate() {
                if ka.key().version() == 4 {
                    v4 += 1;
                }
                assert!(check_key_version_binding(
                    ka.key().version(), ka.key().pk_algo(), i == 0).is_ok(),
                        "{}", v.section);
            }
        }
        assert_eq!(v4, 2);
    }

    /// The policy rejects subkeys that violate the key version
    /// binding, and only those.
    #[test]
    fn policy_checks_subkeys() -> Result<()> {
        let p = &OctopusPolicy::default();

        for version in [4, 6] {
            for algo in ALGORITHMS {
                let (cert, fp) = cert_with_subkey(version, algo)?;
                let allowed = version == 6
                    || algo == PublicKeyAlgorithm::MLKEM768_X25519;

                // The binding signature is valid, and is made by a
                // key that every backend supports.
                let np = cert.with_policy(NP, None)?;
                assert_eq!(np.keys().count(), 2);
                let ka = np.keys().subkeys().next().unwrap();
                assert_eq!(ka.key().fingerprint(), fp);
                assert_eq!(ka.key().version(), version);
                assert_eq!(ka.key().pk_algo(), algo);

                // Ask the policy.
                let ka = np.keys().nth(1).unwrap();
                assert!(! ka.primary());
                assert_eq!(p.key(&ka).is_ok(), allowed,
                           "v{} {}", version, algo);
                let ka = np.keys().nth(0).unwrap();
                assert!(ka.primary());
                assert!(p.key(&ka).is_ok(), "v{} {}", version, algo);

                // Ask Sequoia, which asks the policy.  The
                // certificate is valid either way.
                let vc = cert.with_policy(p, None)?;
                assert_eq!(vc.keys().count(), if allowed { 2 } else { 1 },
                           "v{} {}", version, algo);
                assert_eq!(vc.keys().subkeys().count(),
                           if allowed { 1 } else { 0 },
                           "v{} {}", version, algo);
                assert_eq!(vc.keys().for_transport_encryption().count(),
                           if allowed && is_kem(algo) { 1 } else { 0 },
                           "v{} {}", version, algo);
                assert_eq!(
                    cert.keys().subkeys().next().unwrap()
                        .with_policy(p, None).is_ok(),
                    allowed, "v{} {}", version, algo);
            }
        }
        Ok(())
    }

    /// The policy rejects v4 primary keys using the signature
    /// algorithms of RFC 9980 even if the certificate's
    /// self-signature is valid.
    ///
    /// Making such a certificate requires a cryptographic backend
    /// that supports the algorithm.  With the other backends, this
    /// only tests that we cannot make one.
    #[test]
    fn policy_checks_primary_keys() -> Result<()> {
        let p = &OctopusPolicy::default();

        let mut tested = 0;
        for algo in FAST_SIGNATURE_ALGORITHMS {
            if ! algo.is_supported() {
                // We cannot make, or verify, a self-signature.
                assert!(v4_cert_with_primary_key(algo).is_err());
                eprintln!("{} is not supported by the cryptographic \
                           backend, not testing a valid v4 certificate",
                          algo);
                continue;
            }

            let cert = v4_cert_with_primary_key(algo)?;
            assert_eq!(cert.primary_key().key().pk_algo(), algo);

            // The self-signature is valid, ...
            let np = cert.with_policy(NP, None)?;
            assert_eq!(np.userids().count(), 1);
            // ... the policy rejects the key, ...
            let ka = np.keys().nth(0).unwrap();
            assert!(ka.primary());
            assert!(p.key(&ka).is_err(), "{}", algo);
            // ... and so the certificate is not valid.
            let e = cert.with_policy(p, None).unwrap_err();
            assert!(format!("{:?}", e).contains("RFC 9980, Section 3.5"),
                    "{}: {:?}", algo, e);
            assert_eq!(cert.keys().with_policy(p, None).count(), 0,
                       "{}", algo);
            tested += 1;
        }

        // All or nothing: a backend has either all of them or none.
        assert!(tested == 0 || tested == 3);
        Ok(())
    }

    /// The signature algorithms of RFC 9980, Section 2.1, and the
    /// section with the rule on the digest size.
    const SIGNATURE_ALGORITHMS: [(u8, &str); 5] = [
        (30, "5.3.1"),
        (31, "5.3.1"),
        (32, "6.2.1"),
        (33, "6.2.1"),
        (34, "6.2.1"),
    ];

    /// What RFC 9980 says about each signature algorithm and hash
    /// algorithm.
    #[test]
    fn digest_size() {
        let ok = |pk_algo: u8, hash_algo: u8| {
            check_digest_size(pk_algo.into(), hash_algo.into()).is_ok()
        };

        // The hash algorithms with a digest size of at least 256
        // bits, RFC 9580, Section 9.5: SHA2-256, SHA2-384, SHA2-512,
        // SHA3-256, and SHA3-512.
        let large = [8, 9, 10, 12, 14];
        // And those with a smaller digest size: MD5, SHA-1,
        // RIPEMD-160, and SHA2-224.
        let small = [1, 2, 3, 11];

        for pk_algo in 0..=255 {
            let rfc9980 =
                SIGNATURE_ALGORITHMS.iter().any(|(a, _)| *a == pk_algo);
            assert_eq!(rfc9980, (30..=34).contains(&pk_algo));

            for hash_algo in 0..=255 {
                if rfc9980 {
                    // RFC 9980, Sections 5.3.1 and 6.2.1: "MUST use a
                    // hash algorithm with a digest size of at least
                    // 256 bits", and a verifying implementation "MUST
                    // reject" any other.  That includes the hash
                    // algorithms that we do not know.
                    assert_eq!(ok(pk_algo, hash_algo),
                               large.contains(&hash_algo),
                               "{} {}", pk_algo, hash_algo);
                    assert!(! (ok(pk_algo, hash_algo)
                               && small.contains(&hash_algo)));
                } else {
                    // The rule says nothing about any other
                    // algorithm, including the ML-KEM composites and
                    // those that we do not know.
                    assert!(ok(pk_algo, hash_algo),
                            "{} {}", pk_algo, hash_algo);
                }
            }
        }
    }

    /// The error names what is wrong.
    #[test]
    fn digest_size_error() {
        for (pk_algo, section) in SIGNATURE_ALGORITHMS {
            let e = check_digest_size(pk_algo.into(), HashAlgorithm::SHA224)
                .unwrap_err();
            assert!(matches!(e.downcast_ref::<Error>(),
                             Some(Error::PolicyViolation(_, None))));
            let e = e.to_string();
            assert!(e.contains(&format!(
                "signature using SHA224 (RFC 9980, Section {})", section)),
                    "{}", e);
        }
    }

    /// The policy rejects signatures that violate the rule on the
    /// digest size, and only those.
    ///
    /// The signatures are not signatures, see `dummy_signature`.
    /// Whether a signature that the cryptographic backend can verify
    /// is rejected is tested at the interface, see
    /// `rfc9980_digest_size`.
    #[test]
    fn policy_checks_signatures() -> Result<()> {
        use crate::testdata::signatures::dummy_signature;

        let p = &OctopusPolicy::default();
        let standard = &StandardPolicy::new();
        let secs = [HashAlgoSecurity::SecondPreImageResistance,
                    HashAlgoSecurity::CollisionResistance];

        // Any v6 fingerprint will do.
        let issuer = rfc9980::VECTORS[0].cert().fingerprint();

        for (pk_algo, section) in SIGNATURE_ALGORITHMS {
            // The standard policy accepts SHA2-224, we do not.
            let sig = dummy_signature(pk_algo, HashAlgorithm::SHA224, &issuer)?;
            assert_eq!(sig.version(), 6);
            for sec in secs {
                assert!(standard.signature(&sig, sec).is_ok());
                let e = p.signature(&sig, sec).unwrap_err().to_string();
                assert!(e.contains(&format!("RFC 9980, Section {}", section)),
                        "{}: {}", pk_algo, e);
            }

            // Hash algorithms that the standard policy rejects, too.
            for hash_algo in [HashAlgorithm::MD5,
                              HashAlgorithm::SHA1,
                              HashAlgorithm::RipeMD]
            {
                let sig = dummy_signature(pk_algo, hash_algo, &issuer)?;
                for sec in secs {
                    assert!(p.signature(&sig, sec).is_err(),
                            "{} {}", pk_algo, hash_algo);
                }
            }

            for hash_algo in [HashAlgorithm::SHA256,
                              HashAlgorithm::SHA384,
                              HashAlgorithm::SHA512,
                              HashAlgorithm::SHA3_256,
                              HashAlgorithm::SHA3_512]
            {
                let sig = dummy_signature(pk_algo, hash_algo, &issuer)?;
                for sec in secs {
                    assert!(standard.signature(&sig, sec).is_ok());
                    assert!(p.signature(&sig, sec).is_ok(),
                            "{} {}", pk_algo, hash_algo);
                }
            }
        }

        // Other algorithms are not affected: Ed25519, and an
        // algorithm that we do not know.
        for pk_algo in [27, 37] {
            let sig = dummy_signature(pk_algo, HashAlgorithm::SHA224, &issuer)?;
            for sec in secs {
                assert!(p.signature(&sig, sec).is_ok(), "{}", pk_algo);
            }
        }

        // The detached signatures of RFC 9980, Appendix A satisfy the
        // rule.
        let mut algos = Vec::new();
        for s in rfc9980::SIGNATURES {
            let sig = s.packet();
            algos.push(u8::from(sig.pk_algo()));
            for sec in secs {
                assert!(p.signature(&sig, sec).is_ok(), "{}", s.section);
            }
        }
        assert_eq!(algos,
                   SIGNATURE_ALGORITHMS.iter().map(|(a, _)| *a)
                   .collect::<Vec<_>>());
        Ok(())
    }

    /// The policy also rejects self-signatures that violate the rule
    /// on the digest size, so a certificate with a primary key using
    /// a signature algorithm of RFC 9980 is not valid if all of its
    /// self-signatures use SHA2-224.
    ///
    /// Making such a certificate requires a cryptographic backend
    /// that supports the algorithm.  With the other backends, this
    /// tests nothing.
    #[test]
    fn policy_checks_self_signatures() -> Result<()> {
        use openpgp::packet::UserID;
        use openpgp::packet::signature::SignatureBuilder;
        use openpgp::parse::Parse;
        use openpgp::types::{KeyFlags, SignatureType};

        let p = &OctopusPolicy::default();
        let standard = &StandardPolicy::new();

        let mut tested = 0;
        for v in rfc9980::VECTORS {
            let algo = PublicKeyAlgorithm::from(v.primary.algo);
            if ! FAST_SIGNATURE_ALGORITHMS.contains(&algo) {
                continue;
            }
            if ! algo.is_supported() {
                eprintln!("{} is not supported by the cryptographic \
                           backend, not testing a self-signature", algo);
                continue;
            }
            let section = SIGNATURE_ALGORITHMS.iter()
                .find(|(a, _)| *a == v.primary.algo).unwrap().1;

            // The primary key of the sample key, a user ID, and a
            // self-signature using the given hash algorithm.
            let cert_with = |hash_algo| -> Result<Cert> {
                let key = Cert::from_bytes(v.tsk)?.primary_key().key()
                    .clone().parts_into_secret()?;
                let mut signer = key.clone().into_keypair()?;
                let cert = Cert::try_from(vec![Packet::SecretKey(key)])?;
                let userid = UserID::from(USERID);
                let sig = userid.bind(
                    &mut signer, &cert,
                    SignatureBuilder::new(SignatureType::PositiveCertification)
                        .set_hash_algo(hash_algo)
                        .set_key_flags(KeyFlags::empty()
                                       .set_certification().set_signing())?)?;
                assert_eq!(sig.version(), 6);
                assert_eq!(sig.pk_algo(), algo);
                assert_eq!(sig.hash_algo(), hash_algo);
                let (cert, _) = cert.insert_packets(
                    vec![Packet::from(userid), sig.into()])?;
                // The self-signature is valid.
                assert_eq!(cert.with_policy(NP, None)?.userids().count(), 1);
                Ok(cert.strip_secret_key_material())
            };

            let cert = cert_with(HashAlgorithm::SHA256)?;
            assert!(cert.with_policy(standard, None).is_ok());
            assert!(cert.with_policy(p, None).is_ok(), "{}", v.section);

            let cert = cert_with(HashAlgorithm::SHA224)?;
            assert!(cert.with_policy(standard, None).is_ok());
            let e = cert.with_policy(p, None).unwrap_err();
            assert!(format!("{:?}", e).contains(
                &format!("RFC 9980, Section {}", section)),
                    "{}: {:?}", v.section, e);
            assert_eq!(cert.keys().with_policy(p, None).count(), 0,
                       "{}", v.section);
            tested += 1;
        }

        // Make sure that we tested what we mean to test.
        match rfc9980::backend_has_rfc9980() {
            Some(true) => assert_eq!(tested, 3),
            Some(false) => assert_eq!(tested, 0),
            None => assert!(tested == 0 || tested == 3),
        }
        Ok(())
    }

    /// Everything else is decided by the standard policy.
    #[test]
    fn policy_applies_standard_policy() -> Result<()> {
        use openpgp::packet::Tag;
        use openpgp::policy::AsymmetricAlgorithm;
        use openpgp::types::SignatureType;

        let (cert, _) = CertBuilder::general_purpose(Some("alice"))
            .set_cipher_suite(CipherSuite::P256)
            .generate()?;
        let np = cert.with_policy(NP, None)?;
        let sig = np.primary_userid()?.binding_signature().clone();
        assert_eq!(sig.typ(), SignatureType::PositiveCertification);
        let literal = Packet::Literal(
            openpgp::packet::Literal::new(openpgp::types::DataFormat::Binary));

        // By default, all of these are fine.
        let p = OctopusPolicy::default();
        assert_eq!(cert.with_policy(&p, None)?.keys().count(), 3);
        for ka in np.keys() {
            assert!(p.key(&ka).is_ok());
        }
        assert!(p.signature(
            &sig, HashAlgoSecurity::SecondPreImageResistance).is_ok());
        assert!(p.symmetric_algorithm(SymmetricAlgorithm::AES256).is_ok());
        assert!(p.aead_algorithm(AEADAlgorithm::OCB).is_ok());
        assert!(p.packet(&literal).is_ok());

        // The key.
        let mut p = OctopusPolicy::default();
        p.standard_mut().reject_asymmetric_algo(AsymmetricAlgorithm::NistP256);
        assert!(cert.with_policy(&p, None).is_err());
        for ka in np.keys() {
            assert!(p.key(&ka).is_err());
        }
        assert!(p.standard().asymmetric_algo_cutoff(
            AsymmetricAlgorithm::NistP256).is_some());

        // The signature.
        let mut p = OctopusPolicy::default();
        assert_eq!(sig.hash_algo(), HashAlgorithm::SHA512);
        p.standard_mut().reject_hash(HashAlgorithm::SHA512);
        assert!(p.signature(
            &sig, HashAlgoSecurity::SecondPreImageResistance).is_err());
        assert!(cert.with_policy(&p, None).is_err());

        // The symmetric algorithm.
        let mut p = OctopusPolicy::default();
        p.standard_mut().reject_symmetric_algo(SymmetricAlgorithm::AES256);
        assert!(p.symmetric_algorithm(SymmetricAlgorithm::AES256).is_err());
        assert!(p.symmetric_algorithm(SymmetricAlgorithm::AES128).is_ok());

        // The AEAD algorithm.
        let mut p = OctopusPolicy::default();
        p.standard_mut().reject_aead_algo(AEADAlgorithm::OCB);
        assert!(p.aead_algorithm(AEADAlgorithm::OCB).is_err());
        assert!(p.aead_algorithm(AEADAlgorithm::EAX).is_ok());

        // The packet.
        let mut p = OctopusPolicy::default();
        p.standard_mut().reject_packet_tag(Tag::Literal);
        assert!(p.packet(&literal).is_err());

        // And a policy can be made from a standard policy.
        let mut standard = StandardPolicy::new();
        standard.reject_symmetric_algo(SymmetricAlgorithm::AES256);
        let p = OctopusPolicy::from(standard);
        assert!(p.symmetric_algorithm(SymmetricAlgorithm::AES256).is_err());
        Ok(())
    }
}
