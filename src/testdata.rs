//! Data for tests.

/// The sample keys from RFC 9980, Appendix A.
pub mod rfc9980 {
    use sequoia_openpgp as openpgp;
    use openpgp::{
        Cert,
        parse::Parse,
    };

    /// What we expect RNP's interface to report for a key.
    pub struct TestKey {
        /// The algorithm ID.
        ///
        /// From RFC 9580, Section 9.1, and RFC 9980, Section 2.1.
        pub algo: u8,

        /// The name of the algorithm in RNP's interface.
        pub name: &'static str,

        /// The size of the algorithm-specific part of the public key
        /// in bits.
        ///
        /// From RFC 9580, Section 5.5.5.9, and RFC 9980, Tables 3, 4,
        /// 6, 7, and 8.
        pub bits: u32,

        /// The fingerprint as given in Appendix A.
        pub fingerprint: &'static str,

        /// The SHA-1 digest of the algorithm-specific part of the
        /// public key.
        ///
        /// These values have been computed without the help of
        /// Sequoia: they are the output of `sha1sum` over the
        /// corresponding octets of the key packets.
        pub grip: &'static str,
    }

    /// A Transferable Secret Key, and what we expect for its keys.
    pub struct TestVector {
        /// The section of RFC 9980 containing the key.
        pub section: &'static str,
        /// The Transferable Secret Key.
        pub tsk: &'static [u8],
        /// The version of the keys.
        pub version: u32,
        /// The primary key.
        pub primary: TestKey,
        /// The subkey.
        pub subkey: TestKey,
    }

    impl TestVector {
        /// Returns the certificate without secret key material.
        pub fn cert(&self) -> Cert {
            Cert::from_bytes(self.tsk).expect("valid test vector")
                .strip_secret_key_material()
        }

        /// Returns the primary key followed by the subkey.
        pub fn keys(&self) -> [&TestKey; 2] {
            [&self.primary, &self.subkey]
        }
    }

    /// A detached signature over `SIGNED_DATA`.
    pub struct TestSignature {
        /// The section of RFC 9980 containing the signature.
        pub section: &'static str,
        /// The signature.
        pub signature: &'static [u8],
        /// The section of RFC 9980 containing the Transferable Secret
        /// Key that made the signature.
        pub signer: &'static str,
    }

    impl TestSignature {
        /// Returns the Transferable Secret Key that made the
        /// signature, and what we expect for its keys.
        pub fn signer(&self) -> &'static TestVector {
            VECTORS.iter().find(|v| v.section == self.signer)
                .expect("the signer is one of the test vectors")
        }

        /// Returns the signature packet.
        pub fn packet(&self) -> openpgp::packet::Signature {
            match openpgp::Packet::from_bytes(self.signature)
                .expect("valid test vector")
            {
                openpgp::Packet::Signature(sig) => sig,
                p => panic!("expected a signature, got: {:?}", p),
            }
        }
    }

    /// Whether the cryptographic backend supports the algorithms of
    /// RFC 9980, if we know that without asking Sequoia.
    ///
    /// Tests whose outcome depends on the backend use this to make
    /// sure that they tested what they mean to test.
    pub fn backend_has_rfc9980() -> Option<bool> {
        let backend = openpgp::crypto::backend();
        if backend.starts_with("RustCrypto") {
            Some(true)
        } else if let Some(version) = backend.strip_prefix("OpenSSL ") {
            // OpenSSL has ML-KEM, ML-DSA, and SLH-DSA since version
            // 3.5.
            let mut version = version.split('.').map(|c| c.parse::<u32>());
            match (version.next(), version.next()) {
                (Some(Ok(major)), Some(Ok(minor))) =>
                    Some((major, minor) >= (3, 5)),
                _ => panic!("cannot parse the version: {:?}", backend),
            }
        } else {
            None
        }
    }

    /// The Transferable Secret Keys of Appendix A.
    pub const VECTORS: &[TestVector] = &[
        TestVector {
            section: "A.1.1",
            tsk: include_bytes!("../tests/data/rfc9980/A.1.1.asc"),
            version: 6,
            primary: TestKey {
                algo: 27,
                name: "ED25519",
                bits: 256,
                fingerprint: "C789E17D9DBDCA7B3C833A3C063FEB03\
                              53F80AD911FE27868FB0645DF803E947",
                grip: "FBF78E7446713336F95ABBEE206BF9D8DAD17C9A",
            },
            subkey: TestKey {
                algo: 35,
                name: "ML-KEM-768+X25519",
                bits: (32 + 1184) * 8,
                fingerprint: "DAFE0EEBB2675ECFCDC20A23FE89CA5D\
                              12E83F527DFA354B6DCF662131A48B9D",
                grip: "E0DEC15C542EFCB5C9E41728196E6EA9F13C0C22",
            },
        },
        TestVector {
            section: "A.2.1",
            tsk: include_bytes!("../tests/data/rfc9980/A.2.1.asc"),
            version: 4,
            primary: TestKey {
                algo: 27,
                name: "ED25519",
                bits: 256,
                fingerprint: "342E5DB2DE345215CB2C944F7102FFED3B9CF12D",
                grip: "901EA858C5B0F3593051942DB3CC8B697AAD5CE7",
            },
            subkey: TestKey {
                algo: 35,
                name: "ML-KEM-768+X25519",
                bits: (32 + 1184) * 8,
                fingerprint: "E51DBFEA51936988B5428FFFA4F95F985ED61A51",
                grip: "C41E084A34816E4D5D8022B26B78407D0F1D94AE",
            },
        },
        TestVector {
            section: "A.3.1",
            tsk: include_bytes!("../tests/data/rfc9980/A.3.1.asc"),
            version: 6,
            primary: TestKey {
                algo: 30,
                name: "ML-DSA-65+ED25519",
                bits: (32 + 1952) * 8,
                fingerprint: "A3E2E14B6A493FF930FB27321F125E9A\
                              6880338BE9FB7DA3AE065EA65793242F",
                grip: "77AD1BA119493C82C9EA3C72B0B56F40048483CF",
            },
            subkey: TestKey {
                algo: 35,
                name: "ML-KEM-768+X25519",
                bits: (32 + 1184) * 8,
                fingerprint: "7DAE8FBCE23022607167AF72A002E774\
                              E0CA379A2D7AE072384E1E8FDE3265E4",
                grip: "7E5AD0CBF8569101AD2287FC62053123E06FCACE",
            },
        },
        TestVector {
            section: "A.4.1",
            tsk: include_bytes!("../tests/data/rfc9980/A.4.1.asc"),
            version: 6,
            primary: TestKey {
                algo: 31,
                name: "ML-DSA-87+ED448",
                bits: (57 + 2592) * 8,
                fingerprint: "0D7A8BE1410CD68EED4845AB487B4B4C\
                              FAECD8EBAD1A1166A84230499200EE20",
                grip: "04CC18DD1A9AA42D842B2CE9C33C769C0D23C32D",
            },
            subkey: TestKey {
                algo: 36,
                name: "ML-KEM-1024+X448",
                bits: (56 + 1568) * 8,
                fingerprint: "65090E147A8116AB7F62AB4EC7AAE59D\
                              9E6532FEB2AF230C73CDC869FBC60C8F",
                grip: "40F5F050AC42DFEB08FC083D6A59AD45F05DD2FF",
            },
        },
        TestVector {
            section: "A.5.1",
            tsk: include_bytes!("../tests/data/rfc9980/A.5.1.asc"),
            version: 6,
            primary: TestKey {
                algo: 32,
                name: "SLH-DSA-SHAKE-128s",
                bits: 32 * 8,
                fingerprint: "EED4D13FC36C78E48276A93233339C4D\
                              D230FD5F6F5C5B82C63D5C0B5E361D92",
                grip: "33511300AD3923446F14C483BC1A360C8BD97831",
            },
            subkey: TestKey {
                algo: 35,
                name: "ML-KEM-768+X25519",
                bits: (32 + 1184) * 8,
                fingerprint: "3E8745A4BB488779E0F32480FA23F8D0\
                              BFD8C2F49D7F74E957E1C2FFC2EF4BFC",
                grip: "F3F98BBBFF5A2B960D5508F877447E4911C6DB5B",
            },
        },
        TestVector {
            section: "A.6.1",
            tsk: include_bytes!("../tests/data/rfc9980/A.6.1.asc"),
            version: 6,
            primary: TestKey {
                algo: 33,
                name: "SLH-DSA-SHAKE-128f",
                bits: 32 * 8,
                fingerprint: "D54E0307021169F7B88BEB2B76E3AAD0\
                              E114BE1A8F982D74DBA9CA51D03537F4",
                grip: "EA1629EEB728D33110C63DA5AC60BBF968FCFAC2",
            },
            subkey: TestKey {
                algo: 35,
                name: "ML-KEM-768+X25519",
                bits: (32 + 1184) * 8,
                fingerprint: "D8875664256C382DD7F3A5CE05021088\
                              922811F5D0B1A1F8C7769944A51B7002",
                grip: "296B6CF2E09FF7613294EB88A55465C693832D1F",
            },
        },
        TestVector {
            section: "A.7.1",
            tsk: include_bytes!("../tests/data/rfc9980/A.7.1.asc"),
            version: 6,
            primary: TestKey {
                algo: 34,
                name: "SLH-DSA-SHAKE-256s",
                bits: 64 * 8,
                fingerprint: "72FFF84863AEBA67F0D1D7691173247D\
                              D427533B9D7EE76011C6F77F2CE9FA7A",
                grip: "5A2C7C9051B24D017F38AFFDB8E0171175C5187A",
            },
            subkey: TestKey {
                algo: 36,
                name: "ML-KEM-1024+X448",
                bits: (56 + 1568) * 8,
                fingerprint: "570A5BBAB93169876A8240DA35A1ADA7\
                              BA8A640AABE3AB467C797214844DF15F",
                grip: "52637724D06BEBF5AC767116409CD3FD8ACF19D6",
            },
        },
    ];

    /// The data that the detached signatures of Appendix A are made
    /// over.
    pub const SIGNED_DATA: &[u8] = b"Testing\n";

    /// The detached signatures of Appendix A.
    pub const SIGNATURES: &[TestSignature] = &[
        TestSignature {
            section: "A.3.4",
            signature: include_bytes!("../tests/data/rfc9980/A.3.4.asc"),
            signer: "A.3.1",
        },
        TestSignature {
            section: "A.4.4",
            signature: include_bytes!("../tests/data/rfc9980/A.4.4.asc"),
            signer: "A.4.1",
        },
        TestSignature {
            section: "A.5.4",
            signature: include_bytes!("../tests/data/rfc9980/A.5.4.asc"),
            signer: "A.5.1",
        },
        TestSignature {
            section: "A.6.3",
            signature: include_bytes!("../tests/data/rfc9980/A.6.3.asc"),
            signer: "A.6.1",
        },
        TestSignature {
            section: "A.7.3",
            signature: include_bytes!("../tests/data/rfc9980/A.7.3.asc"),
            signer: "A.7.1",
        },
    ];
}

/// Keys for testing the key version binding of RFC 9980, Section 3.5.
pub mod key_version_binding {
    use std::time::{Duration, SystemTime};

    use sequoia_openpgp as openpgp;
    use openpgp::{
        Cert,
        Fingerprint,
        Packet,
        Profile,
        Result,
        cert::{
            CertBuilder,
            SubkeyBuilder,
        },
        crypto::mpi,
        packet::{
            Key,
            UserID,
            key::{
                Key4,
                Key6,
                PrimaryRole,
                PublicParts,
                SecretKeyMaterial,
                SecretParts,
                SubordinateRole,
                UnspecifiedParts,
            },
            signature::SignatureBuilder,
        },
        types::{
            KeyFlags,
            PublicKeyAlgorithm,
            SignatureType,
        },
    };

    /// The user ID of the certificates.
    pub const USERID: &str = "alice";

    /// The algorithms of RFC 9980, Section 2.1.
    pub const ALGORITHMS: [PublicKeyAlgorithm; 7] = [
        PublicKeyAlgorithm::MLDSA65_Ed25519,
        PublicKeyAlgorithm::MLDSA87_Ed448,
        PublicKeyAlgorithm::SLHDSA128s,
        PublicKeyAlgorithm::SLHDSA128f,
        PublicKeyAlgorithm::SLHDSA256s,
        PublicKeyAlgorithm::MLKEM768_X25519,
        PublicKeyAlgorithm::MLKEM1024_X448,
    ];

    /// The signature algorithms that we make valid v4 certificates
    /// for, see `v4_cert_with_primary_key`.
    ///
    /// SLH-DSA-SHAKE-128s and SLH-DSA-SHAKE-256s are missing: making
    /// one signature with them takes minutes in a debug build using
    /// the RustCrypto backend.
    pub const FAST_SIGNATURE_ALGORITHMS: [PublicKeyAlgorithm; 3] = [
        PublicKeyAlgorithm::MLDSA65_Ed25519,
        PublicKeyAlgorithm::MLDSA87_Ed448,
        PublicKeyAlgorithm::SLHDSA128f,
    ];

    /// Returns whether the algorithm is one of the two ML-KEM
    /// composites.
    pub fn is_kem(algo: PublicKeyAlgorithm) -> bool {
        matches!(algo,
                 PublicKeyAlgorithm::MLKEM768_X25519
                 | PublicKeyAlgorithm::MLKEM1024_X448)
    }

    /// Returns something that has the form of a public key of the
    /// given algorithm, but is not a key: all octets are the same.
    ///
    /// This is good enough for everything that does not compute with
    /// the key, and it works with every cryptographic backend.
    pub fn dummy_public_key(algo: PublicKeyAlgorithm) -> mpi::PublicKey {
        use mpi::PublicKey::*;

        match algo {
            PublicKeyAlgorithm::MLDSA65_Ed25519 => MLDSA65_Ed25519 {
                eddsa: Box::new([0x42; 32]),
                mldsa: Box::new([0x42; 1952]),
            },
            PublicKeyAlgorithm::MLDSA87_Ed448 => MLDSA87_Ed448 {
                eddsa: Box::new([0x42; 57]),
                mldsa: Box::new([0x42; 2592]),
            },
            PublicKeyAlgorithm::SLHDSA128s =>
                SLHDSA128s { public: [0x42; 32] },
            PublicKeyAlgorithm::SLHDSA128f =>
                SLHDSA128f { public: [0x42; 32] },
            PublicKeyAlgorithm::SLHDSA256s =>
                SLHDSA256s { public: Box::new([0x42; 64]) },
            PublicKeyAlgorithm::MLKEM768_X25519 => MLKEM768_X25519 {
                ecdh: Box::new([0x42; 32]),
                mlkem: Box::new([0x42; 1184]),
            },
            PublicKeyAlgorithm::MLKEM1024_X448 => MLKEM1024_X448 {
                ecdh: Box::new([0x42; 56]),
                mlkem: Box::new([0x42; 1568]),
            },
            _ => unreachable!("not an algorithm of RFC 9980"),
        }
    }

    fn creation_time() -> SystemTime {
        SystemTime::now() - Duration::new(60, 0)
    }

    /// Returns a certificate with keys of the given version: a
    /// primary key using a classic algorithm, a user ID, and a subkey
    /// using the given algorithm.  Also returns the fingerprint of
    /// the subkey.
    ///
    /// The subkey is not a key, see `dummy_public_key`, but its
    /// binding signature is valid.  According to its key flags, it is
    /// for encryption if it uses a ML-KEM composite, and for nothing
    /// otherwise: a subkey for signing or authentication would have
    /// to make a signature itself.
    pub fn cert_with_subkey(version: u8, algo: PublicKeyAlgorithm)
                            -> Result<(Cert, Fingerprint)>
    {
        let builder = CertBuilder::new().add_userid(USERID);
        let builder = match version {
            4 => builder.set_profile(Profile::RFC4880)?,
            6 => builder.set_profile(Profile::RFC9580)?,
            _ => unreachable!("neither a v4 nor a v6 key"),
        };
        let (cert, _) = builder.generate()?;
        assert_eq!(cert.primary_key().key().version(), version);
        assert_eq!(cert.keys().count(), 1);

        let subkey: Key<UnspecifiedParts, SubordinateRole> = match version {
            4 => Key4::<PublicParts, SubordinateRole>::new(
                creation_time(), algo, dummy_public_key(algo))?
                .parts_into_unspecified().into(),
            6 => Key6::<PublicParts, SubordinateRole>::new(
                creation_time(), algo, dummy_public_key(algo))?
                .parts_into_unspecified().into(),
            _ => unreachable!("neither a v4 nor a v6 key"),
        };
        let fp = subkey.fingerprint();

        let flags = if is_kem(algo) {
            KeyFlags::empty()
                .set_transport_encryption()
                .set_storage_encryption()
        } else {
            KeyFlags::empty()
        };

        let signer = cert.primary_key().key().clone()
            .parts_into_secret()?.into_keypair()?;
        let cert = SubkeyBuilder::new(
            cert.with_policy(crate::NP, None)?, subkey, flags)?
            .set_primary_key_signer(signer)
            .attach_cert()?;
        assert_eq!(cert.keys().count(), 2);
        assert_eq!(cert.keys().subkeys().next().unwrap()
                   .self_signatures().count(), 1);
        Ok((cert.strip_secret_key_material(), fp))
    }

    /// Returns a v4 primary key using the given algorithm, and a user
    /// ID.
    ///
    /// The key is not a key, see `dummy_public_key`, and there is no
    /// self-signature.
    pub fn v4_primary_key_without_signature(algo: PublicKeyAlgorithm)
                                            -> Result<Cert>
    {
        let key: Key<PublicParts, PrimaryRole> =
            Key4::new(creation_time(), algo, dummy_public_key(algo))?.into();
        let cert = Cert::try_from(vec![
            Packet::PublicKey(key),
            Packet::from(UserID::from(USERID)),
        ])?;
        assert_eq!(cert.primary_key().key().version(), 4);
        assert_eq!(cert.userids().count(), 1);
        Ok(cert)
    }

    /// Returns a v4 certificate with secret key material: a primary
    /// key using the given signature algorithm, and a user ID with a
    /// valid self-signature.
    ///
    /// This is a certificate that RFC 9980 forbids, and whose
    /// self-signature can be verified nevertheless.  Generating it
    /// requires a cryptographic backend that supports the algorithm.
    pub fn v4_cert_with_primary_key(algo: PublicKeyAlgorithm)
                                    -> Result<Cert>
    {
        type K6 = Key6<SecretParts, PrimaryRole>;

        // There is no function that generates such a key.  Generate
        // a v6 key, and put its key material into a v4 key.
        let k6 = match algo {
            PublicKeyAlgorithm::MLDSA65_Ed25519 =>
                K6::generate_mldsa65_ed25519()?,
            PublicKeyAlgorithm::MLDSA87_Ed448 =>
                K6::generate_mldsa87_ed448()?,
            PublicKeyAlgorithm::SLHDSA128s => K6::generate_slhdsa128s()?,
            PublicKeyAlgorithm::SLHDSA128f => K6::generate_slhdsa128f()?,
            PublicKeyAlgorithm::SLHDSA256s => K6::generate_slhdsa256s()?,
            _ => unreachable!("not a signature algorithm of RFC 9980"),
        };
        let secret = match k6.secret() {
            SecretKeyMaterial::Unencrypted(u) => u.clone(),
            SecretKeyMaterial::Encrypted(_) =>
                unreachable!("generated keys are not encrypted"),
        };
        let key: Key<SecretParts, PrimaryRole> =
            Key4::with_secret(creation_time(), algo, k6.mpis().clone(),
                              secret.into())?.into();
        let mut signer = key.clone().into_keypair()?;

        let userid = UserID::from(USERID);
        let cert = Cert::try_from(vec![Packet::SecretKey(key)])?;
        let sig = userid.bind(
            &mut signer, &cert,
            SignatureBuilder::new(SignatureType::PositiveCertification)
                .set_key_flags(
                    KeyFlags::empty().set_certification().set_signing())?)?;
        assert_eq!(sig.version(), 4);
        let (cert, _) =
            cert.insert_packets(vec![Packet::from(userid), sig.into()])?;
        assert_eq!(cert.primary_key().key().version(), 4);
        assert!(cert.is_tsk());
        Ok(cert)
    }

    /// Returns a v4 certificate with secret key material: a primary
    /// key using a classic algorithm, a user ID, and an encryption
    /// subkey using the given ML-KEM composite.
    ///
    /// For ML-KEM-1024+X448, this is a certificate that RFC 9980
    /// forbids.  Generating the subkey requires a cryptographic
    /// backend that supports the algorithm.
    pub fn v4_cert_with_kem_subkey(algo: PublicKeyAlgorithm) -> Result<Cert> {
        type K6 = Key6<SecretParts, SubordinateRole>;

        let (cert, _) = CertBuilder::new().add_userid(USERID)
            .set_profile(Profile::RFC4880)?
            .generate()?;
        assert_eq!(cert.keys().count(), 1);

        // Generate a v6 key, and put its key material into a v4 key.
        let k6 = match algo {
            PublicKeyAlgorithm::MLKEM768_X25519 =>
                K6::generate_mlkem768_x25519()?,
            PublicKeyAlgorithm::MLKEM1024_X448 =>
                K6::generate_mlkem1024_x448()?,
            _ => unreachable!("not a ML-KEM composite"),
        };
        let secret = match k6.secret() {
            SecretKeyMaterial::Unencrypted(u) => u.clone(),
            SecretKeyMaterial::Encrypted(_) =>
                unreachable!("generated keys are not encrypted"),
        };
        let subkey: Key<SecretParts, SubordinateRole> =
            Key4::with_secret(creation_time(), algo, k6.mpis().clone(),
                              secret.into())?.into();

        let signer = cert.primary_key().key().clone()
            .parts_into_secret()?.into_keypair()?;
        let cert = SubkeyBuilder::new(
            cert.with_policy(crate::NP, None)?,
            subkey.parts_into_unspecified(),
            KeyFlags::empty()
                .set_transport_encryption()
                .set_storage_encryption())?
            .set_primary_key_signer(signer)
            .attach_cert()?;
        assert_eq!(cert.keys().count(), 2);
        assert!(cert.keys().all(|ka| ka.key().version() == 4));
        assert!(cert.keys().all(|ka| ka.key().has_secret()));
        Ok(cert)
    }
}

/// Signatures for testing the rules of RFC 9980 for signatures.
pub mod signatures {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use sequoia_openpgp as openpgp;
    use openpgp::{
        Fingerprint,
        Packet,
        Result,
        packet::{
            Key,
            Signature,
            key::{
                Key4,
                PrimaryRole,
                SecretKeyMaterial,
                SecretParts,
            },
        },
        parse::Parse,
        types::HashAlgorithm,
    };

    /// Returns the size of a signature using the given algorithm in
    /// octets.
    ///
    /// From RFC 9980, Tables 6, 7, and 8.  For the composites, the
    /// EdDSA signature comes first.
    pub fn signature_size(pk_algo: u8) -> Option<(usize, usize)> {
        match pk_algo {
            30 => Some((64, 3309)),
            31 => Some((114, 4627)),
            32 => Some((0, 7856)),
            33 => Some((0, 17088)),
            34 => Some((0, 29792)),
            _ => None,
        }
    }

    /// Returns something that has the form of a signature over a
    /// binary document, but is not a signature: all octets of the
    /// algorithm-specific part are the same.
    ///
    /// This is good enough for everything that does not compute with
    /// the signature, and it works with every cryptographic backend.
    /// The signature names `issuer` as its issuer, and it is of
    /// version 4 if that is a v4 fingerprint, and of version 6
    /// otherwise.
    pub fn dummy_signature(pk_algo: u8, hash_algo: HashAlgorithm,
                           issuer: &Fingerprint)
                           -> Result<Signature>
    {
        let version: u8 = match issuer {
            Fingerprint::V4(_) => 4,
            Fingerprint::V6(_) => 6,
            _ => unreachable!("neither a v4 nor a v6 fingerprint"),
        };

        // The hashed subpackets (RFC 9580, Section 5.2.3.7): the
        // signature creation time, and the issuer fingerprint.
        let creation_time = (SystemTime::now() - Duration::new(60, 0))
            .duration_since(UNIX_EPOCH)?.as_secs() as u32;
        let mut hashed = vec![5, 2];
        hashed.extend_from_slice(&creation_time.to_be_bytes());
        hashed.push(1 + 1 + issuer.as_bytes().len() as u8);
        hashed.push(33);
        hashed.push(version);
        hashed.extend_from_slice(issuer.as_bytes());

        // The packet body (RFC 9580, Sections 5.2.3).
        let mut body = vec![version, 0, pk_algo, hash_algo.into()];
        if version == 4 {
            body.extend_from_slice(&(hashed.len() as u16).to_be_bytes());
            body.extend_from_slice(&hashed);
            body.extend_from_slice(&0u16.to_be_bytes());
        } else {
            body.extend_from_slice(&(hashed.len() as u32).to_be_bytes());
            body.extend_from_slice(&hashed);
            body.extend_from_slice(&0u32.to_be_bytes());
        }
        // The left 16 bits of the digest.
        body.extend_from_slice(&[0x42, 0x42]);
        if version == 6 {
            let salt_size = hash_algo.salt_size().unwrap_or(16);
            body.push(salt_size as u8);
            body.extend(std::iter::repeat(0x42).take(salt_size));
        }
        let (a, b) = signature_size(pk_algo).unwrap_or((0, 64));
        body.extend(std::iter::repeat(0x42).take(a + b));

        // The packet header (RFC 9580, Section 4.2.1), using a
        // five-octet length.
        let mut packet = vec![0xc0 | 2, 0xff];
        packet.extend_from_slice(&(body.len() as u32).to_be_bytes());
        packet.extend_from_slice(&body);

        match Packet::from_bytes(&packet)? {
            Packet::Signature(sig) => {
                assert_eq!(sig.version(), version);
                assert_eq!(u8::from(sig.pk_algo()), pk_algo);
                assert_eq!(sig.hash_algo(), hash_algo);
                assert_eq!(sig.issuer_fingerprints().collect::<Vec<_>>(),
                           vec![issuer]);
                Ok(sig)
            },
            p => Err(anyhow::anyhow!("expected a signature, got: {:?}", p)),
        }
    }

    /// Returns a v4 key with the key material of the given key.
    ///
    /// For the signature algorithms of RFC 9980, this is a key that
    /// RFC 9980 forbids.  It makes v4 signatures.
    pub fn v4_key_with_material_of(key: &Key<SecretParts, PrimaryRole>)
                                   -> Result<Key<SecretParts, PrimaryRole>>
    {
        let secret = match key.secret() {
            SecretKeyMaterial::Unencrypted(u) => u.clone(),
            SecretKeyMaterial::Encrypted(_) =>
                return Err(anyhow::anyhow!("the secret key is encrypted")),
        };
        let key: Key<SecretParts, PrimaryRole> =
            Key4::with_secret(key.creation_time(), key.pk_algo(),
                              key.mpis().clone(), secret.into())?.into();
        assert_eq!(key.version(), 4);
        Ok(key)
    }
}
