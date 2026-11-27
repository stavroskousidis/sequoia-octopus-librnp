//! Keygrips.
//!
//! RNP identifies keys by their keygrip, and Thunderbird enumerates
//! its keyring by keygrip.  For the algorithms that GnuPG knows, the
//! keygrip is GnuPG's.  GnuPG does not define a keygrip for the
//! algorithms introduced by RFC 9580 and RFC 9980.  For those, RNP
//! uses the SHA-1 digest of the algorithm-specific part of the public
//! key, and so do we.
//!
//! The latter are identifiers for RNP's interface only.  We never
//! hand them to gpg-agent.

use sequoia_openpgp as openpgp;
use openpgp::{
    Result,
    crypto::mpi::PublicKey,
    types::HashAlgorithm,
};

use crate::Keygrip;

/// Computes the keygrip of the given public key.
///
/// For RSA, DSA, ElGamal, ECDH, ECDSA, and EdDSA keys, this is
/// GnuPG's keygrip.
///
/// For X25519, X448, Ed25519, and Ed448 keys (RFC 9580), and for
/// ML-DSA-65+Ed25519, ML-DSA-87+Ed448, SLH-DSA-SHAKE-128s,
/// SLH-DSA-SHAKE-128f, SLH-DSA-SHAKE-256s, ML-KEM-768+X25519, and
/// ML-KEM-1024+X448 keys (RFC 9980), this is the SHA-1 digest of the
/// algorithm-specific part of the public key, i.e. of the fixed-length
/// octet strings in the order that they appear in the key packet.
/// This is what RNP computes for these algorithms.
///
/// For all other keys, including those using an unknown algorithm,
/// this returns an error.
pub fn keygrip_of(key: &PublicKey) -> Result<Keygrip> {
    use PublicKey::*;

    // The fixed-length octet strings that make up the public key.
    let (a, b): (&[u8], &[u8]) = match key {
        // RFC 9580, Sections 5.5.5.7 to 5.5.5.10.
        X25519 { u } => (&u[..], &[]),
        X448 { u } => (&u[..], &[]),
        Ed25519 { a } => (&a[..], &[]),
        Ed448 { a } => (&a[..], &[]),

        // RFC 9980, Section 5.3.2.1.
        MLDSA65_Ed25519 { eddsa, mldsa } => (&eddsa[..], &mldsa[..]),
        MLDSA87_Ed448 { eddsa, mldsa } => (&eddsa[..], &mldsa[..]),

        // RFC 9980, Section 6.2.2.1.
        SLHDSA128s { public } => (&public[..], &[]),
        SLHDSA128f { public } => (&public[..], &[]),
        SLHDSA256s { public } => (&public[..], &[]),

        // RFC 9980, Section 4.3.2.1.
        MLKEM768_X25519 { ecdh, mlkem } => (&ecdh[..], &mlkem[..]),
        MLKEM1024_X448 { ecdh, mlkem } => (&ecdh[..], &mlkem[..]),

        // GnuPG's keygrip, or an error.
        _ => return Keygrip::of(key),
    };

    let mut hash = HashAlgorithm::SHA1.context()?.for_digest();
    hash.update(a);
    hash.update(b);
    openpgp::fmt::hex::encode(hash.into_digest()?).parse()
}

#[cfg(test)]
mod tests {
    use super::*;

    use openpgp::{
        cert::{CertBuilder, CipherSuite},
        crypto::mpi::MPI,
        types::PublicKeyAlgorithm,
    };

    use crate::testdata::rfc9980;

    /// For the algorithms that GnuPG knows, the keygrip is GnuPG's.
    #[test]
    fn gnupg_keygrips() -> Result<()> {
        for cs in [CipherSuite::Cv25519, CipherSuite::P256,
                   CipherSuite::RSA2k]
        {
            let (cert, _) = CertBuilder::general_purpose(Some("alice"))
                .set_profile(openpgp::Profile::RFC4880)?
                .set_cipher_suite(cs)
                .generate()?;
            assert!(cert.keys().count() > 1);
            for ka in cert.keys() {
                let mpis = ka.key().mpis();
                assert_eq!(keygrip_of(mpis)?, Keygrip::of(mpis)?);
            }
        }
        Ok(())
    }

    /// The keygrips of the keys in RFC 9980, Appendix A.
    ///
    /// This does not depend on whether the cryptographic backend
    /// supports the algorithms.
    #[test]
    fn rfc9980_keygrips() -> Result<()> {
        let mut seen = std::collections::BTreeSet::new();

        for v in rfc9980::VECTORS {
            let cert = v.cert();
            assert_eq!(cert.keys().count(), 2, "{}", v.section);

            for (ka, expected) in cert.keys().zip(v.keys()) {
                let key = ka.key();
                // Make sure that we test what we mean to test.
                assert_eq!(u8::from(key.pk_algo()), expected.algo,
                           "{}", v.section);
                assert_eq!(key.fingerprint().to_hex(), expected.fingerprint,
                           "{}", v.section);
                seen.insert(expected.algo);

                // GnuPG does not define a keygrip for these.
                assert!(Keygrip::of(key.mpis()).is_err(), "{}", v.section);

                assert_eq!(keygrip_of(key.mpis())?.to_string(),
                           expected.grip,
                           "{}", v.section);
            }
        }

        // All algorithms from RFC 9980, and Ed25519.
        assert_eq!(seen.into_iter().collect::<Vec<_>>(),
                   &[27, 30, 31, 32, 33, 34, 35, 36]);
        Ok(())
    }

    /// The keygrips of X25519, X448, Ed25519, and Ed448 keys, and the
    /// order in which the parts of a composite key are hashed.
    ///
    /// The public keys are not valid keys, and the expected values
    /// are the output of `sha1sum` over the octets.
    #[test]
    fn synthetic_keys() -> Result<()> {
        fn count<const N: usize>() -> [u8; N] {
            let mut a = [0; N];
            a.iter_mut().enumerate().for_each(|(i, b)| *b = i as u8 + 1);
            a
        }

        // The octets 1 to 32.
        const ONE_TO_32: &str = "4C9B68754CC4C6A52C2871B90740059372385833";
        // The octets 1 to 56.
        const ONE_TO_56: &str = "6BFA1EEC7D9A7AB597E60C981DD360FAE026B101";
        // The octets 1 to 57.
        const ONE_TO_57: &str = "B6B8D6783547990C2DED24CF476AB4324F5E9497";
        // 32 times the octet 1, followed by 1184 times the octet 2.
        const ONES_THEN_TWOS: &str =
            "8F1ED2D4E4BDD4E1866DE6994AFFDF9C51833B49";

        let grip = |key: PublicKey| -> Result<String> {
            assert!(Keygrip::of(&key).is_err());
            Ok(keygrip_of(&key)?.to_string())
        };

        assert_eq!(grip(PublicKey::X25519 { u: count() })?, ONE_TO_32);
        assert_eq!(grip(PublicKey::X448 { u: Box::new(count()) })?,
                   ONE_TO_56);
        assert_eq!(grip(PublicKey::Ed25519 { a: count() })?, ONE_TO_32);
        assert_eq!(grip(PublicKey::Ed448 { a: Box::new(count()) })?,
                   ONE_TO_57);

        // The elliptic curve part comes first.
        assert_eq!(grip(PublicKey::MLKEM768_X25519 {
            ecdh: Box::new([1; 32]),
            mlkem: Box::new([2; 1184]),
        })?, ONES_THEN_TWOS);
        Ok(())
    }

    /// Keys using an algorithm that we do not know have no keygrip.
    #[test]
    fn unknown_algorithm() {
        // 37 is not assigned by RFC 9580 or RFC 9980.
        assert!(matches!(PublicKeyAlgorithm::from(37),
                         PublicKeyAlgorithm::Unknown(37)));

        let key = PublicKey::Unknown {
            mpis: vec![MPI::new(&[1, 2, 3])].into_boxed_slice(),
            rest: vec![0x42; 64].into_boxed_slice(),
        };
        assert!(keygrip_of(&key).is_err());

        let key = PublicKey::Unknown {
            mpis: vec![].into_boxed_slice(),
            rest: vec![].into_boxed_slice(),
        };
        assert!(keygrip_of(&key).is_err());
    }
}
