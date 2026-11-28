//! Feature queries.
//!
//! RNP lets its user ask what the library supports, by feature type
//! and name: `rnp_supports_feature` answers for one name, and
//! `rnp_supported_features` lists the names.
//!
//! We answer for public key algorithms, with the names that
//! `rnp_key_get_alg` uses.  The answer is what the cryptographic
//! backend that we have been built with supports when we are asked:
//! for example, the OpenSSL backend supports the algorithms of RFC
//! 9980 only if OpenSSL does.  It says nothing about the policy.
//!
//! We do not answer for RNP's other feature types: asking about one
//! of them returns `RNP_ERROR_NOT_IMPLEMENTED`.

use libc::{
    c_char,
};

use sequoia_openpgp as openpgp;
use openpgp::types::PublicKeyAlgorithm;

use crate::{
    RnpResult,
    conversions::ToRnpId,
    error::*,
    security_rules::{
        RNP_FEATURE_AEAD_ALG,
        RNP_FEATURE_COMP_ALG,
        RNP_FEATURE_CURVE,
        RNP_FEATURE_HASH_ALG,
        RNP_FEATURE_PK_ALG,
        RNP_FEATURE_PROT_MODE,
        RNP_FEATURE_SYMM_ALG,
    },
    str_to_rnp_buffer,
};

/// RNP's feature types that we do not answer for.
const UNANSWERED_FEATURE_TYPES: &[&str] = &[
    RNP_FEATURE_SYMM_ALG,
    RNP_FEATURE_AEAD_ALG,
    RNP_FEATURE_PROT_MODE,
    RNP_FEATURE_HASH_ALG,
    RNP_FEATURE_COMP_ALG,
    RNP_FEATURE_CURVE,
];

/// The public key algorithms that we answer for, in the order in
/// which RNP lists them.
///
/// Their names are those of `ToRnpId`.  Where algorithms share a
/// name, this is the one that RNP asks about: RSA (Encrypt or Sign),
/// and ElGamal (Encrypt-Only).
#[allow(deprecated)]
const PUBLIC_KEY_ALGORITHMS: &[PublicKeyAlgorithm] = &[
    PublicKeyAlgorithm::RSAEncryptSign,
    PublicKeyAlgorithm::ElGamalEncrypt,
    PublicKeyAlgorithm::DSA,
    PublicKeyAlgorithm::ECDH,
    PublicKeyAlgorithm::ECDSA,
    PublicKeyAlgorithm::EdDSA,
    PublicKeyAlgorithm::Ed25519,
    PublicKeyAlgorithm::X25519,
    PublicKeyAlgorithm::Ed448,
    PublicKeyAlgorithm::X448,
    PublicKeyAlgorithm::MLKEM768_X25519,
    PublicKeyAlgorithm::MLKEM1024_X448,
    PublicKeyAlgorithm::MLDSA65_Ed25519,
    PublicKeyAlgorithm::MLDSA87_Ed448,
    PublicKeyAlgorithm::SLHDSA128f,
    PublicKeyAlgorithm::SLHDSA128s,
    PublicKeyAlgorithm::SLHDSA256s,
];

/// Returns the public key algorithm with the given name.
///
/// Like RNP, we ignore the case.
fn public_key_algorithm(name: &str) -> Option<PublicKeyAlgorithm> {
    PUBLIC_KEY_ALGORITHMS.iter()
        .find(|algo| algo.to_rnp_id().eq_ignore_ascii_case(name))
        .cloned()
}

/// Returns whether the named public key algorithm is supported.
///
/// An algorithm that we do not know is not supported.
fn supports_public_key_algorithm<F>(name: &str, supported: F) -> bool
    where F: Fn(PublicKeyAlgorithm) -> bool
{
    public_key_algorithm(name).map(supported).unwrap_or(false)
}

/// Returns the names of the supported public key algorithms.
fn supported_public_key_algorithms<F>(supported: F) -> Vec<&'static str>
    where F: Fn(PublicKeyAlgorithm) -> bool
{
    PUBLIC_KEY_ALGORITHMS.iter()
        .filter(|algo| supported(**algo))
        .map(|algo| algo.to_rnp_id())
        .collect()
}

/// Returns whether we support the named feature.
///
/// A public key algorithm that we do not know is not supported, this
/// is not an error.  A feature type that RNP does not know is one.
#[no_mangle] pub unsafe extern "C"
fn rnp_supports_feature(typ: *const c_char,
                        name: *const c_char,
                        supported: *mut bool)
                        -> RnpResult {
    rnp_function!(rnp_supports_feature, crate::TRACE);
    let typ = assert_str!(typ);
    let name = assert_str!(name);
    let supported = assert_ptr_mut!(supported);

    if typ.eq_ignore_ascii_case(RNP_FEATURE_PK_ALG) {
        *supported =
            supports_public_key_algorithm(name, |algo| algo.is_supported());
        rnp_success!()
    } else if UNANSWERED_FEATURE_TYPES.iter()
        .any(|t| typ.eq_ignore_ascii_case(t))
    {
        warn!("feature type {:?} is not implemented", typ);
        rnp_return_status!(RNP_ERROR_NOT_IMPLEMENTED)
    } else {
        warn!("unknown feature type: {:?}", typ);
        rnp_return_status!(RNP_ERROR_BAD_PARAMETERS)
    }
}

/// Returns the names of the supported features of the given type as
/// JSON array.
///
/// The caller must free the result using `rnp_buffer_destroy`.
#[no_mangle] pub unsafe extern "C"
fn rnp_supported_features(typ: *const c_char,
                          result: *mut *mut c_char)
                          -> RnpResult {
    rnp_function!(rnp_supported_features, crate::TRACE);
    let typ = assert_str!(typ);
    let result = assert_ptr_mut!(result);

    if typ.eq_ignore_ascii_case(RNP_FEATURE_PK_ALG) {
        let names =
            supported_public_key_algorithms(|algo| algo.is_supported());
        let json = rnp_try_or!(serde_json::to_string_pretty(&names),
                               RNP_ERROR_GENERIC);
        *result = str_to_rnp_buffer(json);
        rnp_success!()
    } else if UNANSWERED_FEATURE_TYPES.iter()
        .any(|t| typ.eq_ignore_ascii_case(t))
    {
        warn!("feature type {:?} is not implemented", typ);
        rnp_return_status!(RNP_ERROR_NOT_IMPLEMENTED)
    } else {
        warn!("unknown feature type: {:?}", typ);
        rnp_return_status!(RNP_ERROR_BAD_PARAMETERS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    use crate::testdata::rfc9980::backend_has_rfc9980;

    const RNP_SUCCESS: u32 = crate::error::RNP_SUCCESS.as_u32();
    const RNP_ERROR_BAD_PARAMETERS: u32 =
        crate::error::RNP_ERROR_BAD_PARAMETERS.as_u32();
    const RNP_ERROR_NOT_IMPLEMENTED: u32 =
        crate::error::RNP_ERROR_NOT_IMPLEMENTED.as_u32();
    const RNP_ERROR_NULL_POINTER: u32 =
        crate::error::RNP_ERROR_NULL_POINTER.as_u32();

    /// The names of the public key algorithms in RNP's interface in
    /// the order in which RNP lists them, and the algorithm that RNP
    /// asks about.
    const NAMES: &[(&str, u8)] = &[
        // RFC 9580, Section 9.1.
        ("RSA", 1),
        ("ELGAMAL", 16),
        ("DSA", 17),
        ("ECDH", 18),
        ("ECDSA", 19),
        ("EDDSA", 22),
        ("ED25519", 27),
        ("X25519", 25),
        ("ED448", 28),
        ("X448", 26),
        // RFC 9980, Section 2.1.
        ("ML-KEM-768+X25519", 35),
        ("ML-KEM-1024+X448", 36),
        ("ML-DSA-65+ED25519", 30),
        ("ML-DSA-87+ED448", 31),
        ("SLH-DSA-SHAKE-128f", 33),
        ("SLH-DSA-SHAKE-128s", 32),
        ("SLH-DSA-SHAKE-256s", 34),
    ];

    /// Names that are not the name of a public key algorithm that we
    /// know.
    const UNKNOWN_NAMES: &[&str] = &[
        "",
        " ",
        "unknown",
        "RSA ",
        " RSA",
        "RSA\n",
        "RSAA",
        "RS",
        "ML-KEM-768",
        "ML-KEM-768+X25519+",
        "ML-DSA-65",
        "SLH-DSA-SHAKE-192s",
        "SLH-DSA-SHAKE-256f",
        "SLH-DSA-SHA2-128s",
        // RNP knows it, and supports it if it is built with SM2.
        "SM2",
        // RNP's names for the algorithms of
        // draft-ietf-openpgp-nist-bp-comp.
        "ML-KEM-768+ECDH-P384",
        "ML-KEM-1024+ECDH-P521",
        "ML-KEM-768+ECDH-BP384",
        "ML-KEM-1024+ECDH-BP512",
        "ML-DSA-65+ECDSA-P384",
        "ML-DSA-87+ECDSA-P521",
        "ML-DSA-65+ECDSA-BP384",
        "ML-DSA-87+ECDSA-BP512",
        // Names of other feature types.
        "SHA256",
        "AES256",
        "Curve25519",
        "public key algorithm",
    ];

    /// The algorithms of RFC 9980, Section 2.1.
    const RFC9980_NAMES: &[&str] = &[
        "ML-DSA-65+ED25519",
        "ML-DSA-87+ED448",
        "SLH-DSA-SHAKE-128s",
        "SLH-DSA-SHAKE-128f",
        "SLH-DSA-SHAKE-256s",
        "ML-KEM-768+X25519",
        "ML-KEM-1024+X448",
    ];

    /// The feature types of RNP's interface other than the one for
    /// public key algorithms.
    const OTHER_FEATURE_TYPES: &[&str] = &[
        "symmetric algorithm",
        "aead algorithm",
        "protection mode",
        "hash algorithm",
        "compression algorithm",
        "elliptic curve",
    ];

    /// Things that are not a feature type.
    const UNKNOWN_FEATURE_TYPES: &[&str] = &[
        "",
        "public key algorithms",
        "public key algorithm ",
        "public  key algorithm",
        "public-key algorithm",
        "pk algorithm",
        "RSA",
        "v6",
        "pqc",
    ];

    /// Calls rnp_supports_feature.
    ///
    /// Makes sure that the function sets the result on success, and
    /// only then.
    fn supports(typ: &str, name: &str) -> std::result::Result<bool, u32> {
        let typ = CString::new(typ).unwrap();
        let name = CString::new(name).unwrap();
        let mut results = Vec::new();
        for initial in [false, true] {
            let mut supported = initial;
            let r = unsafe {
                rnp_supports_feature(typ.as_ptr(), name.as_ptr(),
                                     &mut supported as *mut _)
            };
            if r == RNP_SUCCESS {
                results.push(Ok(supported));
            } else {
                assert_eq!(supported, initial);
                results.push(Err(r));
            }
        }
        assert_eq!(results[0], results[1]);
        results[0]
    }

    /// Calls rnp_supported_features.  Returns the JSON.
    fn supported_json(typ: &str) -> std::result::Result<String, u32> {
        let typ = CString::new(typ).unwrap();
        let mut json: *mut c_char = std::ptr::null_mut();
        let r = unsafe {
            rnp_supported_features(typ.as_ptr(), &mut json as *mut *mut _)
        };
        if r != RNP_SUCCESS {
            assert!(json.is_null());
            return Err(r);
        }
        assert!(! json.is_null());
        let result = unsafe {
            std::ffi::CStr::from_ptr(json).to_str().unwrap().to_string()
        };
        unsafe { crate::buffer::rnp_buffer_destroy(json as *mut _) };
        Ok(result)
    }

    /// Calls rnp_supported_features.  Returns the names.
    fn supported(typ: &str) -> std::result::Result<Vec<String>, u32> {
        Ok(serde_json::from_str(&supported_json(typ)?).unwrap())
    }

    /// The names of the algorithms, and the algorithm that we ask
    /// about where algorithms share a name.
    #[test]
    fn public_key_algorithm_names() {
        for &(name, id) in NAMES {
            let algo = PublicKeyAlgorithm::from(id);
            assert_eq!(algo.to_rnp_id(), name);
            assert_eq!(public_key_algorithm(name), Some(algo), "{}", name);
            assert_eq!(public_key_algorithm(&name.to_lowercase()),
                       Some(algo), "{}", name);
            assert_eq!(public_key_algorithm(&name.to_uppercase()),
                       Some(algo), "{}", name);
        }

        for name in UNKNOWN_NAMES {
            assert_eq!(public_key_algorithm(name), None, "{:?}", name);
        }

        // We ignore the case like RNP does, which only considers
        // ASCII letters.  U+017F and U+212A are not ASCII letters,
        // but their uppercase and lowercase variants are.
        assert_eq!(public_key_algorithm("R\u{17f}A"), None);
        assert_eq!(public_key_algorithm("\u{212a}YBER"), None);

        // We answer for every algorithm that has a name, and for no
        // other.
        assert_eq!(PUBLIC_KEY_ALGORITHMS.len(), NAMES.len());
        for id in 0..=255 {
            let algo = PublicKeyAlgorithm::from(id);
            let name = algo.to_rnp_id();
            assert_eq!(name != "unknown",
                       NAMES.iter().any(|&(n, _)| n == name),
                       "algorithm {}", id);
            assert_eq!(PUBLIC_KEY_ALGORITHMS.contains(&algo),
                       NAMES.iter().any(|&(_, i)| i == id),
                       "algorithm {}", id);
        }
    }

    /// What we report depends on what is supported, and on nothing
    /// else.  This test does the same with every cryptographic
    /// backend.
    #[test]
    fn supported_public_key_algorithms_follow_the_backend() {
        let all: Vec<&str> = NAMES.iter().map(|&(name, _)| name).collect();

        // Everything is supported.
        assert_eq!(supported_public_key_algorithms(|_| true), all);
        for name in &all {
            assert!(supports_public_key_algorithm(name, |_| true));
        }
        for name in UNKNOWN_NAMES {
            assert!(! supports_public_key_algorithm(name, |_| true),
                    "{:?}", name);
        }

        // Nothing is supported.
        assert!(supported_public_key_algorithms(|_| false).is_empty());
        for name in &all {
            assert!(! supports_public_key_algorithm(name, |_| false));
        }

        // One algorithm is supported, or all but one.
        for id in 0..=255 {
            let algo = PublicKeyAlgorithm::from(id);
            let expected: Vec<&str> = NAMES.iter()
                .filter(|&&(_, i)| i == id)
                .map(|&(name, _)| name)
                .collect();
            assert!(expected.len() <= 1);

            assert_eq!(supported_public_key_algorithms(|a| a == algo),
                       expected, "algorithm {}", id);
            for name in &all {
                assert_eq!(supports_public_key_algorithm(name, |a| a == algo),
                           expected.contains(name),
                           "algorithm {}, {}", id, name);
            }

            let expected: Vec<&str> = NAMES.iter()
                .filter(|&&(_, i)| i != id)
                .map(|&(name, _)| name)
                .collect();
            assert_eq!(supported_public_key_algorithms(|a| a != algo),
                       expected, "algorithm {}", id);
            for name in &all {
                assert_eq!(supports_public_key_algorithm(name, |a| a != algo),
                           expected.contains(name),
                           "algorithm {}, {}", id, name);
            }
        }

        // The algorithms of RFC 9980 are supported, and no other, as
        // if the backend only had these.
        let rfc9980 = |a: PublicKeyAlgorithm| (30..=36).contains(&u8::from(a));
        assert_eq!(supported_public_key_algorithms(rfc9980),
                   &["ML-KEM-768+X25519", "ML-KEM-1024+X448",
                     "ML-DSA-65+ED25519", "ML-DSA-87+ED448",
                     "SLH-DSA-SHAKE-128f", "SLH-DSA-SHAKE-128s",
                     "SLH-DSA-SHAKE-256s"]);
        for name in &all {
            assert_eq!(supports_public_key_algorithm(name, rfc9980),
                       RFC9980_NAMES.contains(name), "{}", name);
        }

        // And the other way around, like a backend without them.
        let classic = |a: PublicKeyAlgorithm| ! rfc9980(a);
        assert_eq!(supported_public_key_algorithms(classic),
                   &["RSA", "ELGAMAL", "DSA", "ECDH", "ECDSA", "EDDSA",
                     "ED25519", "X25519", "ED448", "X448"]);
        for name in &all {
            assert_eq!(supports_public_key_algorithm(name, classic),
                       ! RFC9980_NAMES.contains(name), "{}", name);
        }
    }

    /// rnp_supports_feature for public key algorithms.
    #[test]
    fn supports_feature() {
        // What we report is what the cryptographic backend supports.
        for &(name, id) in NAMES {
            let expected = PublicKeyAlgorithm::from(id).is_supported();
            assert_eq!(supports("public key algorithm", name), Ok(expected),
                       "{}", name);
            // The case does not matter.
            assert_eq!(supports("Public Key Algorithm",
                                &name.to_lowercase()),
                       Ok(expected), "{}", name);
            assert_eq!(supports("PUBLIC KEY ALGORITHM",
                                &name.to_uppercase()),
                       Ok(expected), "{}", name);
        }

        // Every backend supports RSA.
        assert_eq!(supports("public key algorithm", "RSA"), Ok(true));
        assert_eq!(supports("public key algorithm", "rsa"), Ok(true));

        // An algorithm that we do not know is not supported.  This
        // is not an error.
        for name in UNKNOWN_NAMES {
            assert_eq!(supports("public key algorithm", name), Ok(false),
                       "{:?}", name);
        }
    }

    /// What rnp_supports_feature and rnp_supported_features report
    /// for the algorithms of RFC 9980.
    ///
    /// With the cryptographic backends of which we know whether they
    /// support the algorithms, we check that we report that.
    #[test]
    fn rfc9980_algorithms() {
        let listed = supported("public key algorithm").unwrap();
        let expected = backend_has_rfc9980();

        for name in RFC9980_NAMES {
            let supported = supports("public key algorithm", name).unwrap();
            assert_eq!(listed.iter().any(|n| n == name), supported,
                       "{}", name);
            if let Some(expected) = expected {
                assert_eq!(supported, expected,
                           "{} with {}", name, openpgp::crypto::backend());
            }
        }
    }

    /// rnp_supported_features for public key algorithms.
    #[test]
    fn supported_features() {
        let listed = supported("public key algorithm").unwrap();

        // We list exactly what rnp_supports_feature reports as
        // supported, in RNP's order.
        let expected: Vec<&str> = NAMES.iter()
            .map(|&(name, _)| name)
            .filter(|name| {
                supports("public key algorithm", name).unwrap()
            })
            .collect();
        assert_eq!(listed, expected);

        // Every backend supports RSA.
        assert_eq!(listed[0], "RSA");

        // The case of the type does not matter.
        assert_eq!(supported("Public Key Algorithm").unwrap(), listed);
        assert_eq!(supported("PUBLIC KEY ALGORITHM").unwrap(), listed);

        // The result is a JSON array of strings, one per line.
        let json = supported_json("public key algorithm").unwrap();
        let lines: Vec<String> = std::iter::once("[".to_string())
            .chain(listed.iter().enumerate().map(|(i, name)| {
                format!("  {:?}{}", name,
                        if i + 1 < listed.len() { "," } else { "" })
            }))
            .chain(std::iter::once("]".to_string()))
            .collect();
        assert_eq!(json, lines.join("\n"));
    }

    /// Feature types that we do not answer for, and feature types
    /// that do not exist.
    #[test]
    fn feature_types() {
        for typ in OTHER_FEATURE_TYPES {
            for typ in [typ.to_string(), typ.to_uppercase()] {
                assert_eq!(supports(&typ, "RSA"),
                           Err(RNP_ERROR_NOT_IMPLEMENTED), "{:?}", typ);
                assert_eq!(supports(&typ, "SHA256"),
                           Err(RNP_ERROR_NOT_IMPLEMENTED), "{:?}", typ);
                assert_eq!(supported(&typ),
                           Err(RNP_ERROR_NOT_IMPLEMENTED), "{:?}", typ);
            }
        }

        for typ in UNKNOWN_FEATURE_TYPES {
            assert_eq!(supports(typ, "RSA"),
                       Err(RNP_ERROR_BAD_PARAMETERS), "{:?}", typ);
            assert_eq!(supported(typ),
                       Err(RNP_ERROR_BAD_PARAMETERS), "{:?}", typ);
        }
    }

    /// NULL pointers, and strings that are not UTF-8.
    #[test]
    fn bad_arguments() {
        let typ = CString::new("public key algorithm").unwrap();
        let name = CString::new("RSA").unwrap();
        let not_utf8 = CString::new(&b"RSA\xff"[..]).unwrap();

        for initial in [false, true] {
            let mut supported = initial;
            let r = unsafe {
                rnp_supports_feature(std::ptr::null(), name.as_ptr(),
                                     &mut supported as *mut _)
            };
            assert_eq!(r, RNP_ERROR_NULL_POINTER);
            assert_eq!(supported, initial);

            let r = unsafe {
                rnp_supports_feature(typ.as_ptr(), std::ptr::null(),
                                     &mut supported as *mut _)
            };
            assert_eq!(r, RNP_ERROR_NULL_POINTER);
            assert_eq!(supported, initial);

            // RNP compares bytes and reports that such an algorithm
            // is not supported.  We say that it is not a name.
            let r = unsafe {
                rnp_supports_feature(typ.as_ptr(), not_utf8.as_ptr(),
                                     &mut supported as *mut _)
            };
            assert_eq!(r, RNP_ERROR_BAD_PARAMETERS);
            assert_eq!(supported, initial);

            let r = unsafe {
                rnp_supports_feature(not_utf8.as_ptr(), name.as_ptr(),
                                     &mut supported as *mut _)
            };
            assert_eq!(r, RNP_ERROR_BAD_PARAMETERS);
            assert_eq!(supported, initial);
        }

        let r = unsafe {
            rnp_supports_feature(typ.as_ptr(), name.as_ptr(),
                                 std::ptr::null_mut())
        };
        assert_eq!(r, RNP_ERROR_NULL_POINTER);

        let mut json: *mut c_char = std::ptr::null_mut();
        let r = unsafe {
            rnp_supported_features(std::ptr::null(),
                                   &mut json as *mut *mut _)
        };
        assert_eq!(r, RNP_ERROR_NULL_POINTER);
        assert!(json.is_null());

        let r = unsafe {
            rnp_supported_features(not_utf8.as_ptr(),
                                   &mut json as *mut *mut _)
        };
        assert_eq!(r, RNP_ERROR_BAD_PARAMETERS);
        assert!(json.is_null());

        let r = unsafe {
            rnp_supported_features(typ.as_ptr(), std::ptr::null_mut())
        };
        assert_eq!(r, RNP_ERROR_NULL_POINTER);
    }
}
