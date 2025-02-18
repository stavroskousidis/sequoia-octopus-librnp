use sequoia_openpgp as openpgp;
use openpgp::{
    armor,
    KeyID,
    Fingerprint,
    KeyHandle,
    packet::{
        UserID,
    },
    policy::AsymmetricAlgorithm,
    types::{
        AEADAlgorithm,
        Curve,
        HashAlgorithm,
        SymmetricAlgorithm,
        PublicKeyAlgorithm,
        ReasonForRevocation,
        KeyFlags,
    }
};

use crate::{
    Keygrip,
    error::*,
};

pub trait ToRnpId {
    fn to_rnp_id(&self) -> &str;
}

pub trait FromRnpId {
    fn from_rnp_id(id: &str) -> Result<Self>
        where Self: Sized;
}

impl ToRnpId for SymmetricAlgorithm {
    fn to_rnp_id(&self) -> &str {
        use SymmetricAlgorithm::*;
        #[allow(deprecated)]
        match self {
            Unencrypted => "PLAINTEXT",
            IDEA => "IDEA",
            TripleDES => "TRIPLEDES",
            CAST5 => "CAST5",
            Blowfish => "BLOWFISH",
            AES128 => "AES128",
            AES192 => "AES192",
            AES256 => "AES256",
            Twofish => "TWOFISH",
            Camellia128 => "CAMELLIA128",
            Camellia192 => "CAMELLIA192",
            Camellia256 => "CAMELLIA256",
            _ => "unknown",
        }
    }
}

impl FromRnpId for SymmetricAlgorithm {
    fn from_rnp_id(id: &str) -> Result<Self> {
        use SymmetricAlgorithm::*;
        #[allow(deprecated)]
        match id.to_uppercase().as_str() {
            "IDEA" => Ok(IDEA),
            "TRIPLEDES" => Ok(TripleDES),
            "CAST5" => Ok(CAST5),
            "BLOWFISH" => Ok(Blowfish),
            "AES128" => Ok(AES128),
            "AES192" => Ok(AES192),
            "AES256" => Ok(AES256),
            "TWOFISH" => Ok(Twofish),
            "CAMELLIA128" => Ok(Camellia128),
            "CAMELLIA192" => Ok(Camellia192),
            "CAMELLIA256" => Ok(Camellia256),
            "SM4" => Err(RNP_ERROR_NOT_SUPPORTED),
            _ => {
                global_warn!("unknown symmetric algorithm: {:?}", id);
                Err(RNP_ERROR_BAD_PARAMETERS)
            },
        }
    }
}

impl FromRnpId for Option<AEADAlgorithm> {
    fn from_rnp_id(id: &str) -> Result<Self> {
        use AEADAlgorithm::*;
        match id.to_uppercase().as_str() {
            "NONE" => Ok(None),
            "EAX" => Ok(Some(EAX)),
            "OCB" => Ok(Some(OCB)),
            _ => {
                global_warn!("unknown AEAD algorithm: {:?}", id);
                Err(RNP_ERROR_BAD_PARAMETERS)
            },
        }
    }
}

impl ToRnpId for PublicKeyAlgorithm {
    fn to_rnp_id(&self) -> &str {
        use PublicKeyAlgorithm::*;
        #[allow(deprecated)]
        match self {
            RSAEncryptSign => "RSA",
            RSAEncrypt => "RSA",
            RSASign => "RSA",
            ElGamalEncrypt => "ELGAMAL",
            DSA => "DSA",
            ECDH => "ECDH",
            ECDSA => "ECDSA",
            ElGamalEncryptSign => "ELGAMAL",
            EdDSA => "EDDSA",
            _ => "unknown",
        }
    }
}

impl FromRnpId for PublicKeyAlgorithm {
    fn from_rnp_id(id: &str) -> Result<Self> {
        use PublicKeyAlgorithm::*;
        #[allow(deprecated)]
        match id.to_uppercase().as_str() {
            "RSA" =>     Ok(RSAEncryptSign),
            "DSA" =>     Ok(DSA),
            "ELGAMAL" => Ok(ElGamalEncrypt),
            "ECDSA" =>   Ok(ECDSA),
            "ECDH" =>    Ok(ECDH),
            "EDDSA" =>   Ok(EdDSA),
            "SM2" =>     Err(RNP_ERROR_NOT_SUPPORTED),
            _ => {
                global_warn!("unknown public key algorithm: {:?}", id);
                Err(RNP_ERROR_BAD_PARAMETERS)
            },
        }
    }
}

impl ToRnpId for Curve {
    fn to_rnp_id(&self) -> &str {
        use Curve::*;
        match self {
            NistP256 => "NIST P-256",
            NistP384 => "NIST P-384",
            NistP521 => "NIST P-521",
            BrainpoolP256 => "brainpoolP256r1",
            BrainpoolP512 => "brainpoolP512r1",
            Ed25519 => "Ed25519",
            Cv25519 => "Curve25519",
            _ => "unknown",
        }
    }
}

impl FromRnpId for Curve {
    fn from_rnp_id(id: &str) -> Result<Self> {
        use Curve::*;
        match id.to_uppercase().as_str() {
            "NIST P-256" => Ok(NistP256),
            "NIST P-384" => Ok(NistP384),
            "NIST P-521" => Ok(NistP521),
            "BRAINPOOLP256R1" => Ok(BrainpoolP256),
            "BRAINPOOLP512R1" => Ok(BrainpoolP512),
            "ED25519" => Ok(Ed25519),
            "CURVE25519" => Ok(Cv25519),
            "SECP256K1" => Err(RNP_ERROR_NOT_SUPPORTED),
            "SM2" => Err(RNP_ERROR_NOT_SUPPORTED),
            _ => {
                global_warn!("unknown curve: {:?}", id);
                Err(RNP_ERROR_BAD_PARAMETERS)
            },
        }
    }
}

impl ToRnpId for HashAlgorithm {
    fn to_rnp_id(&self) -> &str {
        use HashAlgorithm::*;
        match self {
            MD5 => "MD5",
            SHA1 => "SHA1",
            RipeMD => "RIPEMD160",
            SHA256 => "SHA256",
            SHA384 => "SHA384",
            SHA512 => "SHA512",
            SHA224 => "SHA224",
            _ => "unknown",
        }
    }
}

impl FromRnpId for HashAlgorithm {
    fn from_rnp_id(id: &str) -> Result<Self> {
        use HashAlgorithm::*;
        match id.to_uppercase().as_str() {
            "MD5" => Ok(MD5),
            "SHA1" => Ok(SHA1),
            "RIPEMD160" => Ok(RipeMD),
            "SHA256" => Ok(SHA256),
            "SHA384" => Ok(SHA384),
            "SHA512" => Ok(SHA512),
            "SHA224" => Ok(SHA224),
            "SM3" => Err(RNP_ERROR_NOT_SUPPORTED),
            _ => {
                global_warn!("unknown hash algorithm: {:?}", id);
                Err(RNP_ERROR_BAD_PARAMETERS)
            },
        }
    }
}

/// Extensions for AsymmetricAlgorihm.
pub trait AsymmetricAlgorithmExt {
    /// Returns all AsymmetricAlgorithms matching the given RNP name.
    ///
    /// AsymmetricAlgorithm is more fine-grained as it includes the
    /// key length.  To compensate, we return all RSA values here,
    /// with the most appropriate representative as the first value.
    fn all_from_rnp_id(id: &str) -> Result<Vec<AsymmetricAlgorithm>> {
        use AsymmetricAlgorithm::*;
        match id.to_uppercase().as_str() {
            "RSA" => Ok(vec![RSA2048, RSA1024, RSA3072, RSA4096]),
            "ELGAMAL" =>
                Ok(vec![ElGamal2048, ElGamal1024, ElGamal3072, ElGamal4096]),
            "DSA" => Ok(vec![DSA2048, DSA1024, DSA3072, DSA4096]),
            "SM2" => Ok(vec![]),
            // XXX: Add more algorithms as more RNP_ALGNAME_* symbols
            // are added.
            _ => {
                global_warn!("unknown symmetric algorithm: {:?}", id);
                Err(RNP_ERROR_BAD_PARAMETERS)
            },
        }
    }
}

impl AsymmetricAlgorithmExt for AsymmetricAlgorithm {}

impl FromRnpId for AsymmetricAlgorithm {
    fn from_rnp_id(id: &str) -> Result<Self> {
        Self::all_from_rnp_id(id)?.get(0).cloned()
            .ok_or(RNP_ERROR_NOT_SUPPORTED)
    }
}

impl ToRnpId for armor::Kind {
    fn to_rnp_id(&self) -> &str {
        use armor::Kind::*;
        match self {
            Message => "message",
            PublicKey => "public key",
            SecretKey => "secret key",
            Signature => "signature",
            _ => "unknown",
        }
    }
}

impl FromRnpId for armor::Kind {
    fn from_rnp_id(id: &str) -> Result<Self> {
        use armor::Kind::*;
        match id.to_uppercase().as_str() {
            "MESSAGE" => Ok(Message),
            "PUBLIC KEY" => Ok(PublicKey),
            "SECRET KEY" => Ok(SecretKey),
            "SIGNATURE" => Ok(Signature),
            _ => {
                global_warn!("unknown symmetric algorithm: {:?}", id);
                Err(RNP_ERROR_BAD_PARAMETERS)
            },
        }
    }
}

impl ToRnpId for ReasonForRevocation {
    fn to_rnp_id(&self) -> &str {
        use ReasonForRevocation::*;
        match self {
            Unspecified => "no",
            KeySuperseded => "superseded",
            KeyCompromised => "compromised",
            KeyRetired => "retired",
            UIDRetired => "uid retired", // XXX: RNP doesn't support that afaics
            _ => "unknown",
        }
    }
}

impl FromRnpId for ReasonForRevocation {
    fn from_rnp_id(id: &str) -> Result<Self> {
        use ReasonForRevocation::*;
        match id.to_uppercase().as_str() {
            "NO" => Ok(Unspecified),
            "SUPERSEDED" => Ok(KeySuperseded),
            "COMPROMISED" => Ok(KeyCompromised),
            "RETIRED" => Ok(KeyRetired),
            _ => {
                global_warn!("unknown reason for revocation: {:?}", id);
                Err(RNP_ERROR_BAD_PARAMETERS)
            },
        }
    }
}

#[derive(Debug)]
pub enum RnpIdentifierType {
    UserID,
    KeyID,
    Fingerprint,
    Keygrip,
}

impl FromRnpId for RnpIdentifierType {
    fn from_rnp_id(id: &str) -> Result<Self> {
        match id {
            "userid" =>      Ok(RnpIdentifierType::UserID),
            "keyid" =>       Ok(RnpIdentifierType::KeyID),
            "fingerprint" => Ok(RnpIdentifierType::Fingerprint),
            "grip" =>        Ok(RnpIdentifierType::Keygrip),
            _ => {
                global_warn!("unknown iterator typ: {:?}", id);
                Err(RNP_ERROR_BAD_PARAMETERS)
            },
        }
    }
}

impl RnpIdentifierType {
    pub fn with_identifier(&self, id: &str) -> Result<RnpIdentifier> {
        Ok(match self {
            RnpIdentifierType::UserID =>
                RnpIdentifier::UserID(id.into()),
            RnpIdentifierType::KeyID =>
                RnpIdentifier::KeyID(
                    global_rnp_try_or!(id.parse(), Err(RNP_ERROR_BAD_PARAMETERS))),
            RnpIdentifierType::Fingerprint =>
                RnpIdentifier::Fingerprint(
                    global_rnp_try_or!(id.parse(), Err(RNP_ERROR_BAD_PARAMETERS))),
            RnpIdentifierType::Keygrip =>
                RnpIdentifier::Keygrip(
                    global_rnp_try_or!(id.parse(), Err(RNP_ERROR_BAD_PARAMETERS))),
        })
    }
}

#[derive(Debug)]
pub enum RnpIdentifier {
    UserID(UserID),
    KeyID(KeyID),
    Fingerprint(Fingerprint),
    Keygrip(Keygrip),
}

impl From<KeyHandle> for RnpIdentifier {
    fn from(h: KeyHandle) -> Self {
        match h {
            KeyHandle::KeyID(i) => RnpIdentifier::KeyID(i),
            KeyHandle::Fingerprint(i) => RnpIdentifier::Fingerprint(i),
        }
    }
}

impl From<&KeyHandle> for RnpIdentifier {
    fn from(h: &KeyHandle) -> Self {
        match h {
            KeyHandle::KeyID(i) => RnpIdentifier::KeyID(i.clone()),
            KeyHandle::Fingerprint(i) => RnpIdentifier::Fingerprint(i.clone()),
        }
    }
}

#[derive(Debug)]
pub enum RnpKeyUsage {
    Sign,
    Certify,
    Encrypt,
    Authenticate,
}

impl FromRnpId for RnpKeyUsage {
    fn from_rnp_id(id: &str) -> Result<Self> {
        match id {
            "sign" =>         Ok(RnpKeyUsage::Sign),
            "certify" =>      Ok(RnpKeyUsage::Certify),
            "encrypt" =>      Ok(RnpKeyUsage::Encrypt),
            "authenticate" => Ok(RnpKeyUsage::Authenticate),
            _ => {
                global_warn!("unknown usage: {:?}", id);
                Err(RNP_ERROR_BAD_PARAMETERS)
            },
        }
    }
}

impl RnpKeyUsage {
    pub fn to_keyflags(&self) -> KeyFlags {
        use RnpKeyUsage::*;
        match self {
            Sign => KeyFlags::empty().set_signing(),
            Certify => KeyFlags::empty().set_certification(),
            Encrypt => KeyFlags::empty().set_transport_encryption()
                .set_storage_encryption(),
            Authenticate => KeyFlags::empty().set_authentication(),
        }
    }
}
