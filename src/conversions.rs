use std::{
    ffi::{
        CStr,
    },
};

use libc::{
    c_char,
};

use sequoia_openpgp as openpgp;
use openpgp::{
    armor,
    KeyID,
    Fingerprint,
    KeyHandle,
    packet::{
        UserID,
    },
    types::{
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
    fn from_rnp_id(id: *const c_char) -> Result<Self>
        where Self: Sized;
}

impl ToRnpId for SymmetricAlgorithm {
    fn to_rnp_id(&self) -> &str {
        use SymmetricAlgorithm::*;
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
    fn from_rnp_id(id: *const c_char) -> Result<Self> {
        use SymmetricAlgorithm::*;
        let id = unsafe {
            CStr::from_ptr(id)
        };
        match &id.to_bytes().iter().map(u8::to_ascii_uppercase)
            .collect::<Vec<_>>()[..]
        {
            b"IDEA" => Ok(IDEA),
            b"TRIPLEDES" => Ok(TripleDES),
            b"CAST5" => Ok(CAST5),
            b"BLOWFISH" => Ok(Blowfish),
            b"AES128" => Ok(AES128),
            b"AES192" => Ok(AES192),
            b"AES256" => Ok(AES256),
            b"TWOFISH" => Ok(Twofish),
            b"CAMELLIA128" => Ok(Camellia128),
            b"CAMELLIA192" => Ok(Camellia192),
            b"CAMELLIA256" => Ok(Camellia256),
            b"SM4" => Err(RNP_ERROR_NOT_SUPPORTED),
            _ => {
                warn!("unknown symmetric algorithm: {:?}", id);
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
    fn from_rnp_id(id: *const c_char) -> Result<Self> {
        use PublicKeyAlgorithm::*;
        let id = unsafe {
            CStr::from_ptr(id)
        };
        match &id.to_bytes().iter().map(u8::to_ascii_uppercase)
            .collect::<Vec<_>>()[..]
        {
            b"RSA" =>     Ok(RSAEncryptSign),
            b"DSA" =>     Ok(DSA),
            b"ELGAMAL" => Ok(ElGamalEncrypt),
            b"ECDSA" =>   Ok(ECDSA),
            b"ECDH" =>    Ok(ECDH),
            b"EDDSA" =>   Ok(EdDSA),
            b"SM2" =>     Err(RNP_ERROR_NOT_SUPPORTED),
            _ => {
                warn!("unknown public key algorithm: {:?}", id);
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
    fn from_rnp_id(id: *const c_char) -> Result<Self> {
        use Curve::*;
        let id = unsafe {
            CStr::from_ptr(id)
        };
        match &id.to_bytes().iter().map(u8::to_ascii_uppercase)
            .collect::<Vec<_>>()[..]
        {
            b"NIST P-256" => Ok(NistP256),
            b"NIST P-384" => Ok(NistP384),
            b"NIST P-521" => Ok(NistP521),
            b"BRAINPOOLP256R1" => Ok(BrainpoolP256),
            b"BRAINPOOLP512R1" => Ok(BrainpoolP512),
            b"ED25519" => Ok(Ed25519),
            b"CURVE25519" => Ok(Cv25519),
            b"SECP256K1" => Err(RNP_ERROR_NOT_SUPPORTED),
            b"SM2 P-256" => Err(RNP_ERROR_NOT_SUPPORTED),
            _ => {
                warn!("unknown curve: {:?}", id);
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
    fn from_rnp_id(id: *const c_char) -> Result<Self> {
        use HashAlgorithm::*;
        let id = unsafe {
            CStr::from_ptr(id)
        };
        match &id.to_bytes().iter().map(u8::to_ascii_uppercase)
            .collect::<Vec<_>>()[..]
        {
            b"MD5" => Ok(MD5),
            b"SHA1" => Ok(SHA1),
            b"RIPEMD160" => Ok(RipeMD),
            b"SHA256" => Ok(SHA256),
            b"SHA384" => Ok(SHA384),
            b"SHA512" => Ok(SHA512),
            b"SHA224" => Ok(SHA224),
            b"SM3" => Err(RNP_ERROR_NOT_SUPPORTED),
           _ => {
                warn!("unknown hash algorithm: {:?}", id);
                Err(RNP_ERROR_BAD_PARAMETERS)
            },
        }
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
    fn from_rnp_id(id: *const c_char) -> Result<Self> {
        use armor::Kind::*;
        let id = unsafe {
            CStr::from_ptr(id)
        };
        match &id.to_bytes().iter().map(u8::to_ascii_uppercase)
            .collect::<Vec<_>>()[..]
        {
            b"MESSAGE" => Ok(Message),
            b"PUBLIC KEY" => Ok(PublicKey),
            b"SECRET KEY" => Ok(SecretKey),
            b"SIGNATURE" => Ok(Signature),
            _ => {
                warn!("unknown symmetric algorithm: {:?}", id);
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
    fn from_rnp_id(id: *const c_char) -> Result<Self> {
        use ReasonForRevocation::*;
        let id = unsafe {
            CStr::from_ptr(id)
        };
        match &id.to_bytes().iter().map(u8::to_ascii_uppercase)
            .collect::<Vec<_>>()[..]
        {
            b"NO" => Ok(Unspecified),
            b"SUPERSEDED" => Ok(KeySuperseded),
            b"COMPROMISED" => Ok(KeyCompromised),
            b"RETIRED" => Ok(KeyRetired),
            _ => {
                warn!("unknown reason for revocation: {:?}", id);
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
    fn from_rnp_id(id: *const c_char) -> Result<Self> {
        let id = unsafe {
            CStr::from_ptr(id)
        };
        match id.to_bytes() {
            b"userid" =>      Ok(RnpIdentifierType::UserID),
            b"keyid" =>       Ok(RnpIdentifierType::KeyID),
            b"fingerprint" => Ok(RnpIdentifierType::Fingerprint),
            b"grip" =>        Ok(RnpIdentifierType::Keygrip),
            _ => {
                warn!("unknown iterator typ: {:?}", id);
                Err(RNP_ERROR_BAD_PARAMETERS)
            },
        }
    }
}

impl RnpIdentifierType {
    pub fn with_identifier(&self, id: *const c_char) -> Result<RnpIdentifier> {
        let id = unsafe {
            CStr::from_ptr(id)
        };
        let id = match id.to_str() {
            Ok(v) => v,
            Err(e) => {
                warn!("conversion to string failed: {}", e);
                return Err(RNP_ERROR_BAD_PARAMETERS);
            },
        };

        Ok(match self {
            RnpIdentifierType::UserID =>
                RnpIdentifier::UserID(id.into()),
            RnpIdentifierType::KeyID =>
                RnpIdentifier::KeyID(
                    rnp_try_or!(id.parse(), Err(RNP_ERROR_BAD_PARAMETERS))),
            RnpIdentifierType::Fingerprint =>
                RnpIdentifier::Fingerprint(
                    rnp_try_or!(id.parse(), Err(RNP_ERROR_BAD_PARAMETERS))),
            RnpIdentifierType::Keygrip =>
                RnpIdentifier::Keygrip(
                    rnp_try_or!(id.parse(), Err(RNP_ERROR_BAD_PARAMETERS))),
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
    fn from_rnp_id(id: *const c_char) -> Result<Self> {
        let id = unsafe {
            CStr::from_ptr(id)
        };
        match id.to_bytes() {
            b"sign" =>         Ok(RnpKeyUsage::Sign),
            b"certify" =>      Ok(RnpKeyUsage::Certify),
            b"encrypt" =>      Ok(RnpKeyUsage::Encrypt),
            b"authenticate" => Ok(RnpKeyUsage::Authenticate),
            _ => {
                warn!("unknown usage: {:?}", id);
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
