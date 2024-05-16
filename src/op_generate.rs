use std::{
    time,
};

use libc::{
    c_char,
};

use sequoia_openpgp as openpgp;
use openpgp::{
    Fingerprint,
    crypto::{
        Password,
    },
    cert::{
        CertBuilder,
        CipherSuite,
    },
    packet::{
        Packet,
        UserID,
        Key,
        key::{
            Key4,
            UnspecifiedParts,
            UnspecifiedRole,
        },
        signature::{
            SignatureBuilder,
        },
    },
    types::{
        Curve,
        KeyFlags,
        PublicKeyAlgorithm,
        SignatureType,
    },
};

use crate::{
    RnpContext,
    RnpResult,
    RnpPasswordFor,
    cstr_to_str,
    conversions::FromRnpId,
    key::RnpKey,
    error::*,
};

pub struct RnpOpGenerate<'a> {
    ctx: &'a mut RnpContext,
    mode: Mode,
    pk_algo: PublicKeyAlgorithm,
    curve: Option<Curve>,
    bits: Option<u32>,
    password: Option<Password>,
    expiration: Option<time::Duration>,
}

enum Mode {
    PrimaryKey {
        userids: Vec<UserID>,
    },
    SubKey {
        primary: Fingerprint,
    },
    Generated {
        key: Key<UnspecifiedParts, UnspecifiedRole>,
    },
}

#[no_mangle] pub unsafe extern "C"
fn rnp_op_generate_create(op: *mut *mut RnpOpGenerate,
                          ctx: *mut RnpContext,
                          alg: *const c_char)
                          -> RnpResult
{
    rnp_function!(rnp_op_generate_create, crate::TRACE);
    let op = assert_ptr_mut!(op);
    let ctx = assert_ptr_mut!(ctx);
    assert_str!(alg);

    let pk_algo = rnp_try!(PublicKeyAlgorithm::from_rnp_id(alg));
    use PublicKeyAlgorithm::*;
    match pk_algo {
        RSAEncryptSign | DSA | ECDSA | EdDSA => (), // Ok.
        _ => {
            warn!("public key algorithm unsupported or not signing-capable: {}",
                  pk_algo);
            rnp_return_status!(RNP_ERROR_BAD_PARAMETERS);
        },
    }

    *op = Box::into_raw(Box::new(RnpOpGenerate {
        ctx,
        mode: Mode::PrimaryKey {
            userids: Vec::new(),
        },
        pk_algo,
        curve: None,
        bits: None,
        password: None,
        expiration: None,
    }));
    rnp_success!()
}

#[no_mangle] pub unsafe extern "C"
fn rnp_op_generate_subkey_create(op: *mut *mut RnpOpGenerate,
                                 ctx: *mut RnpContext,
                                 primary: *const RnpKey,
                                 alg: *const c_char)
                                 -> RnpResult
{
    rnp_function!(rnp_op_generate_subkey_create, crate::TRACE);
    let op = assert_ptr_mut!(op);
    let ctx = assert_ptr_mut!(ctx);
    let primary = assert_ptr_ref!(primary);
    assert_str!(alg);

    let pk_algo = rnp_try!(PublicKeyAlgorithm::from_rnp_id(alg));
    *op = Box::into_raw(Box::new(RnpOpGenerate {
        ctx: &mut *ctx,
        mode: Mode::SubKey {
            primary: (*primary).fingerprint(),
        },
        pk_algo,
        curve: None,
        bits: None,
        password: None,
        expiration: None,
    }));
    rnp_success!()
}

#[no_mangle] pub unsafe extern "C"
fn rnp_op_generate_destroy(op: *mut RnpOpGenerate) -> RnpResult {
    rnp_function!(rnp_op_generate_destroy, crate::TRACE);
    arg!(op);

    if ! op.is_null() {
        drop(Box::from_raw(op));
    }
    rnp_success!()
}

#[no_mangle] pub unsafe extern "C"
fn rnp_op_generate_execute(op: *mut RnpOpGenerate) -> RnpResult {
    rnp_function!(rnp_op_generate_execute, crate::TRACE);
    let op = assert_ptr_mut!(op);

    fn f(op: &mut RnpOpGenerate) -> openpgp::Result<()> {
        let generated_key;

        match &op.mode {
            Mode::PrimaryKey { userids } => {
                use PublicKeyAlgorithm::*;
                use CipherSuite::*;
                use Curve::*;
                let cs = match op.pk_algo {
                    RSAEncryptSign => match op.bits {
                        None => RSA3k,
                        Some(n) if n <= 2048 => RSA2k,
                        Some(n) if n <= 3072 => RSA3k,
                        _ => RSA4k,
                    },
                    ECDSA => match op.curve {
                        None => P256,
                        Some(NistP256) => P256,
                        Some(NistP384) => P384,
                        Some(NistP521) => P521,
                        Some(_) =>
                        // XXX: we could support more exotic curves here
                            return Err(anyhow::anyhow!("not supported")),
                    },
                    EdDSA => CipherSuite::Cv25519,
                    _ => return Err(anyhow::anyhow!("not a suitable algorithm")),
                };

                let mut builder = CertBuilder::new()
                    .set_cipher_suite(cs)
                    .set_primary_key_flags(KeyFlags::empty()
                                           .set_signing().set_certification())
                    .set_password(op.password.clone())
                    .set_validity_period(op.expiration);

                for u in userids {
                    builder = builder.add_userid(u.clone());
                }

                let (cert, _) = builder.generate()?;
                generated_key = cert.primary_key().key().clone()
                    .parts_into_unspecified()
                    .role_into_unspecified();
                op.ctx.certs.write().insert(cert);
            },
            Mode::SubKey { primary } => {
                use PublicKeyAlgorithm::*;
                let mut key = Key::from(match op.pk_algo {
                    RSAEncryptSign => {
                        let bits = match op.bits {
                            None => 3072,
                            Some(n) if n <= 2048 => 2048,
                            Some(n) if n <= 3072 => 3072,
                            _ => 4096,
                        };
                        Key4::generate_rsa(bits)?
                    },
                    ECDH =>
                        Key4::generate_ecc(
                            false,
                            op.curve.take().unwrap_or(Curve::Cv25519))?,
                    _ => return Err(anyhow::anyhow!("not a suitable algorithm")),
                });

                if let Some(p) = op.password.as_ref() {
                    key = key.encrypt_secret(p)?;
                }

                // We don't want to (and actually can't) hold the key
                // store lock around the decrypt_key_for: if we prompt
                // the user for a password, it could take a while.
                let cert = op.ctx.certs.read().by_primary_fp(primary)
                    .ok_or_else(|| anyhow::anyhow!("key not found"))?
                    .clone();
                let primary_key = cert.primary_key().key().clone()
                    .role_into_unspecified()
                    .parts_into_secret()?;

                let primary_key = op.ctx.decrypt_key_for(
                    Some(&cert),
                    primary_key,
                    RnpPasswordFor::AddSubkey)?;

                let mut signer = primary_key.into_keypair()?;
                let binding = key.bind(
                    &mut signer, &cert,
                    SignatureBuilder::new(SignatureType::SubkeyBinding)
                        .set_key_flags(KeyFlags::empty()
                                       .set_storage_encryption()
                                       .set_transport_encryption())?
                        .set_key_validity_period(op.expiration)?)?;

                op.ctx.certs.write()
                    .insert(cert.insert_packets(vec![Packet::from(key.clone()),
                                                     binding.into()])?);
                generated_key =
                    key.parts_into_unspecified().role_into_unspecified();
            },
            Mode::Generated { .. } => {
                return Err(anyhow::anyhow!("key already generated"));
            },
        }

        op.mode = Mode::Generated { key: generated_key, };
        Ok(())
    }

    rnp_return_status!(if let Err(e) = f(&mut *op) {
        log!("sequoia-octopus: failed to generate key: {}", e);
        RNP_ERROR_GENERIC
    } else {
        RNP_SUCCESS
    })
}

#[no_mangle] pub unsafe extern "C"
fn rnp_op_generate_get_key(op: *mut RnpOpGenerate,
                           key: *mut *mut RnpKey)
                           -> RnpResult {
    rnp_function!(rnp_op_generate_get_key, crate::TRACE);
    let op = assert_ptr_mut!(op);
    let key = assert_ptr_mut!(key);
    let key_out = key;

    rnp_return_status!(match &op.mode {
        Mode::Generated { key } => {
            *key_out =
                Box::into_raw(Box::new(RnpKey::without_cert(op.ctx, key.clone())));
            RNP_SUCCESS
        },
        _ => RNP_ERROR_BAD_PARAMETERS,
    })
}

#[no_mangle] pub unsafe extern "C"
fn rnp_op_generate_set_protection_password(op: *mut RnpOpGenerate,
                                           password: *const c_char)
                                           -> RnpResult {
    rnp_function!(rnp_op_generate_set_protection_password, crate::TRACE);
    let op = assert_ptr_mut!(op);
    assert_ptr!(password);
    (*op).password = Some(rnp_try!(cstr_to_str(password)).to_string().into());
    rnp_success!()
}

#[no_mangle] pub unsafe extern "C"
fn rnp_op_generate_set_userid(op: *mut RnpOpGenerate,
                              userid: *const c_char)
                              -> RnpResult {
    rnp_function!(rnp_op_generate_set_userid, crate::TRACE);
    let op = assert_ptr_mut!(op);
    let userid = assert_str!(userid);

    rnp_return_status!(match (*op).mode {
        Mode::PrimaryKey { ref mut userids } => {
            userids.push(userid.into());
            RNP_SUCCESS
        },
        _ => RNP_ERROR_BAD_PARAMETERS,
    })
}

#[no_mangle] pub unsafe extern "C"
fn rnp_op_generate_set_bits(op: *mut RnpOpGenerate,
                            bits: u32)
                            -> RnpResult {
    rnp_function!(rnp_op_generate_set_bits, crate::TRACE);
    let op = assert_ptr_mut!(op);
    arg!(bits);
    (*op).bits = Some(bits);
    rnp_success!()
}

#[no_mangle] pub unsafe extern "C"
fn rnp_op_generate_set_curve(op: *mut RnpOpGenerate,
                             curve: *const c_char)
                            -> RnpResult {
    rnp_function!(rnp_op_generate_set_curve, crate::TRACE);
    let op = assert_ptr_mut!(op);
    assert_str!(curve);
    (*op).curve = Some(rnp_try!(Curve::from_rnp_id(curve)));
    rnp_success!()
}

#[no_mangle] pub unsafe extern "C"
fn rnp_op_generate_set_expiration(op: *mut RnpOpGenerate,
                                  expiration: u32)
                                  -> RnpResult {
    rnp_function!(rnp_op_generate_set_expiration, crate::TRACE);
    let op = assert_ptr_mut!(op);
    arg!(expiration);
    (*op).expiration = Some(time::Duration::new(expiration as u64, 0));
    rnp_success!()
}
