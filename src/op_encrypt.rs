use libc::{
    c_char,
    c_void,
};

use sequoia_openpgp as openpgp;
use openpgp::{
    packet::{
        Key,
        key::{
            UnspecifiedParts,
            SecretParts,
            UnspecifiedRole,
        },
    },
    serialize::stream::{*, padding::Padder},
    types::{
        HashAlgorithm,
        SymmetricAlgorithm,
    },
};

use crate::{
    RnpContext,
    RnpResult,
    RnpInput,
    RnpOutput,
    RnpPasswordFor,
    conversions::FromRnpId,
    key::RnpKey,
    error::*,
};

pub struct RnpOpEncrypt<'a> {
    ctx: &'a mut RnpContext,
    input: &'a mut RnpInput,
    output: &'a mut RnpOutput<'a>,
    recipients: Vec<Key<UnspecifiedParts, UnspecifiedRole>>,
    signers: Vec<Key<SecretParts, UnspecifiedRole>>,
    cipher: Option<SymmetricAlgorithm>,
    hash: Option<HashAlgorithm>,
    armor: bool,
}

#[no_mangle] pub unsafe extern "C"
fn rnp_op_encrypt_create<'a>(op: *mut *mut RnpOpEncrypt<'a>,
                             ctx: *mut RnpContext,
                             input: *mut RnpInput,
                             output: *mut RnpOutput<'a>)
                             -> RnpResult
{
    assert_ptr!(op);
    assert_ptr!(ctx);
    assert_ptr!(input);
    assert_ptr!(output);

    *op = Box::into_raw(Box::new(RnpOpEncrypt {
        ctx: &mut *ctx,
        input: &mut *input,
        output: &mut *output,
        recipients: Vec::new(),
        signers: Vec::new(),
        cipher: None,
        hash: None,
        armor: false,
    }));
    RNP_SUCCESS
}

#[no_mangle] pub unsafe extern "C"
fn rnp_op_encrypt_destroy(op: *mut RnpOpEncrypt) -> RnpResult {
    if ! op.is_null() {
        drop(Box::from_raw(op));
    }
    RNP_SUCCESS
}


#[no_mangle] pub unsafe extern "C"
fn rnp_op_encrypt_execute(op: *mut RnpOpEncrypt) -> RnpResult {
    assert_ptr!(op);

    fn f(op: &mut RnpOpEncrypt) -> openpgp::Result<()> {
        let mut message = Message::new(&mut op.output);
        if op.armor {
            message = Armorer::new(message).build()?;
        }

        // Encrypt the message.
        let message =
            Encryptor::for_recipients(message, &op.recipients)
            .symmetric_algo(op.cipher.unwrap_or_default())
            .build()?;

        // Pad the message.
        let mut message = Padder::new(message).build()?;

        // Maybe sign the message.
        if let Some(key) = op.signers.pop() {
            let s =
                op.ctx.decrypt_key_for(None, key, RnpPasswordFor::Sign)?
                .into_keypair()?;
            let mut signer = Signer::new(message, s)
                .hash_algo(op.hash.unwrap_or_default())?;
            for key in op.signers.drain(..) {
                let s =
                    op.ctx.decrypt_key_for(None, key, RnpPasswordFor::Sign)?
                    .into_keypair()?;
                signer = signer.add_signer(s);
            }
            for r in &op.recipients {
                if let (Some(key), _) = op.ctx.cert_by_subkey_fp(&r.fingerprint()) {
                    signer = signer.add_intended_recipient(&key);
                }
            }
            message = signer.build()?;
        }

        // Literal wrapping.
        let mut message = LiteralWriter::new(message).build()?;
        std::io::copy(op.input, &mut message)?;
        message.finalize()?;

        Ok(())
    }

    if let Err(e) = f(&mut *op) {
        warn!("failed to encrypt: {}", e);
        RNP_ERROR_GENERIC
    } else {
        RNP_SUCCESS
    }
}

#[no_mangle] pub unsafe extern "C"
fn rnp_op_encrypt_add_recipient(op: *mut RnpOpEncrypt,
                                key: *const RnpKey)
                                -> RnpResult {
    use std::ops::Deref;
    assert_ptr!(op);
    assert_ptr!(key);
    (*op).recipients.push((*key).deref().clone());
    RNP_SUCCESS
}

#[no_mangle] pub unsafe extern "C"
fn rnp_op_encrypt_add_signature(op: *mut RnpOpEncrypt,
                                key: *const RnpKey,
                                sig: *mut *mut c_void)
                                -> RnpResult {
    use std::ops::Deref;
    assert_ptr!(op);
    assert_ptr!(key);
    if ! sig.is_null() {
        warn!("changing signature parameters not implemented");
        return RNP_ERROR_NOT_IMPLEMENTED;
    }

    if let Ok(k) = (*key).deref().clone().parts_into_secret() {
        (*op).signers.push(k);
        RNP_SUCCESS
    } else {
        RNP_ERROR_NO_SUITABLE_KEY
    }
}

#[no_mangle] pub unsafe extern "C"
fn rnp_op_encrypt_set_armor(op: *mut RnpOpEncrypt,
                            armored: bool)
                            -> RnpResult {
    assert_ptr!(op);
    (*op).armor = armored;
    RNP_SUCCESS
}

#[no_mangle] pub unsafe extern "C"
fn rnp_op_encrypt_set_cipher(op: *mut RnpOpEncrypt,
                             cipher: *const c_char)
                             -> RnpResult {
    assert_ptr!(op);
    assert_ptr!(cipher);
    (*op).cipher = Some(rnp_try!(SymmetricAlgorithm::from_rnp_id(cipher)));
    RNP_SUCCESS
}

#[no_mangle] pub unsafe extern "C"
fn rnp_op_encrypt_set_hash(op: *mut RnpOpEncrypt,
                           hash: *const c_char)
                           -> RnpResult {
    assert_ptr!(op);
    assert_ptr!(hash);
    (*op).hash = Some(rnp_try!(HashAlgorithm::from_rnp_id(hash)));
    RNP_SUCCESS
}

