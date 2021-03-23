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
    serialize::stream::*,
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
    rnp_function!(rnp_op_encrypt_execute, crate::TRACE);
    let op = assert_ptr_mut!(op);

    fn f(op: &mut RnpOpEncrypt) -> openpgp::Result<()> {
        // Currently, Thunderbird uses the RFC 1847 Encapsulation
        // method.  We detect that, and transparently replace it with
        // the combined method.
        let cached_plaintext = if ! op.signers.is_empty()
        {
            // This is already a combined operation, therefore we
            // create signatures over existing signatures.
            // Undoing the encapsulation would change semantics.
            None
        } else if let Ok(Some((plaintext, issuers))) =
            op.ctx.plaintext_cache.get(&op.input)
        {
            t!("Plaintext cache hit, attempting recombination");
            let mut issuer_keys = Vec::new();
            for issuer in &issuers {
                if let Some(key) = op.ctx.cert(&issuer.clone().into())
                    .and_then(|cert| {
                        cert.keys().key_handle(issuer.clone()).nth(0)
                            .and_then(|ka| {
                                ka.key().clone().parts_into_secret().ok()
                            })
                    })
                {
                    issuer_keys.push(key);
                }
            }

            // Did we find all keys that previously did the signing?
            if issuer_keys.len() == issuers.len() {
                t!("Recombination successful");
                op.signers = issuer_keys;
                Some(plaintext)
            } else {
                None
            }
        } else {
            None
        };

        let mut message = Message::new(&mut op.output);
        if op.armor {
            message = Armorer::new(message).build()?;
        }

        // Encrypt the message.
        let mut message =
            Encryptor::for_recipients(message, &op.recipients)
            .symmetric_algo(op.cipher.unwrap_or_default())
            .build()?;

        // XXX: Once implementations are more robust, pad the message.

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
                if let Some(key) = op.ctx.cert_by_subkey_fp(&r.fingerprint()) {
                    signer = signer.add_intended_recipient(&key);
                }
            }
            message = signer.build()?;
        }

        // Literal wrapping.
        let mut message = LiteralWriter::new(message).build()?;
        if let Some(mut plaintext) = cached_plaintext {
            // Create a combined message over the original plaintext.
            std::io::copy(&mut plaintext, &mut message)?;
        } else {
            std::io::copy(op.input, &mut message)?;
        }
        message.finalize()?;

        Ok(())
    }

    rnp_return!(f(op))
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

