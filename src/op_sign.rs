use libc::{
    c_char,
    c_void,
};

use sequoia_openpgp as openpgp;
use openpgp::{
    packet::{
        Key,
        key::{
            SecretParts,
            UnspecifiedRole,
        },
    },
    serialize::stream::*,
    types::{
        HashAlgorithm,
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

pub struct RnpOpSign<'a> {
    ctx: &'a mut RnpContext,
    input: &'a mut RnpInput,
    output: &'a mut RnpOutput<'a>,
    signers: Vec<Key<SecretParts, UnspecifiedRole>>,
    hash: Option<HashAlgorithm>,
    armor: bool,
    csf: bool,
}

#[no_mangle] pub unsafe extern "C"
fn rnp_op_sign_detached_create<'a>(op: *mut *mut RnpOpSign<'a>,
                                   ctx: *mut RnpContext,
                                   input: *mut RnpInput,
                                   output: *mut RnpOutput<'a>)
                                   -> RnpResult
{
    assert_ptr!(op);
    assert_ptr!(ctx);
    assert_ptr!(input);
    assert_ptr!(output);

    *op = Box::into_raw(Box::new(RnpOpSign {
        ctx: &mut *ctx,
        input: &mut *input,
        output: &mut *output,
        signers: Vec::new(),
        hash: None,
        armor: false,
        csf: false,
    }));
    RNP_SUCCESS
}

#[no_mangle] pub unsafe extern "C"
fn rnp_op_sign_cleartext_create<'a>(op: *mut *mut RnpOpSign<'a>,
                                    ctx: *mut RnpContext,
                                    input: *mut RnpInput,
                                    output: *mut RnpOutput<'a>)
                                    -> RnpResult
{
    assert_ptr!(op);
    assert_ptr!(ctx);
    assert_ptr!(input);
    assert_ptr!(output);

    *op = Box::into_raw(Box::new(RnpOpSign {
        ctx: &mut *ctx,
        input: &mut *input,
        output: &mut *output,
        signers: Vec::new(),
        hash: None,
        armor: false,
        csf: true,
    }));
    RNP_SUCCESS
}

#[no_mangle] pub unsafe extern "C"
fn rnp_op_sign_destroy(op: *mut RnpOpSign) -> RnpResult {
    if ! op.is_null() {
        drop(Box::from_raw(op));
    }
    RNP_SUCCESS
}


#[no_mangle] pub unsafe extern "C"
fn rnp_op_sign_execute(op: *mut RnpOpSign) -> RnpResult {
    rnp_function!(rnp_op_sign_execute, crate::TRACE);
    let op = assert_ptr_mut!(op);

    fn sign(op: &mut RnpOpSign) -> openpgp::Result<()> {
        assert!(! op.csf);

        let mut message = Message::new(&mut op.output);
        if op.armor {
            message = Armorer::new(message)
                .kind(openpgp::armor::Kind::Signature)
                .build()?;
        }

        // Maybe sign the message.
        if let Some(key) = op.signers.pop() {
            let s =
                op.ctx.decrypt_key_for(None, key, RnpPasswordFor::Sign)?
                .into_keypair()?;
            let mut signer = Signer::new(message, s)
                .hash_algo(op.hash.unwrap_or_default())?
                .detached();

            for key in op.signers.drain(..) {
                let s =
                    op.ctx.decrypt_key_for(None, key, RnpPasswordFor::Sign)?
                    .into_keypair()?;
                signer = signer.add_signer(s);
            }
            message = signer.build()?;
        }

        std::io::copy(op.input, &mut message)?;
        message.finalize()?;

        Ok(())
    }

    fn clearsign(op: &mut RnpOpSign) -> openpgp::Result<()> {
        assert!(op.csf);

        let mut message = Message::new(&mut op.output);

        // Maybe sign the message.
        if let Some(key) = op.signers.pop() {
            let s =
                op.ctx.decrypt_key_for(None, key, RnpPasswordFor::Sign)?
                .into_keypair()?;
            let mut signer = Signer::new(message, s)
                .hash_algo(op.hash.unwrap_or_default())?
                .cleartext();

            for key in op.signers.drain(..) {
                let s =
                    op.ctx.decrypt_key_for(None, key, RnpPasswordFor::Sign)?
                    .into_keypair()?;
                signer = signer.add_signer(s);
            }
            message = signer.build()?;
        }

        std::io::copy(op.input, &mut message)?;
        message.finalize()?;

        Ok(())
    }

    if op.csf {
        rnp_return!(clearsign(op))
    } else {
        rnp_return!(sign(op))
    }
}

#[no_mangle] pub unsafe extern "C"
fn rnp_op_sign_add_signature(op: *mut RnpOpSign,
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
fn rnp_op_sign_set_armor(op: *mut RnpOpSign,
                         armored: bool)
                         -> RnpResult {
    assert_ptr!(op);
    (*op).armor = armored;
    RNP_SUCCESS
}

#[no_mangle] pub unsafe extern "C"
fn rnp_op_sign_set_hash(op: *mut RnpOpSign,
                        hash: *const c_char)
                        -> RnpResult {
    assert_ptr!(op);
    assert_ptr!(hash);
    (*op).hash = Some(rnp_try!(HashAlgorithm::from_rnp_id(hash)));
    RNP_SUCCESS
}

