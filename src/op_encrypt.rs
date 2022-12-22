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
    flags::*,
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
    /// Disables wrapping data in a Literal Data Packet.
    no_wrap: bool,
}

#[no_mangle] pub unsafe extern "C"
fn rnp_op_encrypt_create<'a>(op: *mut *mut RnpOpEncrypt<'a>,
                             ctx: *mut RnpContext,
                             input: *mut RnpInput,
                             output: *mut RnpOutput<'a>)
                             -> RnpResult
{
    rnp_function!(rnp_op_encrypt_create, crate::TRACE);
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
        no_wrap: false,
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

        // XXX: Pad the message if we implemented SEIPDv2 and the
        // padding packet.

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

        if op.no_wrap {
            // This implicitly disables our recombination workaround
            // because this is RNP's native way to support the
            // combined method when GnuPG is used to literal wrap and
            // sign the data.
            t!("Literal data wrapping disabled, encrypting as-is.");
            std::io::copy(op.input, &mut message)?;
        } else {
            // Literal wrapping.
            message = LiteralWriter::new(message).build()?;
            if let Some(mut plaintext) = cached_plaintext {
                // Create a combined message over the original plaintext.
                std::io::copy(&mut plaintext, &mut message)?;
            } else {
                std::io::copy(op.input, &mut message)?;
            }
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
    rnp_function!(rnp_op_encrypt_add_recipient, crate::TRACE);
    use std::ops::Deref;
    let op = assert_ptr_mut!(op);
    let key = assert_ptr_ref!(key);
    t!("Adding encryption-capable (sub)keys from {:X}", key.fingerprint());

    // Try to locate encryption-capable subkeys.
    let mut found_some = false;
    if let Some(cert) = key.try_cert() {
        for ka in cert.keys().with_policy(&*op.ctx.policy(), None)
            .for_transport_encryption()
            .for_storage_encryption()
            .alive()
        {
            t!("Adding (sub)key {:X}", ka.fingerprint());
            op.recipients.push(ka.key().clone().parts_into_unspecified());
            found_some = true;
        }
    }

    // Fall back to pushing key to the recipients and hoping for the
    // best.  This is what RNP does.
    if ! found_some {
        t!("Found no encryption-capable (sub)keys, adding primary key {:X}",
           key.fingerprint());
        op.recipients.push(key.deref().clone());
    }

    RNP_SUCCESS
}

#[no_mangle] pub unsafe extern "C"
fn rnp_op_encrypt_add_signature(op: *mut RnpOpEncrypt,
                                key: *const RnpKey,
                                sig: *mut *mut c_void)
                                -> RnpResult {
    rnp_function!(rnp_op_encrypt_add_signature, crate::TRACE);
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
    rnp_function!(rnp_op_encrypt_set_armor, crate::TRACE);
    assert_ptr!(op);
    (*op).armor = armored;
    RNP_SUCCESS
}

#[no_mangle] pub unsafe extern "C"
fn rnp_op_encrypt_set_cipher(op: *mut RnpOpEncrypt,
                             cipher: *const c_char)
                             -> RnpResult {
    rnp_function!(rnp_op_encrypt_set_cipher, crate::TRACE);
    assert_ptr!(op);
    assert_ptr!(cipher);
    (*op).cipher = Some(rnp_try!(SymmetricAlgorithm::from_rnp_id(cipher)));
    RNP_SUCCESS
}

#[no_mangle] pub unsafe extern "C"
fn rnp_op_encrypt_set_hash(op: *mut RnpOpEncrypt,
                           hash: *const c_char)
                           -> RnpResult {
    rnp_function!(rnp_op_encrypt_set_hash, crate::TRACE);
    assert_ptr!(op);
    assert_ptr!(hash);
    (*op).hash = Some(rnp_try!(HashAlgorithm::from_rnp_id(hash)));
    RNP_SUCCESS
}

#[no_mangle] pub unsafe extern "C"
fn rnp_op_encrypt_set_flags(op: *mut RnpOpEncrypt,
                            flags: RnpEncryptFlags)
                            -> RnpResult {
    rnp_function!(rnp_op_encrypt_set_flags, crate::TRACE);
    let op = assert_ptr_mut!(op);

    if flags & RNP_ENCRYPT_NOWRAP > 0 {
        t!("Disabling literal data wrapping.");
        op.no_wrap = true;
    } else {
        t!("Enabling literal data wrapping (the default).");
        op.no_wrap = false;
    }

    RNP_SUCCESS
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::ffi::CString;
    use std::ptr::null_mut;

    use super::*;
    use libc::c_char;

    use crate::rnp_ffi_create;
    use crate::io::RnpInput;
    use crate::import::rnp_import_keys;
    use crate::key::*;
    use crate::rnp_output_to_memory;
    use crate::rnp_output_memory_get_buf;
    use crate::rnp_input_from_memory;
    use crate::rnp_input_destroy;
    use crate::rnp_output_destroy;
    use crate::rnp_ffi_destroy;

    use openpgp::{
        Cert,
        crypto::SessionKey,
        packet::prelude::*,
        parse::{
            Parse,
            stream::*,
        },
        serialize::SerializeInto,
    };

    macro_rules! rnp_try {
        ($e: expr) => {{
            let r = unsafe { $e };
            assert_eq!(r, RNP_SUCCESS);
        }}
    }

    #[test]
    fn encrypt_no_wrap() -> openpgp::Result<()> {
        let (key, _) =
            openpgp::cert::CertBuilder::general_purpose(None, Some("uid"))
            .generate()?;

        let cert = key.to_vec()?;

        let mut ctx: *mut RnpContext = std::ptr::null_mut();
        rnp_try!(rnp_ffi_create(
            &mut ctx as *mut *mut _,
            b"GPG\x00".as_ptr() as *const c_char,
            b"GPG\x00".as_ptr() as *const c_char));

        let mut input: *mut RnpInput = std::ptr::null_mut();
        rnp_try!(rnp_input_from_memory(
            &mut input as *mut *mut _,
            cert.as_ptr(), cert.len(), false));

        // And load the certificate.
        rnp_try!(rnp_import_keys(
            ctx, input,
            RNP_LOAD_SAVE_PUBLIC_KEYS
                | RNP_LOAD_SAVE_SECRET_KEYS,
            std::ptr::null_mut() as *mut *mut _));

        rnp_try!(rnp_input_destroy(input));

        // Manually wrap a message.
        const MESSAGE: &[u8] = b"Hello World :)";
        let mut wrapped = Vec::new();
        let mut message =
            LiteralWriter::new(Message::new(&mut wrapped)).build()?;
        message.write_all(&MESSAGE)?;
        message.finalize()?;

        // Now encrypt it.
        let mut input: *mut RnpInput = std::ptr::null_mut();
        rnp_try!(rnp_input_from_memory(
            &mut input as *mut *mut _,
            wrapped.as_ptr(), wrapped.len(), false));

        let mut output: *mut RnpOutput = std::ptr::null_mut();
        rnp_try!(rnp_output_to_memory(&mut output as *mut *mut _, 0));

        let mut op = null_mut();
        rnp_try!(rnp_op_encrypt_create(&mut op as *mut _, ctx, input, output));
        rnp_try!(rnp_op_encrypt_set_flags(op, RNP_ENCRYPT_NOWRAP));

        let fp = CString::new(key.fingerprint().to_string())?;
        let mut recipient = null_mut();
        rnp_try!(rnp_locate_key(ctx, b"fingerprint\0".as_ptr() as *const _,
                                fp.as_ptr(), &mut recipient as *mut _));

        rnp_try!(rnp_op_encrypt_add_recipient(op, recipient));

        rnp_try!(rnp_op_encrypt_execute(op));

        let mut buf: *mut u8 = std::ptr::null_mut();
        let mut len: libc::size_t = 0;
        rnp_try!(rnp_output_memory_get_buf(
            output,
            &mut buf as *mut *mut _,
            &mut len as *mut _,
            false));
        let ciphertext = unsafe {
            std::slice::from_raw_parts(buf, len)
        };

        // Decrypt it.
        struct Helper {
            key: openpgp::Cert,
        }
        impl VerificationHelper for Helper {
            fn get_certs(&mut self, _ids: &[openpgp::KeyHandle]) -> openpgp::Result<Vec<Cert>> {
                Ok(Vec::new())
            }
            fn check(&mut self, _structure: MessageStructure) -> openpgp::Result<()> {
                Ok(())
            }
        }
        impl DecryptionHelper for Helper {
            fn decrypt<D>(&mut self, pkesks: &[PKESK], skesks: &[SKESK],
                          _sym_algo: Option<SymmetricAlgorithm>,
                          mut decrypt: D) -> openpgp::Result<Option<openpgp::Fingerprint>>
            where D: FnMut(SymmetricAlgorithm, &SessionKey) -> bool
            {
                assert_eq!(pkesks.len(), 1);
                assert_eq!(skesks.len(), 0);
                let mut key =
                    self.key.keys().secret().key_handle(pkesks[0].recipient())
                    .next().unwrap().key().clone().into_keypair()?;
                pkesks[0].decrypt(&mut key, None)
                    .map(|(algo, session_key)| decrypt(algo, &session_key));
                Ok(None)
            }
        }

        let p = openpgp::policy::StandardPolicy::new();
        let h = Helper { key, };
        let mut v = DecryptorBuilder::from_bytes(ciphertext)?
            .with_policy(&p, None, h)?;

        let mut content = Vec::new();
        v.read_to_end(&mut content)?;
        assert_eq!(&content, MESSAGE);

        rnp_try!(rnp_key_handle_destroy(recipient));
        rnp_try!(rnp_input_destroy(input));
        rnp_try!(rnp_output_destroy(output));
        rnp_try!(rnp_ffi_destroy(ctx));

        Ok(())
    }
}
