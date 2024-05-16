use std::{
    fmt,
    io,
};
use libc::{
    c_char,
    size_t,
};

use sequoia_openpgp as openpgp;
use openpgp::{
    KeyHandle,
    KeyID,
    Fingerprint,
    cert::{
        Cert,
    },
    packet::{
        Signature,
        Key,
        key::{
            PublicParts,
            SecretParts,
            UnspecifiedParts,
            UnspecifiedRole,
        },
    },
    parse::{
        Parse,
        stream::*,
    },
    types::{
        SymmetricAlgorithm,
        AEADAlgorithm,
    },
};
use openpgp::crypto::{self, SessionKey};
use openpgp::packet::{PKESK, SKESK};

use sequoia_ipc as ipc;

use crate::{
    RnpContext,
    RnpResult,
    RnpInput,
    RnpOutput,
    RnpPasswordFor,
    RnpSignature,
    str_to_rnp_buffer,
    conversions::ToRnpId,
    key::RnpKey,
    error::*,
};

/// Controls tracing in this module.
const TRACE: bool = crate::TRACE;

pub struct RnpOpVerify<'a> {
    ctx: &'a mut RnpContext,
    input: &'a mut RnpInput,
    mode: SignatureMode<'a>,
    result: RnpOpVerifyResult,
}

enum SignatureMode<'a> {
    Inline(&'a mut RnpOutput<'a>),
    Detached(&'a mut RnpInput),
}

#[derive(Default)]
pub struct RnpOpVerifyResult {
    // Information about the symmetric encryption.
    mode: RnpProtectionMode,
    cipher: Option<SymmetricAlgorithm>,

    pkesks: Vec<PKESK>,
    skesks: Vec<SKESK>,

    // rnp_op_verify_get_used_recipient returns the info from the
    // PKESK used to decrypt the message.
    pkesk_used: Option<PKESK>,
    // rnp_op_verify_get_used_symenc returns the info from the
    // SKESK used to decrypt the message.
    skesk_used: Option<SKESK>,

    // Any signatures.
    signatures: Vec<RnpOpVerifySignature>,
}

impl fmt::Debug for RnpOpVerifyResult {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("RnpOpVerifyResult")
            .field("mode", &self.mode)
            .field("cipher", &self.cipher)
            .field("pkesks", &self.pkesks.iter().map(|pkesk| {
                pkesk.recipient().to_hex()
            }).collect::<Vec<String>>())
            .field("skesk count", &self.skesks.len())
            .field("pkesk_used", &self.pkesk_used.as_ref().map(|pkesk| {
                self.pkesks.iter().position(|x| x == pkesk).expect("added")
            }))
            .field("skesk_used", &self.skesk_used.as_ref().map(|skesk| {
                self.skesks.iter().position(|x| x == skesk).expect("added")
            }))
            .field("signatures", &self.signatures)
            .finish()
    }
}

impl RnpOpVerifyResult {
    /// Returns whether we operated on an encrypted message.
    fn encrypted_message(&self) -> bool {
        ! (self.pkesks.is_empty() && self.skesks.is_empty())
    }

    /// Returns whether the message was decrypted successfully.
    fn decrypted_successfully(&self) -> bool {
        self.pkesk_used.is_some() || self.skesk_used.is_some()
    }

    /// Returns an verification failure (arbitrarily picks the first).
    fn verification_error(&self) -> Option<RnpStatus> {
        for s in &self.signatures {
            if s.status != RNP_SUCCESS {
                return Some(s.status);
            }
        }
        None
    }
}

pub struct RnpOpVerifySignature {
    ctx: *mut RnpContext,
    status: RnpStatus,
    sig: Signature,
    key: Option<(Key<UnspecifiedParts, UnspecifiedRole>, Cert)>,
}

impl fmt::Debug for RnpOpVerifySignature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("RnpOpVerifySignature")
            .field("ctx", &self.ctx)
            .field("status", &format_args!("{:X}", self.status))
            .field("sig", &self.sig)
            .field("key", &self.key.as_ref().map(|(k, c)| {
                (c.fingerprint().to_hex(), k.fingerprint().to_hex())
            }))
            .finish()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum RnpProtectionMode {
    None,
    Cfb,
    CfbMdc,
    Aead(AEADAlgorithm),
}

impl Default for RnpProtectionMode {
    fn default() -> Self {
        Self::None
    }
}

impl ToRnpId for RnpProtectionMode {
    fn to_rnp_id(&self) -> &str {
        use RnpProtectionMode::*;
        match self {
            None => "none",
            Cfb => "cfb",
            CfbMdc => "cfb-mdc",
            Aead(AEADAlgorithm::EAX) => "aead-eax",
            Aead(AEADAlgorithm::OCB) => "aead-ocb",
            Aead(_) => "aead-unknown",
        }
    }
}

#[no_mangle] pub unsafe extern "C"
fn rnp_op_verify_create<'a>(op: *mut *mut RnpOpVerify<'a>,
                            ctx: *mut RnpContext,
                            input: *mut RnpInput,
                            output: *mut RnpOutput<'a>)
                            -> RnpResult
{
    rnp_function!(rnp_op_verify_create, crate::TRACE);
    let op = assert_ptr_mut!(op);
    let ctx = assert_ptr_mut!(ctx);
    let input = assert_ptr_mut!(input);
    let output = assert_ptr_mut!(output);

    *op = Box::into_raw(Box::new(RnpOpVerify {
        ctx,
        input,
        mode: SignatureMode::Inline(output),
        result: Default::default(),
    }));
    rnp_success!()
}

#[no_mangle] pub unsafe extern "C"
fn rnp_op_verify_detached_create<'a>(op: *mut *mut RnpOpVerify<'a>,
                                     ctx: *mut RnpContext,
                                     input: *mut RnpInput,
                                     signature: *mut RnpInput)
                                     -> RnpResult
{
    rnp_function!(rnp_op_verify_detached_create, crate::TRACE);
    let op = assert_ptr_mut!(op);
    let ctx = assert_ptr_mut!(ctx);
    let input = assert_ptr_mut!(input);
    let signature = assert_ptr_mut!(signature);

    *op = Box::into_raw(Box::new(RnpOpVerify {
        ctx,
        input,
        mode: SignatureMode::Detached(signature),
        result: Default::default(),
    }));
    rnp_success!()
}

#[no_mangle] pub unsafe extern "C"
fn rnp_op_verify_destroy(op: *mut RnpOpVerify) -> RnpResult {
    rnp_function!(rnp_op_verify_destroy, crate::TRACE);
    arg!(op);

    if ! op.is_null() {
        drop(Box::from_raw(op));
    }
    rnp_success!()
}

#[no_mangle] pub unsafe extern "C"
fn rnp_op_verify_execute(op: *mut RnpOpVerify) -> RnpResult {
    rnp_function!(rnp_op_verify_execute, crate::TRACE);
    let op = assert_ptr_mut!(op);

    fn f(op: &mut RnpOpVerify) -> openpgp::Result<()> {
        let policy = op.ctx.policy().clone();
        match &mut op.mode {
            SignatureMode::Inline(output) => {
                t!("Inline signature verification or decryption");

                // We first try to verify without decryption.  This
                // way, Sequoia will handle messages using the
                // Cleartext Signature Framework.

                let mut input = op.input.try_clone()?;
                let h = Helper {
                    ctx: op.ctx,
                    result: &mut op.result,
                };
                if VerifierBuilder::from_reader(&mut input)
                    .and_then(|b| b.with_policy(&policy, None, h))
                    .and_then(|mut v|
                              io::copy(&mut v, output).map_err(Into::into))
                    .is_ok()
                {
                    t!("Verification without decryption successful: {:#?}",
                       op.result);
                    return Ok(());
                }

                let h = Helper {
                    ctx: op.ctx,
                    result: &mut op.result,
                };

                let mut v = DecryptorBuilder::from_reader(&mut op.input)?
                    .with_policy(&policy, None, h)?;
                io::copy(&mut v, output)?;
                t!("Decryption successful: {:#?}", op.result);
            },
            SignatureMode::Detached(signature) => {
                t!("Detached signature verification");
                let h = Helper {
                    ctx: op.ctx,
                    result: &mut op.result,
                };
                let mut v = DetachedVerifierBuilder::from_reader(signature)?
                    .with_policy(&policy, None, h)?;
                v.verify_reader(&mut op.input)?;
                t!("Verification without decryption successful: {:#?}",
                   op.result);
            },
        }
        Ok(())
    }

    rnp_return_status!(if let Err(e) = f(op) {
        if op.result.encrypted_message()
            && ! op.result.decrypted_successfully()
        {
            warn!("failed to decrypt: {}", e);
            RNP_ERROR_DECRYPT_FAILED
        } else if let Some(status) = op.result.verification_error() {
            warn!("failed to verify sig: {}", e);
            status
        } else {
            warn!("{}", e);
            // We need to return an error that Thunderbird
            // understands.  It does not understand RNP_ERROR_GENERIC
            // in this context.  See:
            //
            // https://searchfox.org/comm-central/rev/35c9e2929a5ae37d07192315db3787dc01f73441/mail/extensions/openpgp/content/modules/RNP.jsm#953
            RNP_ERROR_DECRYPT_FAILED
        }
    } else {
        RNP_SUCCESS
    })
}

#[no_mangle] pub unsafe extern "C"
fn rnp_op_verify_get_signature_at(op: *mut RnpOpVerify,
                                  idx: size_t,
                                  signature: *mut *const RnpOpVerifySignature)
                                  -> RnpResult {
    rnp_function!(rnp_op_verify_get_signature_at, crate::TRACE);
    let op = assert_ptr_ref!(op);
    arg!(idx);
    let signature = assert_ptr_mut!(signature);

    rnp_return_status!(if let Some(s) = op.result.signatures.get(idx) {
        *signature = s as *const _;
        RNP_SUCCESS
    } else {
        RNP_ERROR_BAD_PARAMETERS
    })
}

#[no_mangle] pub unsafe extern "C"
fn rnp_op_verify_get_signature_count(op: *mut RnpOpVerify,
                                     count: *mut size_t)
                                     -> RnpResult {
    rnp_function!(rnp_op_verify_get_signature_count, crate::TRACE);
    let op = assert_ptr_ref!(op);
    let count = assert_ptr_mut!(count);
    *count = op.result.signatures.len();
    rnp_success!()
}

#[no_mangle] pub unsafe extern "C"
fn rnp_op_verify_signature_get_handle(sig: *const RnpOpVerifySignature,
                                      handle: *mut *mut RnpSignature)
                                      -> RnpResult {
    rnp_function!(rnp_op_verify_signature_get_handle, crate::TRACE);
    let sig = assert_ptr_ref!(sig);
    let handle = assert_ptr_mut!(handle);

    *handle =
        Box::into_raw(Box::new(
            RnpSignature::new(sig.ctx, sig.sig.clone(),
                              Some(sig.status == RNP_SUCCESS))));
    rnp_success!()
}

#[no_mangle] pub unsafe extern "C"
fn rnp_op_verify_signature_get_status(sig: *const RnpOpVerifySignature)
                                      -> RnpResult {
    rnp_function!(rnp_op_verify_signature_get_status, crate::TRACE);
    assert_ptr!(sig);
    rnp_return_status!((*sig).status)
}

#[no_mangle] pub unsafe extern "C"
fn rnp_op_verify_signature_get_key(sig: *const RnpOpVerifySignature,
                                   key_out: *mut *mut RnpKey)
                                   -> RnpResult {
    rnp_function!(rnp_op_verify_signature_get_key, crate::TRACE);
    let sig = assert_ptr_ref!(sig);
    let key_out = assert_ptr_mut!(key_out);

    rnp_return_status!(if let Some(key) = (*sig).key.as_ref().cloned() {
        *key_out =
            Box::into_raw(Box::new(RnpKey::new((*sig).ctx, key.0, &key.1)));
        RNP_SUCCESS
    } else {
        *key_out = std::ptr::null_mut();
        RNP_ERROR_KEY_NOT_FOUND
    })
}

#[no_mangle] pub unsafe extern "C"
fn rnp_op_verify_signature_get_times(sig: *const RnpOpVerifySignature,
                                     created: *mut u32,
                                     expires: *mut u32)
                                     -> RnpResult {
    rnp_function!(rnp_op_verify_signature_get_times, crate::TRACE);
    use std::time::UNIX_EPOCH;
    let sig = assert_ptr_ref!(sig);
    arg!(created);
    arg!(expires);

    if ! created.is_null() {
        *created = (*sig).sig.signature_creation_time().unwrap_or(UNIX_EPOCH)
            .duration_since(UNIX_EPOCH).unwrap().as_secs()
            as u32;
    }
    if ! expires.is_null() {
        *expires = (*sig).sig.signature_expiration_time().map(|e| {
            e.duration_since(UNIX_EPOCH).unwrap().as_secs()
                as u32
        }).unwrap_or(0);
    }
    rnp_success!()
}

#[no_mangle] pub unsafe extern "C"
fn rnp_op_verify_get_protection_info(op: *const RnpOpVerify,
                                     mode: *mut *mut c_char,
                                     cipher: *mut *mut c_char,
                                     valid: *mut bool)
                                     -> RnpResult {
    rnp_function!(rnp_op_verify_get_protection_info, crate::TRACE);
    let op = assert_ptr_ref!(op);
    arg!(mode);
    arg!(cipher);
    arg!(valid);

    if ! mode.is_null() {
        *mode = str_to_rnp_buffer(op.result.mode.to_rnp_id());
    }
    if ! cipher.is_null() {
        *cipher = str_to_rnp_buffer(
            op.result.cipher.unwrap_or(SymmetricAlgorithm::Unencrypted)
                .to_rnp_id());
    }
    if ! valid.is_null() {
        *valid = if op.result.cipher.unwrap_or(SymmetricAlgorithm::Unencrypted)
            != SymmetricAlgorithm::Unencrypted
            && op.result.mode != RnpProtectionMode::None
            && op.result.mode != RnpProtectionMode::Cfb
        {
            true
        } else {
            false
        };
    }
    rnp_success!()
}

#[no_mangle] pub unsafe extern "C"
fn rnp_op_verify_get_used_recipient(op: *const RnpOpVerify,
                                    pkesk: *mut *const PKESK)
                                    -> RnpResult {
    rnp_function!(rnp_op_verify_get_used_recipient, crate::TRACE);
    let op = assert_ptr_ref!(op);
    let pkesk = assert_ptr_mut!(pkesk);

    *pkesk = op.result.pkesk_used.as_ref().map(|p| p as *const _)
        .unwrap_or(std::ptr::null());
    rnp_success!()
}

#[no_mangle] pub unsafe extern "C"
fn rnp_op_verify_get_recipient_at(op: *const RnpOpVerify,
                                  idx: size_t,
                                  pkesk: *mut *const PKESK)
                                  -> RnpResult {
    rnp_function!(rnp_op_verify_get_recipient_at, crate::TRACE);
    let op = assert_ptr_ref!(op);
    arg!(idx);
    let pkesk = assert_ptr_mut!(pkesk);

    rnp_return_status!(if let Some(p) = op.result.pkesks.get(idx) {
        *pkesk = p as *const _;
        RNP_SUCCESS
    } else {
        RNP_ERROR_BAD_PARAMETERS
    })
}

#[no_mangle] pub unsafe extern "C"
fn rnp_op_verify_get_recipient_count(op: *const RnpOpVerify,
                                     count: *mut size_t)
                                     -> RnpResult {
    rnp_function!(rnp_op_verify_get_recipient_count, crate::TRACE);
    let op = assert_ptr_ref!(op);
    let count = assert_ptr_mut!(count);
    *count = op.result.pkesks.len();
    rnp_success!()
}

#[no_mangle] pub unsafe extern "C"
fn rnp_recipient_get_keyid(recipient: *const PKESK,
                           keyid: *mut *mut c_char)
                           -> RnpResult {
    rnp_function!(rnp_recipient_get_keyid, crate::TRACE);
    let recipient = assert_ptr_ref!(recipient);
    let keyid = assert_ptr_mut!(keyid);
    *keyid = str_to_rnp_buffer(format!("{:X}", (*recipient).recipient()));
    rnp_success!()
}

#[no_mangle] pub unsafe extern "C"
fn rnp_recipient_get_alg(recipient: *const PKESK,
                         alg: *mut *mut c_char)
                         -> RnpResult {
    rnp_function!(rnp_recipient_get_alg, crate::TRACE);
    let recipient = assert_ptr_ref!(recipient);
    let alg = assert_ptr_mut!(alg);
    *alg = str_to_rnp_buffer((*recipient).pk_algo().to_rnp_id());
    rnp_success!()
}

#[no_mangle] pub unsafe extern "C"
fn rnp_op_verify_get_used_symenc(op: *const RnpOpVerify,
                                 skesk: *mut *const SKESK)
                                 -> RnpResult {
    rnp_function!(rnp_op_verify_get_used_symenc, crate::TRACE);
    let op = assert_ptr_ref!(op);
    let skesk = assert_ptr_mut!(skesk);
    *skesk = op.result.skesk_used.as_ref().map(|p| p as *const _)
        .unwrap_or(std::ptr::null());
    rnp_success!()
}

#[no_mangle] pub unsafe extern "C"
fn rnp_op_verify_get_symenc_at(op: *const RnpOpVerify,
                               idx: size_t,
                               skesk: *mut *const SKESK)
                               -> RnpResult {
    rnp_function!(rnp_op_verify_get_symenc_at, crate::TRACE);
    let op = assert_ptr_ref!(op);
    arg!(idx);
    let skesk = assert_ptr_mut!(skesk);

    rnp_return_status!(if let Some(p) = op.result.skesks.get(idx) {
        *skesk = p as *const _;
        RNP_SUCCESS
    } else {
        RNP_ERROR_BAD_PARAMETERS
    })
}

#[no_mangle] pub unsafe extern "C"
fn rnp_op_verify_get_symenc_count(op: *const RnpOpVerify,
                                  count: *mut size_t)
                                  -> RnpResult {
    rnp_function!(rnp_op_verify_get_symenc_count, crate::TRACE);
    let op = assert_ptr_ref!(op);
    let count = assert_ptr_mut!(count);
    *count = op.result.skesks.len();
    rnp_success!()
}

struct Helper<'a> {
    ctx: &'a mut RnpContext,
    result: &'a mut RnpOpVerifyResult,
}

impl<'a> VerificationHelper for Helper<'a> {
    fn get_certs(&mut self, ids: &[KeyHandle])
                 -> openpgp::Result<Vec<Cert>> {
        Ok(ids.iter().filter_map(|id| {
            match self.ctx.cert(&id.into()) {
                Some(cert) => Some(cert),
                None => {
                    // The lookup failed.  If we are in the process of
                    // loading a keyring, wait until that is done, and
                    // then retry the lookup.
                    if let Ok(true) = self.ctx.certs.block_on_load() {
                        self.ctx.cert(&id.into())
                    } else {
                        None
                    }
                }
            }
        }).collect())
    }

    fn check(&mut self, structure: MessageStructure) -> openpgp::Result<()> {
        rnp_function!(Helper::check, TRACE);

        use self::VerificationError::*;

        // Thunderbird doesn't deal well with not having a key
        // associated with a signature, even though that seems
        // possible in RNP.  Make a last-ditch effort to find the key.
        fn last_ditch_key_lookup(ctx: &RnpContext,
                                 sig: &Signature,
                                 cert: Option<&Cert>)
                                 -> Option<(Key<UnspecifiedParts, UnspecifiedRole>, Cert)>
        {
            t!("Doing a last-ditch key lookup for {:?}, {:?}", sig, cert);
            if let Some(cert) = cert {
                for h in sig.get_issuers() {
                    if let Some(key) = cert.keys().key_handle(h).nth(0) {
                        t!("success: key {}, cert {}",
                           key.fingerprint(), cert.fingerprint());
                        return Some((key.parts_as_unspecified().key().clone(),
                                     cert.clone()));
                    }
                }
            }

            for h in sig.get_issuers() {
                if let Some(cert) = ctx.cert_by_subkey_handle(&h) {
                    if let Some(key) = cert.keys().key_handle(h).nth(0) {
                        t!("success: key {}, cert {}",
                           key.fingerprint(), cert.fingerprint());
                        return Some((key.parts_as_unspecified().key().clone(),
                                     cert.clone()));
                    }
                }
            }

            t!("failed");
            None
        }

        let n_layers = structure.iter().count();
        for (i, layer) in structure.into_iter().enumerate() {
            match (i, layer) {
                (i, MessageLayer::SignatureGroup { results })
                    if i == n_layers - 1 =>
                {
                    for (signo, result) in results.into_iter().enumerate() {
                        match result {
                            Ok(GoodChecksum { sig, ka, .. }) => {
                                t!("Signature {}.{} is good", i, signo);
                                self.result.signatures.push(
                                    RnpOpVerifySignature {
                                        ctx: self.ctx as *mut _,
                                        status: RNP_SUCCESS,
                                        sig: sig.clone(),
                                        key: Some((ka.key().clone()
                                                   .parts_into_unspecified(),
                                                   ka.cert().clone())),
                                    });
                            },
                            Err(MalformedSignature { sig, error }) => {
                                t!("Signature {}.{} is malformed: {}",
                                   i, signo, error);
                                self.result.signatures.push(
                                    RnpOpVerifySignature {
                                        ctx: self.ctx as *mut _,
                                        status: RNP_ERROR_SIGNATURE_INVALID,
                                        sig: sig.clone(),
                                        key: last_ditch_key_lookup(
                                            self.ctx, sig, None),
                                    });
                            },
                            Err(MissingKey { sig, .. }) => {
                                t!("Signature {}.{}: can't verify, missing key",
                                   i, signo);
                                self.result.signatures.push(
                                    RnpOpVerifySignature {
                                        ctx: self.ctx as *mut _,
                                        status: RNP_ERROR_KEY_NOT_FOUND,
                                        sig: sig.clone(),
                                        key: last_ditch_key_lookup(
                                            self.ctx, sig, None),
                                    });
                            },
                            Err(UnboundKey { sig, cert, error }) => {
                                t!("Signature {}.{}: can't verify, \
                                    unbound key from {}: {}",
                                   i, signo, cert.fingerprint(), error);
                                self.result.signatures.push(
                                    RnpOpVerifySignature {
                                        ctx: self.ctx as *mut _,
                                        status: RNP_ERROR_SIGNATURE_INVALID,
                                        sig: sig.clone(),
                                        // The key was not bound under
                                        // the policy, let's see if we
                                        // can get it without
                                        // validating the cert.
                                        key: last_ditch_key_lookup(
                                            self.ctx, sig, Some(cert)),
                                    });
                            },
                            Err(BadKey { sig, ka, error }) => {
                                t!("Signature {}.{}: can't verify, \
                                    bad key ({}): {}",
                                   i, signo, ka.fingerprint(), error);
                                self.result.signatures.push(
                                    RnpOpVerifySignature {
                                        ctx: self.ctx as *mut _,
                                        status: RNP_ERROR_SIGNATURE_INVALID,
                                        sig: sig.clone(),
                                        key: Some((ka.key().clone()
                                                   .parts_into_unspecified(),
                                                   ka.cert().clone())),
                                    });
                            },
                            Err(BadSignature { sig, ka, error }) => {
                                t!("Signature {}.{}: bad signature by {}: {}",
                                   i, signo, ka.fingerprint(), error);
                                self.result.signatures.push(
                                    RnpOpVerifySignature {
                                        ctx: self.ctx as *mut _,
                                        status: if sig.signature_alive(None, None).is_err() {
                                            RNP_ERROR_SIGNATURE_EXPIRED
                                        } else {
                                            RNP_ERROR_SIGNATURE_INVALID
                                        },
                                        sig: sig.clone(),
                                        key: Some((ka.key().clone()
                                                   .parts_into_unspecified(),
                                                   ka.cert().clone())),
                                    });
                            },
                        }
                    }
                }

                (n, MessageLayer::Compression { .. })
                    if n == 0 || n == 1 =>
                {
                    // Do nothing.
                },

                (0, MessageLayer::Encryption { sym_algo, aead_algo, .. }) => {
                    self.result.cipher = Some(sym_algo);
                    self.result.mode = match aead_algo {
                        Some(a) => RnpProtectionMode::Aead(a),
                        None => RnpProtectionMode::CfbMdc,
                    };
                },

                _ => {
                    return Err(
                        anyhow::anyhow!("Unsupported message structure")
                    );
                },
            }
        }

        Ok(())
    }
}

impl<'a> Helper<'a> {
    /// Returns the decryption key with the given keyid.
    fn get_decryption_key(&self, id: &KeyID)
                          -> Option<Key<SecretParts, UnspecifiedRole>>
    {
        rnp_function!(Helper::get_decryption_key, crate::TRACE);
        t!("want key {}", id);
        let ks = self.ctx.certs.read();

        let r = ks.by_subkey_id(id)
            .chain(ks.by_primary_id(id))
            .filter_map(|cert| {
                t!("candidate cert {}", cert.fingerprint());
                match cert.with_policy(&*self.ctx.policy(), None) {
                    Ok(vcert) => {
                        let r = vcert.keys()
                            .secret()
                            .for_storage_encryption()
                            .for_transport_encryption()
                            .key_handle(id).nth(0)
                            .map(|vka| vka.key().clone());

                        // Some diagnostics:
                        if r.is_none() {
                            if vcert.keys()
                                .for_storage_encryption()
                                .for_transport_encryption()
                                .key_handle(id).nth(0).is_some()
                            {
                                t!("the key exists, but we don't have \
                                    the secret");
                            }
                            if let Some(k) = vcert.keys().key_handle(id).nth(0)
                            {
                                t!("the key exists, but it is not \
                                    marked as encryption capable");
                                t!("key flags: {:?}", k.key_flags());
                            }
                        }

                        r
                    },
                    Err(e) => {
                        t!("but it is not valid: {}", e);
                        None
                    },
                }
            })
            .nth(0);
        r
    }

    /// Returns the decryption key with the given keyid.
    fn get_public_key(&self, id: &KeyID)
        -> Option<(Cert, Key<PublicParts, UnspecifiedRole>)>
    {
        rnp_function!(Helper::get_public_key, crate::TRACE);
        t!("want key {}", id);
        let ks = self.ctx.certs.read();

        let r = ks.by_subkey_id(id)
            .chain(ks.by_primary_id(id))
            .filter_map(|cert| {
                t!("candidate cert {}", cert.fingerprint());
                match cert.with_policy(&*self.ctx.policy(), None) {
                    Ok(vcert) => {
                        vcert.keys()
                            .key_handle(id).nth(0)
                            .map(|vka| (cert.clone(), vka.key().clone()))
                    },
                    Err(e) => {
                        t!("but it is not valid: {}", e);
                        None
                    },
                }
            })
            .nth(0);
        r
    }

    /// Tries to decrypt the given PKESK packet with `keypair` and try
    /// to decrypt the packet parser using `decrypt`.
    fn try_decrypt<D>(&self, pkesk: &PKESK,
                      algo: Option<SymmetricAlgorithm>,
                      keypair: &mut dyn crypto::Decryptor,
                      decrypt: &mut D)
                      -> Option<(SymmetricAlgorithm,
                                 SessionKey,
                                 Option<Fingerprint>)>
        where D: FnMut(SymmetricAlgorithm, &SessionKey) -> bool
    {
        let fp = keypair.public().fingerprint();
        let (algo, sk) = pkesk.decrypt(keypair, algo)
            .and_then(|(algo, sk)| {
                if decrypt(algo, &sk) { Some((algo, sk)) } else { None }
            })?;

        // We need the recipient's fingerprint for the intended
        // recipient test.  If `keypair` is a subkey, look up its cert
        // and compute the fingerprint.  Otherwise, `fp` is our
        // identity.

        let ks = self.ctx.certs.read();

        let recipient =
            ks.by_subkey_fp(&fp)
                .filter(|fp| fp.is_tsk())
                .nth(0)
                .map(|cert| cert.fingerprint())
                .unwrap_or(fp);

        Some((algo, sk, Some(recipient)))
    }
}

impl<'a> DecryptionHelper for Helper<'a> {
    fn decrypt<D>(&mut self, pkesks: &[PKESK], skesks: &[SKESK],
                  algo: Option<SymmetricAlgorithm>,
                  mut decrypt: D) -> openpgp::Result<Option<Fingerprint>>
        where D: FnMut(SymmetricAlgorithm, &SessionKey) -> bool
    {
        rnp_function!(Helper::decrypt, crate::TRACE);
        t!("{} PKESKs, {} SKESKs, algo: {:?}",
           pkesks.len(), skesks.len(), algo);

        // Preserve PKESKs and SKESKs for later inspection.
        self.result.pkesks = pkesks.iter().cloned().collect();
        self.result.skesks = skesks.iter().cloned().collect();

        // Even if we happen to be loading a keyring in the
        // background, try the lookup.
        t!("trying to decrypt PKESKs with unencrypted keys");
        for &block in [false, true].iter() {
            if block {
                if let Ok(false) = self.ctx.certs.block_on_load() {
                    // We didn't block.  It is extremely unlikely that
                    // the keystore was updated.
                    t!("we didn't block, breaking out of the loop.");
                    break;
                }
            }

            // First, we try those keys that we can use without
            // prompting for a password.
            for pkesk in pkesks {
                let keyid = pkesk.recipient();
                t!("trying to decrypt PKESK with recipient {}", keyid);
                if let Some(key) = self.get_decryption_key(&keyid) {
                    if ! key.secret().is_encrypted() {
                        if let Some((_algo, _sk, fp)) =
                            key.clone().into_keypair().ok().and_then(|mut k| {
                                self.try_decrypt(pkesk, algo, &mut k, &mut decrypt)
                            })
                        {
                            t!("success!");
                            self.result.pkesk_used = Some(pkesk.clone());
                            return Ok(fp);
                        } else {
                            t!("failure!");
                        }
                    } else {
                        t!("but it is encrypted!");
                    }
                } else {
                    t!("but we don't have that key!");
                }
            }
        }

        // Second, we try to decrypt PKESK packets with wildcard
        // recipients using those keys that we can use without
        // prompting for a password.
        t!("trying to decrypt PKESKs using wildcard recipients with \
            unencrypted keys");
        let ks = self.ctx.certs.read();
        for pkesk in pkesks.iter().filter(|p| p.recipient().is_wildcard()) {
            t!("trying to decrypt PKESK with wildcard recipient...");
            // Get all possible decryption keys from the context.
            for cert in ks.iter().filter(|cert| cert.is_tsk()) {
                 t!("... using cert {}...", cert.fingerprint());

                for key in cert.with_policy(&*self.ctx.policy(), None).ok()
                    .iter()
                    .flat_map(|vcert| vcert.keys()
                              .secret()
                              .for_storage_encryption()
                              .for_transport_encryption()
                              .map(|vka| vka.key().clone()))
                {
                    t!("... and key {}", key.fingerprint());
                    if ! key.secret().is_encrypted() {
                        if let Some((_algo, _sk, fp)) =
                            key.clone().into_keypair().ok().and_then(|mut k| {
                                self.try_decrypt(pkesk, algo, &mut k,
                                                 &mut decrypt)
                            })
                        {
                            t!("success!");
                            self.result.pkesk_used =
                                Some(pkesk.clone());
                            return Ok(fp);
                        } else {
                            t!("failure!");
                        }
                    } else {
                        t!("but it is encrypted!");
                    }
                }
            }
        }
        drop(ks);

        t!("trying to decrypt PKESKs with encrypted keys");
        // Third, we try those keys that are encrypted.
        'next_pkesk: for pkesk in pkesks {
            // Don't ask the user to decrypt a key if we don't support
            // the algorithm.
            if ! pkesk.pk_algo().is_supported() {
                continue;
            }

            let keyid = pkesk.recipient();
            t!("trying to decrypt PKESK with recipient {}", keyid);
            if let Some(key) = self.get_decryption_key(&keyid) {
                let mut keypair =
                    if ! key.secret().is_encrypted() {
                        t!("odd, it is not encrypted, why didn't we \
                            decrypt this PKESK before?");
                        key.clone().into_keypair()?
                    } else {
                        match self.ctx.decrypt_key_for(
                            None, // XXX
                            key.clone(),
                            RnpPasswordFor::Decrypt)
                        {
                            Ok(k) => k.into_keypair()?,
                            Err(_) => {
                                t!("failed to decrypt the key!");
                                break 'next_pkesk;
                            },
                        }
                    };

                if let Some((_algo, _sk, fp)) =
                    self.try_decrypt(pkesk, algo, &mut keypair,
                                     &mut decrypt)
                {
                    t!("success!");
                    self.result.pkesk_used = Some(pkesk.clone());
                    return Ok(fp);
                } else {
                    t!("failure!");
                }
            } else {
                t!("but we don't have that key!");
            }
        }

        t!("trying to decrypt PKESKs with gpg-agent");
        for pkesk in pkesks {
            let keyid = pkesk.recipient();
            t!("trying to decrypt PKESK with recipient {}", keyid);
            if let Some((cert, key)) = self.get_public_key(keyid) {
                let mut pair = ipc::gnupg::KeyPair::new(
                    &ipc::gnupg::Context::new()?, key.parts_as_public())?;
                if let Ok(vcert) = cert.with_policy(&*self.ctx.policy(), None) {
                    pair = pair.with_cert(&vcert);
                }
                if pkesk.decrypt(&mut pair, algo)
                    .map(|(algo, session_key)| decrypt(algo, &session_key))
                    .unwrap_or(false)
                {
                    t!("success!");
                    self.result.pkesk_used = Some(pkesk.clone());
                    return Ok(Some(cert.fingerprint()));
                } else {
                    t!("failure!");
                }
            } else {
                t!("but we don't even have that cert!");
            }
        }

        if skesks.is_empty() {
            t!("decryption using PKESKs failed and there are no SKESKs");
            return
                Err(anyhow::anyhow!("No key to decrypt message"));
        }

        // Finally, try to decrypt using the SKESKs.
        //for password in self.passwords.iter() {
        //    for skesk in skesks {
        //        if let Some((algo, sk)) = skesk.decrypt(password).ok()
        //            .and_then(|(algo, sk)| {
        //                if decrypt(algo, &sk) {
        //                    Some((algo, sk))
        //                } else {
        //                    None
        //                }
        //            })
        //        {
        //            return Ok(None);
        //        }
        //    }
        //}
        t!("decryption using SKESKs is not supported by Thunderbird, \
            giving up");

        Err(anyhow::anyhow!("Decryption failed"))
    }
}
