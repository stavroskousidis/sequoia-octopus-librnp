use std::{
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

use crate::{
    P,
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

#[derive(Debug, Default)]
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
    fn verification_error(&self) -> Option<RnpResult> {
        for s in &self.signatures {
            if s.status != RNP_SUCCESS {
                return Some(s.status);
            }
        }
        None
    }
}

#[derive(Debug)]
pub struct RnpOpVerifySignature {
    ctx: *mut RnpContext,
    status: RnpResult,
    sig: Signature,
    key: Option<Key<UnspecifiedParts, UnspecifiedRole>>,
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
    assert_ptr!(op);
    assert_ptr!(ctx);
    assert_ptr!(input);
    assert_ptr!(output);

    *op = Box::into_raw(Box::new(RnpOpVerify {
        ctx: &mut *ctx,
        input: &mut *input,
        mode: SignatureMode::Inline(&mut *output),
        result: Default::default(),
    }));
    RNP_SUCCESS
}

#[no_mangle] pub unsafe extern "C"
fn rnp_op_verify_detached_create<'a>(op: *mut *mut RnpOpVerify<'a>,
                                     ctx: *mut RnpContext,
                                     input: *mut RnpInput,
                                     signature: *mut RnpInput)
                                     -> RnpResult
{
    assert_ptr!(op);
    assert_ptr!(ctx);
    assert_ptr!(input);
    assert_ptr!(signature);

    *op = Box::into_raw(Box::new(RnpOpVerify {
        ctx: &mut *ctx,
        input: &mut *input,
        mode: SignatureMode::Detached(&mut *signature),
        result: Default::default(),
    }));
    RNP_SUCCESS
}

#[no_mangle] pub unsafe extern "C"
fn rnp_op_verify_destroy(op: *mut RnpOpVerify) -> RnpResult {
    if ! op.is_null() {
        drop(Box::from_raw(op));
    }
    RNP_SUCCESS
}

#[no_mangle] pub unsafe extern "C"
fn rnp_op_verify_execute(op: *mut RnpOpVerify) -> RnpResult {
    rnp_function!(rnp_op_verify_execute, crate::TRACE);
    let op = assert_ptr_mut!(op);

    fn f(op: &mut RnpOpVerify) -> openpgp::Result<()> {
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
                    .and_then(|b| b.with_policy(P, None, h))
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
                    .with_policy(P, None, h)?;
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
                    .with_policy(P, None, h)?;
                v.verify_reader(&mut op.input)?;
                t!("Verification without decryption successful: {:#?}",
                   op.result);
            },
        }
        Ok(())
    }

    if let Err(e) = f(op) {
        if op.result.encrypted_message()
            && ! op.result.decrypted_successfully()
        {
            _warn!("failed to decrypt: {}", e);
            RNP_ERROR_DECRYPT_FAILED
        } else if let Some(status) = op.result.verification_error() {
            _warn!("failed to verify sig: {}", e);
            status
        } else {
            _warn!("{}", e);
            RNP_ERROR_GENERIC
        }
    } else {
        RNP_SUCCESS
    }
}

#[no_mangle] pub unsafe extern "C"
fn rnp_op_verify_get_signature_at(op: *mut RnpOpVerify,
                                  idx: size_t,
                                  signature: *mut *const RnpOpVerifySignature)
                                  -> RnpResult {
    rnp_function!(rnp_op_verify_get_signature_at, crate::TRACE);
    let op = assert_ptr_ref!(op);
    assert_ptr!(signature);

    if let Some(s) = op.result.signatures.get(idx) {
        *signature = s as *const _;
        RNP_SUCCESS
    } else {
        RNP_ERROR_BAD_PARAMETERS
    }
}

#[no_mangle] pub unsafe extern "C"
fn rnp_op_verify_get_signature_count(op: *mut RnpOpVerify,
                                     count: *mut size_t)
                                     -> RnpResult {
    rnp_function!(rnp_op_verify_get_signature_count, crate::TRACE);
    let op = assert_ptr_ref!(op);
    assert_ptr!(count);
    *count = op.result.signatures.len();
    RNP_SUCCESS
}

#[no_mangle] pub unsafe extern "C"
fn rnp_op_verify_signature_get_handle(sig: *mut RnpOpVerifySignature,
                                      handle: *mut *mut RnpSignature)
                                      -> RnpResult {
    assert_ptr!(sig);
    assert_ptr!(handle);
    let sig = &*sig;
    *handle =
        Box::into_raw(Box::new(RnpSignature::new(sig.ctx, sig.sig.clone())));
    RNP_SUCCESS
}

#[no_mangle] pub unsafe extern "C"
fn rnp_op_verify_signature_get_status(sig: *mut RnpOpVerifySignature)
                                      -> RnpResult {
    assert_ptr!(sig);
    (*sig).status
}

#[no_mangle] pub unsafe extern "C"
fn rnp_op_verify_signature_get_key(sig: *mut RnpOpVerifySignature,
                                   // XXX: I think we want the signing
                                   // key here.
                                   key: *mut *mut RnpKey)
                                   -> RnpResult {
    assert_ptr!(sig);
    assert_ptr!(key);
    *key = if let Some(key) = (*sig).key.as_ref().cloned() {
        Box::into_raw(Box::new(RnpKey::new((*sig).ctx, key)))
    } else {
        std::ptr::null_mut()
    };
    RNP_SUCCESS
}

#[no_mangle] pub unsafe extern "C"
fn rnp_op_verify_signature_get_times(sig: *mut RnpOpVerifySignature,
                                     created: *mut u32,
                                     expires: *mut u32)
                                     -> RnpResult {
    use std::time::UNIX_EPOCH;
    assert_ptr!(sig);
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
    RNP_SUCCESS
}

#[no_mangle] pub unsafe extern "C"
fn rnp_op_verify_get_protection_info(op: *mut RnpOpVerify,
                                     mode: *mut *mut c_char,
                                     cipher: *mut *mut c_char,
                                     valid: *mut bool)
                                     -> RnpResult {
    rnp_function!(rnp_op_verify_get_protection_info, crate::TRACE);
    let op = assert_ptr_ref!(op);

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
    RNP_SUCCESS
}

#[no_mangle] pub unsafe extern "C"
fn rnp_op_verify_get_used_recipient(op: *mut RnpOpVerify,
                                    pkesk: *mut *const PKESK)
                                    -> RnpResult {
    rnp_function!(rnp_op_verify_get_used_recipient, crate::TRACE);
    let op = assert_ptr_ref!(op);
    assert_ptr!(pkesk);

    *pkesk = op.result.pkesk_used.as_ref().map(|p| p as *const _)
        .unwrap_or(std::ptr::null());
    RNP_SUCCESS
}

#[no_mangle] pub unsafe extern "C"
fn rnp_op_verify_get_recipient_at(op: *mut RnpOpVerify,
                                  idx: size_t,
                                  pkesk: *mut *const PKESK)
                                  -> RnpResult {
    rnp_function!(rnp_op_verify_get_recipient_at, crate::TRACE);
    let op = assert_ptr_ref!(op);
    assert_ptr!(pkesk);

    if let Some(p) = op.result.pkesks.get(idx) {
        *pkesk = p as *const _;
        RNP_SUCCESS
    } else {
        RNP_ERROR_BAD_PARAMETERS
    }
}

#[no_mangle] pub unsafe extern "C"
fn rnp_op_verify_get_recipient_count(op: *mut RnpOpVerify,
                                     count: *mut size_t)
                                     -> RnpResult {
    rnp_function!(rnp_op_verify_get_recipient_count, crate::TRACE);
    let op = assert_ptr_ref!(op);
    assert_ptr!(count);
    *count = op.result.pkesks.len();
    RNP_SUCCESS
}

#[no_mangle] pub unsafe extern "C"
fn rnp_recipient_get_keyid(recipient: *const PKESK,
                           keyid: *mut *mut c_char)
                           -> RnpResult {
    assert_ptr!(recipient);
    assert_ptr!(keyid);
    *keyid = str_to_rnp_buffer(format!("{:X}", (*recipient).recipient()));
    RNP_SUCCESS
}

#[no_mangle] pub unsafe extern "C"
fn rnp_recipient_get_alg(recipient: *const PKESK,
                         alg: *mut *mut c_char)
                         -> RnpResult {
    assert_ptr!(recipient);
    assert_ptr!(alg);
    *alg = str_to_rnp_buffer((*recipient).pk_algo().to_rnp_id());
    RNP_SUCCESS
}

#[no_mangle] pub unsafe extern "C"
fn rnp_op_verify_get_used_symenc(op: *mut RnpOpVerify,
                                 skesk: *mut *const SKESK)
                                 -> RnpResult {
    rnp_function!(rnp_op_verify_get_used_symenc, crate::TRACE);
    let op = assert_ptr_ref!(op);
    assert_ptr!(skesk);
    *skesk = op.result.skesk_used.as_ref().map(|p| p as *const _)
        .unwrap_or(std::ptr::null());
    RNP_SUCCESS
}

#[no_mangle] pub unsafe extern "C"
fn rnp_op_verify_get_symenc_at(op: *mut RnpOpVerify,
                               idx: size_t,
                               skesk: *mut *const SKESK)
                               -> RnpResult {
    rnp_function!(rnp_op_verify_get_symenc_at, crate::TRACE);
    let op = assert_ptr_ref!(op);
    assert_ptr!(skesk);
    if let Some(p) = op.result.skesks.get(idx) {
        *skesk = p as *const _;
        RNP_SUCCESS
    } else {
        RNP_ERROR_BAD_PARAMETERS
    }
}

#[no_mangle] pub unsafe extern "C"
fn rnp_op_verify_get_symenc_count(op: *mut RnpOpVerify,
                                  count: *mut size_t)
                                  -> RnpResult {
    rnp_function!(rnp_op_verify_get_symenc_count, crate::TRACE);
    let op = assert_ptr_ref!(op);
    assert_ptr!(count);
    *count = op.result.skesks.len();
    RNP_SUCCESS
}

struct Helper<'a> {
    ctx: &'a mut RnpContext,
    result: &'a mut RnpOpVerifyResult,
}

impl<'a> VerificationHelper for Helper<'a> {
    fn get_certs(&mut self, ids: &[KeyHandle])
                 -> openpgp::Result<Vec<Cert>> {
        Ok(ids.iter().filter_map(|id| self.ctx.cert(&id.into())).collect())
    }

    fn check(&mut self, structure: MessageStructure) -> openpgp::Result<()> {
        use self::VerificationError::*;

        let n_layers = structure.iter().count();
        for (i, layer) in structure.into_iter().enumerate() {
            match (i, layer) {
                (i, MessageLayer::SignatureGroup { results })
                    if i == n_layers - 1 =>
                {
                    for result in results {
                        match result {
                            Ok(GoodChecksum { sig, ka, .. }) => {
                                self.result.signatures.push(
                                    RnpOpVerifySignature {
                                        ctx: self.ctx as *mut _,
                                        status: RNP_SUCCESS,
                                        sig: sig.clone(),
                                        key: Some(ka.key().clone()
                                                  .parts_into_unspecified()),
                                    });
                            },
                            Err(MalformedSignature { sig, .. }) => {
                                self.result.signatures.push(
                                    RnpOpVerifySignature {
                                        ctx: self.ctx as *mut _,
                                        status: RNP_ERROR_SIGNATURE_INVALID,
                                        sig: sig.clone(),
                                        key: None,
                                    });
                            },
                            Err(MissingKey { sig, .. }) => {
                                self.result.signatures.push(
                                    RnpOpVerifySignature {
                                        ctx: self.ctx as *mut _,
                                        status: RNP_ERROR_KEY_NOT_FOUND,
                                        sig: sig.clone(),
                                        key: None,
                                    });
                            },
                            Err(UnboundKey { sig, .. }) => {
                                self.result.signatures.push(
                                    RnpOpVerifySignature {
                                        ctx: self.ctx as *mut _,
                                        status: RNP_ERROR_SIGNATURE_INVALID,
                                        sig: sig.clone(),
                                        key: None,
                                    });
                            },
                            Err(BadKey { sig, ka, .. }) => {
                                self.result.signatures.push(
                                    RnpOpVerifySignature {
                                        ctx: self.ctx as *mut _,
                                        status: RNP_ERROR_SIGNATURE_INVALID,
                                        sig: sig.clone(),
                                        key: Some(ka.key().clone()
                                                  .parts_into_unspecified()),
                                    });
                            },
                            Err(BadSignature { sig, ka, .. }) => {
                                self.result.signatures.push(
                                    RnpOpVerifySignature {
                                        ctx: self.ctx as *mut _,
                                        status: if sig.signature_alive(None, None).is_err() {
                                            RNP_ERROR_SIGNATURE_EXPIRED
                                        } else {
                                            RNP_ERROR_SIGNATURE_INVALID
                                        },
                                        sig: sig.clone(),
                                        key: Some(ka.key().clone()
                                                  .parts_into_unspecified()),
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
        self.ctx.keys.by_subkey_id(id)
            .chain(self.ctx.keys.by_primary_id(id))
            .nth(0)
            .and_then(|cert| {
                cert.with_policy(P, None).ok()
                    .and_then(|vcert| vcert.keys()
                              .secret()
                              .for_storage_encryption()
                              .for_transport_encryption()
                              .key_handle(id).nth(0))
                    .map(|vka| vka.key().clone())
            })
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
        let recipient =
            self.ctx.keys.by_subkey_fp(&fp)
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
        // Preserve PKESKs and SKESKs for later inspection.
        self.result.pkesks = pkesks.iter().cloned().collect();
        self.result.skesks = skesks.iter().cloned().collect();

        // First, we try those keys that we can use without prompting
        // for a password.
        for pkesk in pkesks {
            let keyid = pkesk.recipient();
            if let Some(key) = self.get_decryption_key(&keyid) {
                if ! key.secret().is_encrypted() {
                    if let Some((_algo, _sk, fp)) =
                        key.clone().into_keypair().ok().and_then(|mut k| {
                            self.try_decrypt(pkesk, algo, &mut k, &mut decrypt)
                        })
                    {
                        self.result.pkesk_used = Some(pkesk.clone());
                        return Ok(fp);
                    }
                }
            }
        }

        // Second, we try to decrypt PKESK packets with wildcard
        // recipients using those keys that we can use without
        // prompting for a password.
        for pkesk in pkesks.iter().filter(|p| p.recipient().is_wildcard()) {
            // Get all possible decryption keys from the context.
            for cert in self.ctx.keys.iter() {
                for key in cert.with_policy(P, None).ok()
                    .iter()
                    .flat_map(|vcert| vcert.keys()
                              .secret()
                              .for_storage_encryption()
                              .for_transport_encryption()
                              .map(|vka| vka.key().clone()))
                {
                    if ! key.secret().is_encrypted() {
                        if let Some((_algo, _sk, fp)) =
                            key.clone().into_keypair().ok().and_then(|mut k| {
                                self.try_decrypt(pkesk, algo, &mut k,
                                                 &mut decrypt)
                            })
                        {
                            self.result.pkesk_used =
                                Some(pkesk.clone());
                            return Ok(fp);
                        }
                    }
                }
            }
        }

        // Third, we try those keys that are encrypted.
        'next_pkesk: for pkesk in pkesks {
            // Don't ask the user to decrypt a key if we don't support
            // the algorithm.
            if ! pkesk.pk_algo().is_supported() {
                continue;
            }

            let keyid = pkesk.recipient();
            if let Some(key) = self.get_decryption_key(&keyid) {
                let mut keypair =
                    if ! key.secret().is_encrypted() {
                        key.clone().into_keypair()?
                    } else {
                        match self.ctx.decrypt_key_for(
                            None, // XXX
                            key.clone(),
                            RnpPasswordFor::Decrypt)
                        {
                            Ok(k) => k.into_keypair()?,
                            Err(_) => break 'next_pkesk,
                        }
                    };

                if let Some((_algo, _sk, fp)) =
                    self.try_decrypt(pkesk, algo, &mut keypair,
                                     &mut decrypt)
                {
                    self.result.pkesk_used = Some(pkesk.clone());
                    return Ok(fp);
                }
            }
        }

        if skesks.is_empty() {
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

        Err(anyhow::anyhow!("Decryption failed"))
    }
}
