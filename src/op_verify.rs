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

use sequoia_gpg_agent::gnupg;

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
    flags::*,
};

/// Controls tracing in this module.
const TRACE: bool = crate::TRACE;

pub struct RnpOpVerify<'a> {
    ctx: &'a mut RnpContext,
    input: &'a mut RnpInput,
    mode: SignatureMode<'a>,
    flags: RnpOpVerifyFlags,
    result: RnpOpVerifyResult,
}

/// The flags set using rnp_op_verify_set_flags.
#[derive(Clone, Copy, Debug, Default)]
struct RnpOpVerifyFlags {
    /// RNP_VERIFY_IGNORE_SIGS_ON_DECRYPT.
    ///
    /// We never fail a decryption because of the signatures, so we
    /// only record this flag.
    #[allow(dead_code)]
    ignore_sigs_on_decrypt: bool,

    /// RNP_VERIFY_REQUIRE_ALL_SIGS.
    require_all_sigs: bool,

    /// RNP_VERIFY_ALLOW_HIDDEN_RECIPIENT.
    allow_hidden_recipient: bool,
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

    // The number of signatures that we could not make sense of, and
    // that are hence not in `signatures`.
    unknown_signatures: usize,
}

impl fmt::Debug for RnpOpVerifyResult {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("RnpOpVerifyResult")
            .field("mode", &self.mode)
            .field("cipher", &self.cipher)
            .field("pkesks", &self.pkesks.iter().map(|pkesk| {
                pkesk.recipient().map(|r| r.to_hex())
                    .unwrap_or_else(|| "<anonymous>".into())
            }).collect::<Vec<String>>())
            .field("skesk count", &self.skesks.len())
            .field("pkesk_used", &self.pkesk_used.as_ref().map(|pkesk| {
                self.pkesks.iter().position(|x| x == pkesk).expect("added")
            }))
            .field("skesk_used", &self.skesk_used.as_ref().map(|skesk| {
                self.skesks.iter().position(|x| x == skesk).expect("added")
            }))
            .field("signatures", &self.signatures)
            .field("unknown_signatures", &self.unknown_signatures)
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
        flags: Default::default(),
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
        flags: Default::default(),
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

/// Sets flags that control the verification or decryption.
///
/// All flags are set at once: a flag that is not present is unset.
///
///   - `RNP_VERIFY_IGNORE_SIGS_ON_DECRYPT`: Don't fail the
///     decryption because of invalid signatures.  This is what we
///     always do: `rnp_op_verify_execute` reports the status of the
///     signatures separately.
///
///   - `RNP_VERIFY_REQUIRE_ALL_SIGS`: Let `rnp_op_verify_execute`
///     fail with `RNP_ERROR_SIGNATURE_INVALID` unless all signatures
///     are valid.
///
///   - `RNP_VERIFY_ALLOW_HIDDEN_RECIPIENT`: When decrypting a
///     message with a hidden recipient, also try the secret keys
///     that are password protected, asking for their passwords.
///     Note: unlike RNP, we always try the secret keys that are not
///     password protected, whether or not this flag is set.
#[no_mangle] pub unsafe extern "C"
fn rnp_op_verify_set_flags(op: *mut RnpOpVerify,
                           flags: RnpVerifyFlags)
                           -> RnpResult {
    rnp_function!(rnp_op_verify_set_flags, crate::TRACE);
    let op = assert_ptr_mut!(op);
    arg!(flags);

    op.flags = RnpOpVerifyFlags {
        ignore_sigs_on_decrypt:
            flags & RNP_VERIFY_IGNORE_SIGS_ON_DECRYPT > 0,
        require_all_sigs:
            flags & RNP_VERIFY_REQUIRE_ALL_SIGS > 0,
        allow_hidden_recipient:
            flags & RNP_VERIFY_ALLOW_HIDDEN_RECIPIENT > 0,
    };

    // Like RNP, we apply the flags that we know before we complain
    // about those that we don't.
    let unknown = flags & ! (RNP_VERIFY_IGNORE_SIGS_ON_DECRYPT
                             | RNP_VERIFY_REQUIRE_ALL_SIGS
                             | RNP_VERIFY_ALLOW_HIDDEN_RECIPIENT);
    if unknown > 0 {
        warn!("unknown flags: {:x}", unknown);
        rnp_return_status!(RNP_ERROR_BAD_PARAMETERS);
    }
    rnp_success!()
}

#[no_mangle] pub unsafe extern "C"
fn rnp_op_verify_execute(op: *mut RnpOpVerify) -> RnpResult {
    rnp_function!(rnp_op_verify_execute, crate::TRACE);
    let op = assert_ptr_mut!(op);

    fn f(op: &mut RnpOpVerify) -> openpgp::Result<()> {
        let policy = op.ctx.policy().clone();
        let allow_hidden_recipient = op.flags.allow_hidden_recipient;
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
                    allow_hidden_recipient,
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
                    allow_hidden_recipient,
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
                    allow_hidden_recipient,
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
    } else if op.flags.require_all_sigs
        && (op.result.verification_error().is_some()
            || op.result.unknown_signatures > 0)
    {
        // The caller requires all signatures to be valid.  That
        // includes those that we could not make sense of.
        warn!("not all signatures are valid");
        RNP_ERROR_SIGNATURE_INVALID
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
    let r = (*recipient).recipient();
    *keyid = str_to_rnp_buffer(format!("{:X}", match r {
        Some(KeyHandle::KeyID(i)) => i.clone(),
        Some(KeyHandle::Fingerprint(i)) => i.into(),
        // XXX: Best effort given the API.
        None => KeyID::wildcard(),
    }));
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
    /// Whether RNP_VERIFY_ALLOW_HIDDEN_RECIPIENT is set.
    allow_hidden_recipient: bool,
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
                           key.key().fingerprint(), cert.fingerprint());
                        return Some((key.parts_as_unspecified().key().clone(),
                                     cert.clone()));
                    }
                }
            }

            for h in sig.get_issuers() {
                if let Some(cert) = ctx.cert_by_subkey_handle(&h) {
                    if let Some(key) = cert.keys().key_handle(h).nth(0) {
                        t!("success: key {}, cert {}",
                           key.key().fingerprint(), cert.fingerprint());
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
                                   i, signo, ka.key().fingerprint(), error);
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
                                   i, signo, ka.key().fingerprint(), error);
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
                            Err(UnknownSignature { sig, .. }) => {
                                t!("Signature {}.{}: unknown signature: {}",
                                   i, signo, sig.error());
                                // XXX: Not sure what to do with it.
                                self.result.unknown_signatures += 1;
                            },
                            Err(e) => {
                                t!("Signature {}.{}: {}", i, signo, e);
                                // XXX: Not sure what to do with it.
                                self.result.unknown_signatures += 1;
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
    fn try_decrypt(&self, pkesk: &PKESK,
                   algo: Option<SymmetricAlgorithm>,
                   keypair: &mut dyn crypto::Decryptor,
                   decrypt: &mut dyn FnMut(Option<SymmetricAlgorithm>, &SessionKey) -> bool)
                   -> Option<(Option<SymmetricAlgorithm>,
                              SessionKey,
                              Option<Cert>)>
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

        // First, try a subkey lookup.
        let mut recipient =
            ks.by_subkey_fp(&fp)
                .filter(|fp| fp.is_tsk())
                .nth(0)
                .map(|cert| cert.clone().strip_secret_key_material());

        // Then lookup as cert, unlikely as that may be.
        if recipient.is_none() {
            recipient = ks.by_fp(&fp)
                .filter(|fp| fp.is_tsk())
                .nth(0)
                .map(|cert| cert.clone().strip_secret_key_material());
        }

        Some((algo, sk, recipient))
    }
}

impl<'a> DecryptionHelper for Helper<'a> {
    fn decrypt(&mut self, pkesks: &[PKESK], skesks: &[SKESK],
               algo: Option<SymmetricAlgorithm>,
               decrypt: &mut dyn FnMut(Option<SymmetricAlgorithm>, &SessionKey) -> bool)
               -> openpgp::Result<Option<Cert>>
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
                let keyid = if let Some(r) = pkesk.recipient() {
                    KeyID::from(r)
                } else {
                    // Skip anonymous recipients.
                    continue;
                };

                t!("trying to decrypt PKESK with recipient {:?}", keyid);
                if let Some(key) = self.get_decryption_key(&keyid) {
                    if ! key.secret().is_encrypted() {
                        if let Some((_algo, _sk, fp)) =
                            key.clone().into_keypair().ok().and_then(|mut k| {
                                self.try_decrypt(pkesk, algo, &mut k, decrypt)
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
        for pkesk in pkesks.iter().filter(|p| p.recipient().is_none()) {
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
                                self.try_decrypt(pkesk, algo, &mut k, decrypt)
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

            let keyid = if let Some(r) = pkesk.recipient() {
                KeyID::from(r)
            } else {
                // Skip anonymous recipients.
                continue;
            };

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
                    self.try_decrypt(pkesk, algo, &mut keypair, decrypt)
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

        // Fourth, if the caller allows hidden recipients, we try to
        // decrypt PKESK packets with wildcard recipients using those
        // keys that are encrypted.  Like RNP, we ask for the password
        // of every secret key that could decrypt the PKESK.
        if self.allow_hidden_recipient
            && pkesks.iter().any(|p| p.recipient().is_none())
        {
            t!("trying to decrypt PKESKs using wildcard recipients with \
                encrypted keys");

            // Get all possible decryption keys from the context.  We
            // must not hold the lock on the keystore while we ask for
            // passwords.
            let mut keys = Vec::new();
            let ks = self.ctx.certs.read();
            for cert in ks.iter().filter(|cert| cert.is_tsk()) {
                for key in cert.with_policy(&*self.ctx.policy(), None).ok()
                    .iter()
                    .flat_map(|vcert| vcert.keys()
                              .secret()
                              .for_storage_encryption()
                              .for_transport_encryption()
                              .map(|vka| vka.key().clone()))
                {
                    if key.secret().is_encrypted() {
                        keys.push(key);
                    }
                }
            }
            drop(ks);

            for pkesk in pkesks.iter().filter(|p| p.recipient().is_none()) {
                // Don't ask the user to decrypt a key if we don't
                // support the algorithm.
                if ! pkesk.pk_algo().is_supported() {
                    continue;
                }

                t!("trying to decrypt PKESK with wildcard recipient...");
                for key in keys.iter()
                    .filter(|key| key.pk_algo() == pkesk.pk_algo())
                {
                    t!("... using key {}", key.fingerprint());
                    let mut keypair = match self.ctx.decrypt_key_for(
                        None, // XXX
                        key.clone(),
                        RnpPasswordFor::Decrypt)
                        .and_then(|k| k.into_keypair())
                    {
                        Ok(k) => k,
                        Err(_) => {
                            t!("failed to decrypt the key!");
                            continue;
                        },
                    };

                    if let Some((_algo, _sk, fp)) =
                        self.try_decrypt(pkesk, algo, &mut keypair, decrypt)
                    {
                        t!("success!");
                        self.result.pkesk_used = Some(pkesk.clone());
                        return Ok(fp);
                    } else {
                        t!("failure!");
                    }
                }
            }
        }

        t!("trying to decrypt PKESKs with gpg-agent");
        for pkesk in pkesks {
            let keyid = if let Some(r) = pkesk.recipient() {
                KeyID::from(r)
            } else {
                // Skip anonymous recipients.
                continue;
            };

            t!("trying to decrypt PKESK with recipient {}", keyid);
            if let Some((cert, key)) = self.get_public_key(&keyid) {
                match gnupg::Context::new() {
                    Ok(ctx) =>
                        match sequoia_gpg_agent::KeyPair::new_for_gnupg_context(
                            &ctx, key.parts_as_public())
                    {
                        Ok(mut pair) => {
                            if let Ok(vcert) = cert.with_policy(
                                &*self.ctx.policy(), None)
                            {
                                pair = pair.with_cert(&vcert);
                            }
                            if pkesk.decrypt(&mut pair, algo)
                                .map(|(algo, session_key)|
                                     decrypt(algo, &session_key))
                                .unwrap_or(false)
                            {
                                t!("success!");
                                self.result.pkesk_used = Some(pkesk.clone());
                                return Ok(Some(cert.clone()));
                            } else {
                                t!("failure!");
                            }
                        },
                        Err(e) =>
                            t!("but gpg-agent failed: {}", e),
                    },
                    Err(e) =>
                        t!("but creating the GnuPG context failed: {}", e),
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

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::ptr::null_mut;

    use super::*;
    use libc::c_void;

    use openpgp::{
        cert::CertBuilder,
        policy::StandardPolicy,
        serialize::{
            MarshalInto,
            stream::{
                Encryptor,
                LiteralWriter,
                Message,
                Recipient,
                Signer,
            },
        },
        types::Features,
    };

    use crate::rnp_ffi_create;
    use crate::rnp_ffi_destroy;
    use crate::rnp_ffi_set_pass_provider;
    use crate::rnp_input_destroy;
    use crate::rnp_input_from_memory;
    use crate::rnp_output_destroy;
    use crate::rnp_output_memory_get_buf;
    use crate::rnp_output_to_memory;
    use crate::import::rnp_import_keys;

    const MESSAGE: &[u8] = b"Hello World :)";

    macro_rules! rnp_try {
        ($e: expr) => {{
            let r = unsafe { $e };
            assert_eq!(r, RNP_SUCCESS.as_u32());
        }}
    }

    /// Creates a context and imports the certificates, including any
    /// secret key material.
    fn ctx_with_certs(certs: &[&Cert]) -> *mut RnpContext {
        let mut ctx: *mut RnpContext = null_mut();
        rnp_try!(rnp_ffi_create(
            &mut ctx as *mut *mut _,
            b"GPG\x00".as_ptr() as *const c_char,
            b"GPG\x00".as_ptr() as *const c_char));

        for cert in certs {
            let buffer = cert.as_tsk().to_vec().unwrap();
            let mut input: *mut RnpInput = null_mut();
            rnp_try!(rnp_input_from_memory(
                &mut input as *mut *mut _,
                buffer.as_ptr(), buffer.len(), false));
            rnp_try!(rnp_import_keys(
                ctx, input,
                RNP_LOAD_SAVE_PUBLIC_KEYS
                    | RNP_LOAD_SAVE_SECRET_KEYS,
                null_mut() as *mut *mut _));
            rnp_try!(rnp_input_destroy(input));
        }

        ctx
    }

    /// The result of a verification or decryption operation.
    #[derive(Debug, PartialEq, Eq)]
    struct Outcome {
        /// What rnp_op_verify_execute returned.
        status: RnpResult,
        /// What rnp_op_verify_signature_get_status returned for each
        /// signature.
        signatures: Vec<RnpResult>,
        /// The content of the output.
        output: Vec<u8>,
    }

    /// Verifies or decrypts `message`.
    ///
    /// If `detached` is given, `message` is the signed data and
    /// `detached` the signature.  If `flags` is given, they are set
    /// using rnp_op_verify_set_flags.
    fn execute(ctx: *mut RnpContext, message: &[u8],
               detached: Option<&[u8]>, flags: Option<RnpVerifyFlags>)
               -> Outcome
    {
        let mut input: *mut RnpInput = null_mut();
        rnp_try!(rnp_input_from_memory(
            &mut input as *mut *mut _,
            message.as_ptr(), message.len(), false));

        let mut output: *mut RnpOutput = null_mut();
        rnp_try!(rnp_output_to_memory(&mut output as *mut *mut _, 0));

        let mut signature: *mut RnpInput = null_mut();
        let mut op: *mut RnpOpVerify = null_mut();
        if let Some(detached) = detached {
            rnp_try!(rnp_input_from_memory(
                &mut signature as *mut *mut _,
                detached.as_ptr(), detached.len(), false));
            rnp_try!(rnp_op_verify_detached_create(
                &mut op as *mut *mut _, ctx, input, signature));
        } else {
            rnp_try!(rnp_op_verify_create(
                &mut op as *mut *mut _, ctx, input, output));
        }

        if let Some(flags) = flags {
            rnp_try!(rnp_op_verify_set_flags(op, flags));
        }

        let status = unsafe { rnp_op_verify_execute(op) };

        let mut count = 0;
        rnp_try!(rnp_op_verify_get_signature_count(op, &mut count as *mut _));
        let mut signatures = Vec::new();
        for i in 0..count {
            let mut sig: *const RnpOpVerifySignature = std::ptr::null();
            rnp_try!(rnp_op_verify_get_signature_at(
                op, i, &mut sig as *mut *const _));
            signatures.push(
                unsafe { rnp_op_verify_signature_get_status(sig) });
        }

        let mut buf: *mut u8 = null_mut();
        let mut len: size_t = 0;
        rnp_try!(rnp_output_memory_get_buf(
            output,
            &mut buf as *mut *mut _,
            &mut len as *mut _,
            false));
        let output_data = if len > 0 {
            unsafe { std::slice::from_raw_parts(buf, len) }.to_vec()
        } else {
            Vec::new()
        };

        rnp_try!(rnp_op_verify_destroy(op));
        if ! signature.is_null() {
            rnp_try!(rnp_input_destroy(signature));
        }
        rnp_try!(rnp_input_destroy(input));
        rnp_try!(rnp_output_destroy(output));

        Outcome {
            status,
            signatures,
            output: output_data,
        }
    }

    /// Returns a signer for the certificate's signing subkey.
    fn signer(cert: &Cert) -> openpgp::crypto::KeyPair {
        let p = &StandardPolicy::new();
        cert.keys().with_policy(p, None).secret().for_signing()
            .next().unwrap().key().clone().into_keypair().unwrap()
    }

    /// Signs MESSAGE using the certificates' signing subkeys.
    fn sign(certs: &[&Cert], detached: bool) -> openpgp::Result<Vec<u8>> {
        let mut sink = Vec::new();
        let message = Message::new(&mut sink);
        let mut signer_ = Signer::new(message, signer(certs[0]))?;
        for cert in &certs[1..] {
            signer_ = signer_.add_signer(signer(cert))?;
        }
        if detached {
            let mut message = signer_.detached().build()?;
            message.write_all(MESSAGE)?;
            message.finalize()?;
        } else {
            let mut message =
                LiteralWriter::new(signer_.build()?).build()?;
            message.write_all(MESSAGE)?;
            message.finalize()?;
        }
        Ok(sink)
    }

    /// Encrypts MESSAGE to the certificates' encryption subkeys
    /// without naming the recipients in the PKESK packets.
    fn encrypt_hidden(certs: &[&Cert]) -> openpgp::Result<Vec<u8>> {
        let p = &StandardPolicy::new();
        let mut keys = Vec::new();
        for cert in certs {
            keys.push(
                cert.keys().with_policy(p, None).for_transport_encryption()
                    .next().unwrap().key().clone());
        }
        let recipients = keys.iter()
            .map(|key| Recipient::new(None::<Features>,
                                      None::<KeyHandle>,
                                      key))
            .collect::<Vec<_>>();

        let mut sink = Vec::new();
        let message = Message::new(&mut sink);
        let message =
            Encryptor::for_recipients(message, recipients).build()?;
        let mut message = LiteralWriter::new(message).build()?;
        message.write_all(MESSAGE)?;
        message.finalize()?;

        // Make sure that we test what we mean to test.
        let ppr = openpgp::PacketPile::from_bytes(&sink)?;
        let mut pkesks = 0;
        for packet in ppr.descendants() {
            if let openpgp::Packet::PKESK(pkesk) = packet {
                assert!(pkesk.recipient().is_none());
                pkesks += 1;
            }
        }
        assert_eq!(pkesks, certs.len());

        Ok(sink)
    }

    #[test]
    fn set_flags() -> openpgp::Result<()> {
        let ctx = ctx_with_certs(&[]);

        let mut input: *mut RnpInput = null_mut();
        rnp_try!(rnp_input_from_memory(
            &mut input as *mut *mut _,
            MESSAGE.as_ptr(), MESSAGE.len(), false));
        let mut output: *mut RnpOutput = null_mut();
        rnp_try!(rnp_output_to_memory(&mut output as *mut *mut _, 0));
        let mut op: *mut RnpOpVerify = null_mut();
        rnp_try!(rnp_op_verify_create(
            &mut op as *mut *mut _, ctx, input, output));

        let flags = |op: *mut RnpOpVerify| {
            let f = unsafe { &*op }.flags;
            (f.ignore_sigs_on_decrypt,
             f.require_all_sigs,
             f.allow_hidden_recipient)
        };

        // By default, no flag is set.
        assert_eq!(flags(op), (false, false, false));

        // All flags are set at once: a flag that is not present is
        // unset.
        for f in 0..8u32 {
            rnp_try!(rnp_op_verify_set_flags(op, f));
            assert_eq!(flags(op), (f & 1 > 0, f & 2 > 0, f & 4 > 0));
        }
        rnp_try!(rnp_op_verify_set_flags(
            op,
            RNP_VERIFY_IGNORE_SIGS_ON_DECRYPT
                | RNP_VERIFY_REQUIRE_ALL_SIGS
                | RNP_VERIFY_ALLOW_HIDDEN_RECIPIENT));
        assert_eq!(flags(op), (true, true, true));
        rnp_try!(rnp_op_verify_set_flags(op, 0));
        assert_eq!(flags(op), (false, false, false));

        // The values are those of RNP's rnp.h.
        assert_eq!(RNP_VERIFY_IGNORE_SIGS_ON_DECRYPT, 1);
        assert_eq!(RNP_VERIFY_REQUIRE_ALL_SIGS, 2);
        assert_eq!(RNP_VERIFY_ALLOW_HIDDEN_RECIPIENT, 4);

        // Unknown flags are an error, but like RNP we apply the
        // known ones first.
        let r = unsafe {
            rnp_op_verify_set_flags(op, 8 | RNP_VERIFY_REQUIRE_ALL_SIGS)
        };
        assert_eq!(r, RNP_ERROR_BAD_PARAMETERS.as_u32());
        assert_eq!(flags(op), (false, true, false));
        let r = unsafe { rnp_op_verify_set_flags(op, 1 << 31) };
        assert_eq!(r, RNP_ERROR_BAD_PARAMETERS.as_u32());
        assert_eq!(flags(op), (false, false, false));

        let r = unsafe { rnp_op_verify_set_flags(null_mut(), 0) };
        assert_eq!(r, RNP_ERROR_NULL_POINTER.as_u32());

        rnp_try!(rnp_op_verify_destroy(op));
        rnp_try!(rnp_input_destroy(input));
        rnp_try!(rnp_output_destroy(output));
        rnp_try!(rnp_ffi_destroy(ctx));
        Ok(())
    }

    #[test]
    fn require_all_sigs() -> openpgp::Result<()> {
        let ok = RNP_SUCCESS.as_u32();
        let invalid = RNP_ERROR_SIGNATURE_INVALID.as_u32();
        let not_found = RNP_ERROR_KEY_NOT_FOUND.as_u32();

        let (alice, _) = CertBuilder::general_purpose(Some("alice"))
            .generate()?;
        let (bob, _) = CertBuilder::general_purpose(Some("bob"))
            .generate()?;

        // We know Alice's certificate, but not Bob's.
        let alice_pub = alice.clone().strip_secret_key_material();
        let ctx = ctx_with_certs(&[&alice_pub]);

        let without = [
            None,
            Some(0),
            Some(RNP_VERIFY_IGNORE_SIGS_ON_DECRYPT),
            Some(RNP_VERIFY_ALLOW_HIDDEN_RECIPIENT),
        ];
        let with = [
            Some(RNP_VERIFY_REQUIRE_ALL_SIGS),
            Some(RNP_VERIFY_REQUIRE_ALL_SIGS
                 | RNP_VERIFY_IGNORE_SIGS_ON_DECRYPT),
        ];

        // One good signature: the flag makes no difference.
        let by_alice = sign(&[&alice], false)?;
        for flags in without.iter().chain(with.iter()) {
            assert_eq!(execute(ctx, &by_alice, None, *flags),
                       Outcome {
                           status: ok,
                           signatures: vec![ok],
                           output: MESSAGE.to_vec(),
                       },
                       "flags {:?}", flags);
        }

        // One good signature, and one that we cannot check.
        let by_both = sign(&[&alice, &bob], false)?;
        for flags in without {
            let outcome = execute(ctx, &by_both, None, flags);
            assert_eq!(outcome.status, ok, "flags {:?}", flags);
            let mut signatures = outcome.signatures.clone();
            signatures.sort();
            assert_eq!(signatures, vec![ok, not_found], "flags {:?}", flags);
        }
        for flags in with {
            let outcome = execute(ctx, &by_both, None, flags);
            assert_eq!(outcome.status, invalid, "flags {:?}", flags);
            let mut signatures = outcome.signatures.clone();
            signatures.sort();
            assert_eq!(signatures, vec![ok, not_found], "flags {:?}", flags);
        }

        // A detached signature over different data.
        let detached = sign(&[&alice], true)?;
        for flags in without.iter().chain(with.iter()) {
            assert_eq!(execute(ctx, MESSAGE, Some(&detached), *flags),
                       Outcome {
                           status: ok,
                           signatures: vec![ok],
                           output: vec![],
                       },
                       "flags {:?}", flags);
        }
        for flags in without {
            assert_eq!(execute(ctx, b"Other data", Some(&detached), flags),
                       Outcome {
                           status: ok,
                           signatures: vec![invalid],
                           output: vec![],
                       },
                       "flags {:?}", flags);
        }
        for flags in with {
            assert_eq!(execute(ctx, b"Other data", Some(&detached), flags),
                       Outcome {
                           status: invalid,
                           signatures: vec![invalid],
                           output: vec![],
                       },
                       "flags {:?}", flags);
        }

        // A good signature followed by a signature packet that we
        // cannot parse.  We do not report the latter, but it is not
        // a valid signature.
        let mut unknown = openpgp::packet::Unknown::new(
            openpgp::packet::Tag::Signature,
            anyhow::anyhow!("unsupported version"));
        unknown.set_body(vec![23, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
        let unknown = openpgp::Packet::from(unknown).to_vec()?;
        let mut with_unknown = detached.clone();
        with_unknown.extend_from_slice(&unknown);
        for flags in without {
            assert_eq!(execute(ctx, MESSAGE, Some(&with_unknown), flags),
                       Outcome {
                           status: ok,
                           signatures: vec![ok],
                           output: vec![],
                       },
                       "flags {:?}", flags);
        }
        for flags in with {
            assert_eq!(execute(ctx, MESSAGE, Some(&with_unknown), flags),
                       Outcome {
                           status: invalid,
                           signatures: vec![ok],
                           output: vec![],
                       },
                       "flags {:?}", flags);
        }

        rnp_try!(rnp_ffi_destroy(ctx));
        Ok(())
    }

    /// What the password callback is supposed to do.
    struct Passwords {
        /// The password to return, if any.
        password: Option<&'static str>,
        /// How often the callback was invoked.
        calls: usize,
    }

    unsafe extern "C" fn password_cb(_ctx: *mut RnpContext,
                                     cookie: *mut c_void,
                                     _key: *const RnpKey,
                                     _pgp_context: *const c_char,
                                     buf: *mut c_char,
                                     buf_len: size_t)
                                     -> bool {
        let passwords = &mut *(cookie as *mut Passwords);
        passwords.calls += 1;
        if let Some(password) = passwords.password {
            assert!(password.len() < buf_len);
            std::ptr::copy_nonoverlapping(
                password.as_ptr(), buf as *mut u8, password.len());
            *buf.add(password.len()) = 0;
            true
        } else {
            false
        }
    }

    #[test]
    fn hidden_recipient() -> openpgp::Result<()> {
        let ok = RNP_SUCCESS.as_u32();
        let failed = RNP_ERROR_DECRYPT_FAILED.as_u32();
        let decrypted = Outcome {
            status: ok,
            signatures: vec![],
            output: MESSAGE.to_vec(),
        };
        let not_decrypted = Outcome {
            status: failed,
            signatures: vec![],
            output: vec![],
        };

        // Alice's and Bob's secret keys are password protected,
        // Carol's are not.
        let (alice, _) = CertBuilder::general_purpose(Some("alice"))
            .set_password(Some("alice's password".into()))
            .generate()?;
        let (bob, _) = CertBuilder::general_purpose(Some("bob"))
            .set_password(Some("bob's password".into()))
            .generate()?;
        let (carol, _) = CertBuilder::general_purpose(Some("carol"))
            .generate()?;
        for cert in [&alice, &bob] {
            assert!(cert.keys().secret()
                    .all(|ka| ka.key().secret().is_encrypted()));
        }
        assert!(carol.keys().secret()
                .all(|ka| ! ka.key().secret().is_encrypted()));

        let for_alice = encrypt_hidden(&[&alice])?;
        let for_carol = encrypt_hidden(&[&carol])?;

        let without = [
            None,
            Some(0),
            Some(RNP_VERIFY_IGNORE_SIGS_ON_DECRYPT
                 | RNP_VERIFY_REQUIRE_ALL_SIGS),
        ];
        let with = [
            Some(RNP_VERIFY_ALLOW_HIDDEN_RECIPIENT),
            Some(RNP_VERIFY_ALLOW_HIDDEN_RECIPIENT
                 | RNP_VERIFY_REQUIRE_ALL_SIGS),
        ];

        let ctx = ctx_with_certs(&[&alice, &bob, &carol]);
        let mut passwords = Passwords { password: None, calls: 0 };
        rnp_try!(rnp_ffi_set_pass_provider(
            ctx, password_cb, &mut passwords as *mut _ as *mut c_void));

        // Without the flag, we try the keys that are not password
        // protected and never ask for a password.  This is what we
        // did before rnp_op_verify_set_flags existed.
        passwords.password = Some("alice's password");
        for flags in without {
            assert_eq!(execute(ctx, &for_carol, None, flags), decrypted,
                       "flags {:?}", flags);
            assert_eq!(execute(ctx, &for_alice, None, flags), not_decrypted,
                       "flags {:?}", flags);
        }
        assert_eq!(passwords.calls, 0);

        for flags in with {
            // With the flag, we don't need a password for the keys
            // that are not password protected.
            passwords.calls = 0;
            passwords.password = None;
            assert_eq!(execute(ctx, &for_carol, None, flags), decrypted,
                       "flags {:?}", flags);
            assert_eq!(passwords.calls, 0);

            // We ask for the password of every password protected
            // key that could decrypt the message: Alice's and Bob's.
            assert_eq!(execute(ctx, &for_alice, None, flags), not_decrypted,
                       "flags {:?}", flags);
            assert_eq!(passwords.calls, 2);

            // A wrong password does not help.
            passwords.calls = 0;
            passwords.password = Some("not the password");
            assert_eq!(execute(ctx, &for_alice, None, flags), not_decrypted,
                       "flags {:?}", flags);
            assert_eq!(passwords.calls, 2);

            // The right one does.
            passwords.calls = 0;
            passwords.password = Some("alice's password");
            assert_eq!(execute(ctx, &for_alice, None, flags), decrypted,
                       "flags {:?}", flags);
            assert!(passwords.calls >= 1 && passwords.calls <= 2);
        }

        rnp_try!(rnp_ffi_destroy(ctx));
        Ok(())
    }

    /// RFC 9980, Section 3.5: the signature algorithms of RFC 9980
    /// are to be used only in v6 keys, and Sections 5.3.1 and 6.2.1:
    /// only with v6 signatures.
    ///
    /// A signature made by a v4 key using such an algorithm is not a
    /// good signature, although it is cryptographically valid.
    ///
    /// Making such a signature requires a cryptographic backend that
    /// supports the algorithm.  With the other backends, this only
    /// tests that we cannot make one.
    #[test]
    fn rfc9980_key_version_binding_signatures() -> openpgp::Result<()> {
        use crate::testdata::key_version_binding::*;

        let ok = RNP_SUCCESS.as_u32();
        let invalid = RNP_ERROR_SIGNATURE_INVALID.as_u32();

        for algo in FAST_SIGNATURE_ALGORITHMS {
            if ! algo.is_supported() {
                assert!(v4_cert_with_primary_key(algo).is_err());
                eprintln!("{} is not supported by the cryptographic \
                           backend, not testing a v4 signature",
                          algo);
                continue;
            }

            let cert = v4_cert_with_primary_key(algo)?;
            let keypair = cert.primary_key().key().clone()
                .parts_into_secret()?.into_keypair()?;
            let cert = cert.strip_secret_key_material();
            let ctx = ctx_with_certs(&[&cert]);

            for detached in [false, true] {
                let mut sink = Vec::new();
                let message = Message::new(&mut sink);
                let signer = Signer::new(message, keypair.clone())?;
                if detached {
                    let mut message = signer.detached().build()?;
                    message.write_all(MESSAGE)?;
                    message.finalize()?;
                } else {
                    let mut message =
                        LiteralWriter::new(signer.build()?).build()?;
                    message.write_all(MESSAGE)?;
                    message.finalize()?;
                }

                // Make sure that we test what we mean to test: this
                // is a v4 signature using the algorithm, and it is
                // cryptographically valid.
                let ppr = openpgp::PacketPile::from_bytes(&sink)?;
                let sigs = ppr.descendants().filter_map(|p| match p {
                    openpgp::Packet::Signature(s) => Some(s.clone()),
                    _ => None,
                }).collect::<Vec<_>>();
                assert_eq!(sigs.len(), 1);
                assert_eq!(sigs[0].version(), 4);
                assert_eq!(sigs[0].pk_algo(), algo);
                if detached {
                    sigs[0].clone().verify_message(
                        cert.primary_key().key(), MESSAGE)?;
                }

                let (message, signature) = if detached {
                    (MESSAGE, Some(&sink[..]))
                } else {
                    (&sink[..], None)
                };

                // The operation succeeds, like it does for any other
                // signature that is not good, and the signature is
                // reported as invalid.
                let outcome = execute(ctx, message, signature, None);
                assert_eq!(outcome.status, ok,
                           "{}, detached: {}", algo, detached);
                assert_eq!(outcome.signatures, vec![invalid],
                           "{}, detached: {}", algo, detached);

                let outcome = execute(ctx, message, signature,
                                      Some(RNP_VERIFY_REQUIRE_ALL_SIGS));
                assert_eq!(outcome.status, invalid,
                           "{}, detached: {}", algo, detached);
                assert_eq!(outcome.signatures, vec![invalid],
                           "{}, detached: {}", algo, detached);
            }

            rnp_try!(rnp_ffi_destroy(ctx));
        }
        Ok(())
    }

    /// RFC 9980, Section 3.5: ML-KEM-768+X25519 is allowed in v4
    /// encryption subkeys, ML-KEM-1024+X448 is not.
    ///
    /// We do not decrypt with a v4 ML-KEM-1024+X448 subkey, although
    /// we have the secret key.
    ///
    /// Making the keys requires a cryptographic backend that supports
    /// the algorithms.  With the other backends, this only tests that
    /// we cannot make them.
    #[test]
    fn rfc9980_key_version_binding_decryption() -> openpgp::Result<()> {
        use openpgp::types::PublicKeyAlgorithm;
        use crate::testdata::key_version_binding::*;

        for algo in [PublicKeyAlgorithm::MLKEM768_X25519,
                     PublicKeyAlgorithm::MLKEM1024_X448]
        {
            if ! algo.is_supported() {
                assert!(v4_cert_with_kem_subkey(algo).is_err());
                eprintln!("{} is not supported by the cryptographic \
                           backend, not testing decryption with a v4 \
                           subkey", algo);
                continue;
            }
            let allowed = algo == PublicKeyAlgorithm::MLKEM768_X25519;

            let cert = v4_cert_with_kem_subkey(algo)?;
            let subkey = cert.keys().subkeys().next().unwrap().key().clone();
            assert_eq!(subkey.pk_algo(), algo);

            // Encrypt MESSAGE to the subkey, using a v6 PKESK packet
            // and a v2 SEIPD packet.
            let recipient = Recipient::new(
                Features::empty().set_seipdv2(),
                Some(openpgp::KeyHandle::from(subkey.fingerprint())),
                &subkey);
            let mut sink = Vec::new();
            let message = Message::new(&mut sink);
            let message =
                Encryptor::for_recipients(message, vec![recipient]).build()?;
            let mut message = LiteralWriter::new(message).build()?;
            message.write_all(MESSAGE)?;
            message.finalize()?;

            // Make sure that we test what we mean to test.
            let ppr = openpgp::PacketPile::from_bytes(&sink)?;
            let pkesks = ppr.descendants().filter_map(|p| match p {
                openpgp::Packet::PKESK(p) => Some(p.clone()),
                _ => None,
            }).collect::<Vec<_>>();
            assert_eq!(pkesks.len(), 1);
            assert_eq!(pkesks[0].pk_algo(), algo);

            let ctx = ctx_with_certs(&[&cert]);
            let outcome = execute(ctx, &sink, None, None);
            if allowed {
                assert_eq!(outcome,
                           Outcome {
                               status: RNP_SUCCESS.as_u32(),
                               signatures: vec![],
                               output: MESSAGE.to_vec(),
                           },
                           "{}", algo);
            } else {
                assert_eq!(outcome,
                           Outcome {
                               status: RNP_ERROR_DECRYPT_FAILED.as_u32(),
                               signatures: vec![],
                               output: vec![],
                           },
                           "{}", algo);
            }
            rnp_try!(rnp_ffi_destroy(ctx));
        }
        Ok(())
    }

    /// What the interface reports about a signature.
    #[derive(Debug, PartialEq, Eq)]
    struct SignatureInfo {
        /// What rnp_op_verify_signature_get_status returned.
        status: RnpResult,
        /// The fingerprint of the key that
        /// rnp_op_verify_signature_get_key returned, if any.
        key: Option<String>,
        /// The creation time that rnp_op_verify_signature_get_times
        /// returned.
        created: u32,
        /// What rnp_signature_get_hash_alg returned for the
        /// signature's handle.
        hash: String,
        /// What rnp_signature_get_keyid returned for the signature's
        /// handle.
        keyid: Option<String>,
        /// What rnp_signature_is_valid returned for the signature's
        /// handle.
        valid: RnpResult,
    }

    /// Verifies the detached `signature` over `data`, and returns
    /// what the interface reports about each signature.
    fn signature_info(ctx: *mut RnpContext, data: &[u8], signature: &[u8])
                      -> Vec<SignatureInfo>
    {
        use std::ffi::CStr;
        use crate::buffer::rnp_buffer_destroy;
        use crate::key::{rnp_key_get_fprint, rnp_key_handle_destroy};
        use crate::signature::{
            RnpSignature,
            rnp_signature_get_hash_alg,
            rnp_signature_get_keyid,
            rnp_signature_handle_destroy,
            rnp_signature_is_valid,
        };

        // Returns the string, and frees the buffer.
        let take = |s: *mut c_char| -> Option<String> {
            if s.is_null() {
                None
            } else {
                let r = unsafe { CStr::from_ptr(s) }.to_str().unwrap()
                    .to_string();
                unsafe { rnp_buffer_destroy(s as *mut c_void) };
                Some(r)
            }
        };

        let mut input: *mut RnpInput = null_mut();
        rnp_try!(rnp_input_from_memory(
            &mut input as *mut *mut _, data.as_ptr(), data.len(), false));
        let mut sig_input: *mut RnpInput = null_mut();
        rnp_try!(rnp_input_from_memory(
            &mut sig_input as *mut *mut _,
            signature.as_ptr(), signature.len(), false));
        let mut op: *mut RnpOpVerify = null_mut();
        rnp_try!(rnp_op_verify_detached_create(
            &mut op as *mut *mut _, ctx, input, sig_input));
        rnp_try!(rnp_op_verify_execute(op));

        let mut count = 0;
        rnp_try!(rnp_op_verify_get_signature_count(op, &mut count as *mut _));
        let mut result = Vec::new();
        for i in 0..count {
            let mut sig: *const RnpOpVerifySignature = std::ptr::null();
            rnp_try!(rnp_op_verify_get_signature_at(
                op, i, &mut sig as *mut *const _));
            let status = unsafe { rnp_op_verify_signature_get_status(sig) };

            let mut key: *mut RnpKey = null_mut();
            let r = unsafe {
                rnp_op_verify_signature_get_key(sig, &mut key as *mut *mut _)
            };
            let key = if key.is_null() {
                assert_eq!(r, RNP_ERROR_KEY_NOT_FOUND.as_u32());
                None
            } else {
                assert_eq!(r, RNP_SUCCESS.as_u32());
                let mut fp: *mut c_char = null_mut();
                rnp_try!(rnp_key_get_fprint(key, &mut fp as *mut *mut _));
                rnp_try!(rnp_key_handle_destroy(key));
                take(fp)
            };

            let mut created: u32 = 0;
            let mut expires: u32 = 0;
            rnp_try!(rnp_op_verify_signature_get_times(
                sig, &mut created as *mut _, &mut expires as *mut _));
            assert_eq!(expires, 0);

            let mut handle: *mut RnpSignature = null_mut();
            rnp_try!(rnp_op_verify_signature_get_handle(
                sig, &mut handle as *mut *mut _));
            let mut hash: *mut c_char = null_mut();
            rnp_try!(rnp_signature_get_hash_alg(
                handle, &mut hash as *mut *mut _));
            let mut keyid: *mut c_char = null_mut();
            rnp_try!(rnp_signature_get_keyid(
                handle, &mut keyid as *mut *mut _));
            let valid = unsafe { rnp_signature_is_valid(handle, 0) };
            rnp_try!(rnp_signature_handle_destroy(handle));

            result.push(SignatureInfo {
                status,
                key,
                created,
                hash: take(hash).unwrap(),
                keyid: take(keyid),
                valid,
            });
        }

        rnp_try!(rnp_op_verify_destroy(op));
        rnp_try!(rnp_input_destroy(sig_input));
        rnp_try!(rnp_input_destroy(input));
        result
    }

    /// Returns whether the cryptographic backend supports the
    /// algorithm.  For the algorithms of RFC 9980, this also makes
    /// sure that this is what we expect where we know the backend.
    ///
    /// The tests of the signatures of RFC 9980 show one thing with a
    /// backend that supports the algorithms, and another with a
    /// backend that does not.  This makes sure that they show what
    /// they are meant to show with the backends that we know.
    fn supported(algo: openpgp::types::PublicKeyAlgorithm) -> bool {
        let supported = algo.is_supported();
        if (30..=36).contains(&u8::from(algo)) {
            if let Some(expected) =
                crate::testdata::rfc9980::backend_has_rfc9980()
            {
                assert_eq!(supported, expected,
                           "{} with {}", algo, openpgp::crypto::backend());
            }
        }
        supported
    }

    /// Returns the signature packets in `data`.
    fn signature_packets(data: &[u8]) -> Vec<Signature> {
        openpgp::PacketPile::from_bytes(data).unwrap()
            .descendants().filter_map(|p| match p {
                openpgp::Packet::Signature(s) => Some(s.clone()),
                _ => None,
            }).collect()
    }

    /// Verifies the detached signatures of RFC 9980, Appendix A.
    ///
    /// These are v6 signatures using each of the five signature
    /// algorithms of RFC 9980.  They are good if the cryptographic
    /// backend supports the algorithm.  Otherwise we cannot verify
    /// them, and they are reported as invalid.
    #[test]
    fn rfc9980_detached_signatures() -> openpgp::Result<()> {
        use std::time::UNIX_EPOCH;
        use openpgp::types::{PublicKeyAlgorithm, SignatureType};
        use crate::testdata::rfc9980::*;

        let ok = RNP_SUCCESS.as_u32();
        let invalid = RNP_ERROR_SIGNATURE_INVALID.as_u32();
        let not_found = RNP_ERROR_KEY_NOT_FOUND.as_u32();

        let mut algos = Vec::new();
        for s in SIGNATURES {
            let v = s.signer();
            let algo = PublicKeyAlgorithm::from(v.primary.algo);
            algos.push(v.primary.algo);

            // Make sure that we test what we mean to test.
            let sig = s.packet();
            assert_eq!(sig.version(), 6, "{}", s.section);
            // A signature over a text document: the data is hashed
            // with its line endings converted to CR LF.
            assert_eq!(sig.typ(), SignatureType::Text, "{}", s.section);
            assert_eq!(sig.pk_algo(), algo, "{}", s.section);
            assert_eq!(sig.issuer_fingerprints()
                       .map(|fp| fp.to_hex()).collect::<Vec<_>>(),
                       vec![v.primary.fingerprint], "{}", s.section);
            assert!(sig.hash_algo().digest_size()? * 8 >= 256,
                    "{}", s.section);
            let created = sig.signature_creation_time().unwrap()
                .duration_since(UNIX_EPOCH)?.as_secs() as u32;
            let binary = openpgp::Packet::from(sig.clone()).to_vec()?;

            let status = if supported(algo) { ok } else { invalid };
            let info = |status| SignatureInfo {
                status,
                key: Some(v.primary.fingerprint.into()),
                created,
                hash: sig.hash_algo().to_rnp_id().into(),
                // The key ID of a v6 key is the first 64 bits of its
                // fingerprint, RFC 9580, Section 5.5.4.3.
                keyid: Some(v.primary.fingerprint[..16].into()),
                valid: status,
            };

            let ctx = ctx_with_certs(&[&v.cert()]);
            for signature in [s.signature, &binary[..]] {
                // The signature over the signed data.
                assert_eq!(signature_info(ctx, SIGNED_DATA, signature),
                           vec![info(status)], "{}", s.section);

                let outcome =
                    execute(ctx, SIGNED_DATA, Some(signature), None);
                assert_eq!(outcome.status, ok, "{}", s.section);
                assert_eq!(outcome.signatures, vec![status],
                           "{}", s.section);

                let outcome = execute(ctx, SIGNED_DATA, Some(signature),
                                      Some(RNP_VERIFY_REQUIRE_ALL_SIGS));
                assert_eq!(outcome.status, status, "{}", s.section);
                assert_eq!(outcome.signatures, vec![status],
                           "{}", s.section);

                // The signature over other data.
                for data in [&SIGNED_DATA[..SIGNED_DATA.len() - 1],
                             &b"Testing\n\n"[..],
                             &b"testing\n"[..],
                             &b""[..]]
                {
                    assert_eq!(signature_info(ctx, data, signature),
                               vec![info(invalid)],
                               "{}, {:?}", s.section, data);

                    let outcome = execute(ctx, data, Some(signature), None);
                    assert_eq!(outcome.status, ok, "{}", s.section);
                    assert_eq!(outcome.signatures, vec![invalid],
                               "{}, {:?}", s.section, data);

                    let outcome = execute(ctx, data, Some(signature),
                                          Some(RNP_VERIFY_REQUIRE_ALL_SIGS));
                    assert_eq!(outcome.status, invalid, "{}", s.section);
                }
            }
            rnp_try!(rnp_ffi_destroy(ctx));

            // Without the certificate.
            let ctx = ctx_with_certs(&[]);
            assert_eq!(signature_info(ctx, SIGNED_DATA, s.signature),
                       vec![SignatureInfo {
                           status: not_found,
                           key: None,
                           valid: invalid,
                           ..info(not_found)
                       }], "{}", s.section);
            rnp_try!(rnp_ffi_destroy(ctx));
        }

        // These are the signature algorithms of RFC 9980, Section 2.1.
        assert_eq!(algos, vec![30, 31, 32, 33, 34]);
        Ok(())
    }

    /// RFC 9980, Section 5.2.3: a composite signature is valid only
    /// if both of its component signatures are valid.
    ///
    /// Modifies the detached signatures of RFC 9980, Appendix A, one
    /// octet at a time.  For the composites, that is one component
    /// signature at a time.
    ///
    /// With a cryptographic backend that does not support the
    /// algorithms, this shows nothing: there, the unmodified
    /// signatures are reported as invalid, too.
    #[test]
    fn rfc9980_modified_signatures() -> openpgp::Result<()> {
        use openpgp::crypto::mpi;
        use openpgp::types::PublicKeyAlgorithm;
        use crate::testdata::rfc9980::*;
        use crate::testdata::signatures::signature_size;

        let ok = RNP_SUCCESS.as_u32();
        let invalid = RNP_ERROR_SIGNATURE_INVALID.as_u32();

        // Returns the component signatures.
        let components = |sig: &Signature| -> (Vec<u8>, Vec<u8>) {
            match sig.mpis() {
                mpi::Signature::MLDSA65_Ed25519 { eddsa, mldsa } =>
                    (eddsa.to_vec(), mldsa.to_vec()),
                mpi::Signature::MLDSA87_Ed448 { eddsa, mldsa } =>
                    (eddsa.to_vec(), mldsa.to_vec()),
                mpi::Signature::SLHDSA128s { sig } => (vec![], sig.to_vec()),
                mpi::Signature::SLHDSA128f { sig } => (vec![], sig.to_vec()),
                mpi::Signature::SLHDSA256s { sig } => (vec![], sig.to_vec()),
                s => panic!("unexpected signature: {:?}", s),
            }
        };

        let mut composites = 0;
        for s in SIGNATURES {
            let v = s.signer();
            let algo = PublicKeyAlgorithm::from(v.primary.algo);
            let supported = supported(algo);

            let sig = s.packet();
            let binary = openpgp::Packet::from(sig.clone()).to_vec()?;
            let (first, second) = components(&sig);
            // The sizes are those of RFC 9980, Tables 6, 7, and 8,
            // and the component signatures are the last octets of the
            // packet.
            assert_eq!(Some((first.len(), second.len())),
                       signature_size(v.primary.algo));
            let offset_first = binary.len() - second.len() - first.len();
            let offset_second = binary.len() - second.len();
            assert_eq!(&binary[offset_first..offset_second], &first[..]);
            assert_eq!(&binary[offset_second..], &second[..]);

            let ctx = ctx_with_certs(&[&v.cert()]);

            // The signature is good to begin with.
            let outcome = execute(ctx, SIGNED_DATA, Some(&binary), None);
            assert_eq!(outcome.signatures,
                       vec![if supported { ok } else { invalid }],
                       "{}", s.section);

            // The first, a middle, and the last octet of each
            // component signature.
            let mut offsets = vec![
                (false, offset_second),
                (false, offset_second + second.len() / 2),
                (false, binary.len() - 1),
            ];
            if ! first.is_empty() {
                composites += 1;
                offsets.extend_from_slice(&[
                    (true, offset_first),
                    (true, offset_first + first.len() / 2),
                    (true, offset_second - 1),
                ]);
            }

            for (in_first, offset) in offsets {
                let mut modified = binary.clone();
                modified[offset] ^= 1;

                // Make sure that we test what we mean to test: only
                // one of the component signatures differs.
                let sigs = signature_packets(&modified);
                assert_eq!(sigs.len(), 1);
                assert_ne!(sigs[0], sig);
                let (f, s_) = components(&sigs[0]);
                assert_eq!(f != first, in_first,
                           "{}, offset {}", s.section, offset);
                assert_eq!(s_ != second, ! in_first,
                           "{}, offset {}", s.section, offset);

                let outcome =
                    execute(ctx, SIGNED_DATA, Some(&modified), None);
                assert_eq!(outcome.status, ok,
                           "{}, offset {}", s.section, offset);
                assert_eq!(outcome.signatures, vec![invalid],
                           "{}, offset {}", s.section, offset);

                let outcome =
                    execute(ctx, SIGNED_DATA, Some(&modified),
                            Some(RNP_VERIFY_REQUIRE_ALL_SIGS));
                assert_eq!(outcome.status, invalid,
                           "{}, offset {}", s.section, offset);
            }
            rnp_try!(rnp_ffi_destroy(ctx));
        }

        // ML-DSA-65+Ed25519 and ML-DSA-87+Ed448.
        assert_eq!(composites, 2);
        Ok(())
    }

    /// Returns the primary key of the Transferable Secret Key of RFC
    /// 9980, Appendix A with its secret key material.
    fn rfc9980_primary_key(v: &crate::testdata::rfc9980::TestVector)
        -> Key<openpgp::packet::key::SecretParts,
               openpgp::packet::key::PrimaryRole>
    {
        let tsk = Cert::from_bytes(v.tsk).unwrap();
        tsk.primary_key().key().clone().parts_into_secret().unwrap()
    }

    /// Signs MESSAGE with the key using the hash algorithm.
    fn sign_with_hash(keypair: openpgp::crypto::KeyPair,
                      hash_algo: openpgp::types::HashAlgorithm,
                      detached: bool)
                      -> openpgp::Result<Vec<u8>>
    {
        use openpgp::packet::signature::SignatureBuilder;
        use openpgp::types::SignatureType;

        if detached {
            let mut keypair = keypair;
            let sig = SignatureBuilder::new(SignatureType::Binary)
                .set_hash_algo(hash_algo)
                .sign_message(&mut keypair, MESSAGE)?;
            openpgp::Packet::from(sig).to_vec()
        } else {
            let mut sink = Vec::new();
            let message = Message::new(&mut sink);
            let signer = Signer::new(message, keypair)?.hash_algo(hash_algo)?;
            let mut message = LiteralWriter::new(signer.build()?).build()?;
            message.write_all(MESSAGE)?;
            message.finalize()?;
            Ok(sink)
        }
    }

    /// RFC 9980, Sections 5.3.1 and 6.2.1: a signature using one of
    /// the signature algorithms of RFC 9980 and a hash algorithm with
    /// a digest size of less than 256 bits must be rejected.
    ///
    /// SHA2-224 is the one such hash algorithm that Sequoia verifies
    /// v6 signatures with.  The signatures are made with the sample
    /// keys of RFC 9980, Appendix A.
    ///
    /// Making the signatures requires a cryptographic backend that
    /// supports the algorithms.  With the other backends, this only
    /// tests that the rule does not affect other algorithms.
    #[test]
    fn rfc9980_digest_size() -> openpgp::Result<()> {
        use openpgp::types::{HashAlgorithm, PublicKeyAlgorithm};
        use crate::testdata::rfc9980::*;
        use crate::testdata::signatures::{can_sign_using, expected_signers};

        let ok = RNP_SUCCESS.as_u32();
        let invalid = RNP_ERROR_SIGNATURE_INVALID.as_u32();

        // Verifies MESSAGE and the signatures in `signed`.  Returns
        // the status of the signatures, with and without
        // RNP_VERIFY_REQUIRE_ALL_SIGS.
        let verify = |ctx, signed: &[u8], detached: bool| {
            let (message, signature) = if detached {
                (MESSAGE, Some(signed))
            } else {
                (signed, None)
            };
            let outcome = execute(ctx, message, signature, None);
            assert_eq!(outcome.status, ok);
            assert_eq!(outcome.signatures.len(), 1);
            if ! detached {
                assert_eq!(outcome.output, MESSAGE);
            }

            let all = execute(ctx, message, signature,
                              Some(RNP_VERIFY_REQUIRE_ALL_SIGS));
            assert_eq!(all.signatures, outcome.signatures);
            (outcome.signatures[0], all.status)
        };

        let mut tested = Vec::new();
        for v in VECTORS {
            let algo = PublicKeyAlgorithm::from(v.primary.algo);
            let rfc9980 = (30..=34).contains(&v.primary.algo);
            if v.version != 6 {
                // A v4 key makes v4 signatures.
                assert!(! rfc9980);
                continue;
            }
            if ! supported(algo) {
                assert!(rfc9980);
                eprintln!("{} is not supported by the cryptographic \
                           backend, not testing the digest size", algo);
                continue;
            }
            if ! can_sign_using(algo) {
                eprintln!("{}: signing is too slow with {}, not testing \
                           the digest size",
                          algo, openpgp::crypto::backend());
                continue;
            }

            let key = rfc9980_primary_key(v);
            let ctx = ctx_with_certs(&[&v.cert()]);

            // Signing with ML-DSA is fast.  With SLH-DSA, we make as
            // few signatures as possible.
            let fast = ! rfc9980 || matches!(
                algo,
                PublicKeyAlgorithm::MLDSA65_Ed25519
                    | PublicKeyAlgorithm::MLDSA87_Ed448);
            let hashes: &[HashAlgorithm] = if fast {
                &[HashAlgorithm::SHA224,
                  HashAlgorithm::SHA256,
                  HashAlgorithm::SHA384,
                  HashAlgorithm::SHA512,
                  HashAlgorithm::SHA3_256,
                  HashAlgorithm::SHA3_512]
            } else {
                &[HashAlgorithm::SHA224, HashAlgorithm::SHA256]
            };
            // Inline signatures only with hash algorithms that
            // Sequoia's streaming signer offers.
            let inline = |hash_algo| fast && matches!(
                hash_algo, HashAlgorithm::SHA224 | HashAlgorithm::SHA512);

            for &hash_algo in hashes {
                if ! hash_algo.is_supported() {
                    // Nettle does not support SHA3.
                    assert!(! rfc9980);
                    continue;
                }
                let good = ! rfc9980 || hash_algo != HashAlgorithm::SHA224;

                for detached in [true, false] {
                    if ! detached && ! inline(hash_algo) {
                        continue;
                    }
                    let signed = sign_with_hash(
                        key.clone().into_keypair()?, hash_algo, detached)?;

                    // Make sure that we test what we mean to test:
                    // this is a v6 signature using the algorithms,
                    // and it is cryptographically valid.
                    let sigs = signature_packets(&signed);
                    assert_eq!(sigs.len(), 1);
                    assert_eq!(sigs[0].version(), 6);
                    assert_eq!(sigs[0].pk_algo(), algo);
                    assert_eq!(sigs[0].hash_algo(), hash_algo);
                    if detached {
                        sigs[0].clone().verify_message(&key, MESSAGE)?;
                    }

                    assert_eq!(verify(ctx, &signed, detached),
                               if good { (ok, ok) } else { (invalid, invalid) },
                               "{}, {}, detached: {}",
                               v.section, hash_algo, detached);
                }
            }

            rnp_try!(rnp_ffi_destroy(ctx));
            tested.push(v.primary.algo);
        }

        // Make sure that we tested what we mean to test.
        match expected_signers() {
            Some(expected) => assert_eq!(tested, expected),
            None => assert!(tested.contains(&27)),
        }
        Ok(())
    }

    /// RFC 9980, Sections 5.3.1 and 6.2.1: the signature algorithms
    /// of RFC 9980 must be used only with v6 signatures.
    ///
    /// A v4 signature that is made with the key material of a v6 key,
    /// and that names the v6 key as its issuer, is invalid.  (A v4
    /// signature of a v4 key is invalid because of the key, see
    /// `rfc9980_key_version_binding_signatures`.)
    ///
    /// Making such a signature requires a cryptographic backend that
    /// supports the algorithm.  With the other backends, this tests
    /// nothing.
    #[test]
    fn rfc9980_signature_version() -> openpgp::Result<()> {
        use openpgp::packet::signature::SignatureBuilder;
        use openpgp::types::{PublicKeyAlgorithm, SignatureType};
        use crate::testdata::rfc9980::*;
        use crate::testdata::key_version_binding::FAST_SIGNATURE_ALGORITHMS;
        use crate::testdata::signatures::v4_key_with_material_of;

        let ok = RNP_SUCCESS.as_u32();
        let invalid = RNP_ERROR_SIGNATURE_INVALID.as_u32();

        let mut tested = 0;
        for v in VECTORS {
            let algo = PublicKeyAlgorithm::from(v.primary.algo);
            if ! FAST_SIGNATURE_ALGORITHMS.contains(&algo) {
                continue;
            }
            if ! supported(algo) {
                eprintln!("{} is not supported by the cryptographic \
                           backend, not testing a v4 signature", algo);
                continue;
            }

            let v6 = rfc9980_primary_key(v);
            assert_eq!(v6.version(), 6);
            let v4 = v4_key_with_material_of(&v6)?;
            assert_eq!(v4.mpis(), v6.mpis());

            let ctx = ctx_with_certs(&[&v.cert()]);

            // The v6 signature is good.
            let sig = SignatureBuilder::new(SignatureType::Binary)
                .sign_message(&mut v6.clone().into_keypair()?, MESSAGE)?;
            assert_eq!(sig.version(), 6);
            let sig = openpgp::Packet::from(sig).to_vec()?;
            let outcome = execute(ctx, MESSAGE, Some(&sig), None);
            assert_eq!(outcome.signatures, vec![ok], "{}", v.section);

            // The v4 signature.  Make sure that we test what we mean
            // to test: it is cryptographically valid, and it names
            // the v6 key as its issuer.
            let sig = SignatureBuilder::new(SignatureType::Binary)
                .set_issuer_fingerprint(v6.fingerprint())?
                .sign_message(&mut v4.clone().into_keypair()?, MESSAGE)?;
            assert_eq!(sig.version(), 4);
            assert_eq!(sig.pk_algo(), algo);
            assert_eq!(sig.get_issuers(),
                       vec![openpgp::KeyHandle::from(v6.fingerprint())]);
            sig.clone().verify_message(&v4, MESSAGE)?;
            // Sequoia refuses to verify it using the v6 key.
            assert!(sig.clone().verify_message(&v6, MESSAGE).is_err());

            let sig = openpgp::Packet::from(sig).to_vec()?;
            let outcome = execute(ctx, MESSAGE, Some(&sig), None);
            assert_eq!(outcome.status, ok, "{}", v.section);
            assert_eq!(outcome.signatures, vec![invalid], "{}", v.section);

            let outcome = execute(ctx, MESSAGE, Some(&sig),
                                  Some(RNP_VERIFY_REQUIRE_ALL_SIGS));
            assert_eq!(outcome.status, invalid, "{}", v.section);

            rnp_try!(rnp_ffi_destroy(ctx));
            tested += 1;
        }

        // Make sure that we tested what we mean to test.
        match backend_has_rfc9980() {
            Some(true) => assert_eq!(tested, 3),
            Some(false) => assert_eq!(tested, 0),
            None => assert!(tested == 0 || tested == 3),
        }
        Ok(())
    }

    /// A signature using an algorithm of RFC 9980 next to other
    /// signatures over the same data (RFC 9980, Section 8.2), one of
    /// which uses an algorithm that we do not know.
    ///
    /// The signatures do not affect each other: with a cryptographic
    /// backend that does not support the algorithms of RFC 9980, the
    /// signature using a classic algorithm is still good, and the
    /// signature using an unknown algorithm does no harm.
    #[test]
    fn rfc9980_signatures_next_to_others() -> openpgp::Result<()> {
        use openpgp::packet::signature::SignatureBuilder;
        use openpgp::types::{HashAlgorithm, PublicKeyAlgorithm, SignatureType};
        use crate::testdata::rfc9980::*;
        use crate::testdata::signatures::dummy_signature;

        let ok = RNP_SUCCESS.as_u32();
        let invalid = RNP_ERROR_SIGNATURE_INVALID.as_u32();

        // The v6 certificate with an Ed25519 primary key.
        let classic = &VECTORS[0];
        assert_eq!(classic.primary.algo, 27);
        let classic_key = rfc9980_primary_key(classic);
        let classic_sig = openpgp::Packet::from(
            SignatureBuilder::new(SignatureType::Binary)
                .sign_message(&mut classic_key.clone().into_keypair()?,
                              SIGNED_DATA)?)
            .to_vec()?;

        // Something that looks like a signature made by the same key
        // using ML-DSA-65+ECDSA-NIST-P-256, algorithm ID 37 of
        // draft-ietf-openpgp-nist-bp-comp, which we do not know.
        let unknown = dummy_signature(
            37, HashAlgorithm::SHA512, &classic_key.fingerprint())?;
        assert!(matches!(unknown.pk_algo(), PublicKeyAlgorithm::Unknown(37)));
        let unknown_sig = openpgp::Packet::from(unknown).to_vec()?;

        for s in SIGNATURES {
            let v = s.signer();
            let algo = PublicKeyAlgorithm::from(v.primary.algo);
            let pq = if supported(algo) { ok } else { invalid };
            let pq_sig = openpgp::Packet::from(s.packet()).to_vec()?;

            let ctx = ctx_with_certs(&[&v.cert(), &classic.cert()]);

            let check = |sigs: &[&[u8]], expected: Vec<RnpResult>| {
                let signature = sigs.concat();
                let outcome =
                    execute(ctx, SIGNED_DATA, Some(&signature), None);
                assert_eq!(outcome.status, ok, "{}", s.section);
                assert_eq!(outcome.signatures, expected, "{}", s.section);

                let all = execute(ctx, SIGNED_DATA, Some(&signature),
                                  Some(RNP_VERIFY_REQUIRE_ALL_SIGS));
                assert_eq!(all.status,
                           if expected.iter().all(|&s| s == ok) {
                               ok
                           } else {
                               invalid
                           }, "{}", s.section);
                assert_eq!(all.signatures, expected, "{}", s.section);
            };

            check(&[&pq_sig, &classic_sig], vec![pq, ok]);
            check(&[&classic_sig, &pq_sig], vec![ok, pq]);
            check(&[&unknown_sig], vec![invalid]);
            check(&[&pq_sig, &unknown_sig, &classic_sig],
                  vec![pq, invalid, ok]);
            check(&[&unknown_sig, &classic_sig, &pq_sig],
                  vec![invalid, ok, pq]);

            rnp_try!(rnp_ffi_destroy(ctx));
        }
        Ok(())
    }
}
