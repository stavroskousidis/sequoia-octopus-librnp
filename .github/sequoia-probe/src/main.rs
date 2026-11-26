//! Capability probe (work packages A0 and W1).
//!
//! Shows what sequoia-openpgp does for the RFC 9980 algorithms on the
//! crypto backend it was built with.  It only calls sequoia-openpgp's
//! public API (and `Keygrip::of` from sequoia-ipc, and
//! sequoia-policy-config to read the system crypto policy); it
//! implements no cryptography.  All keys and messages are generated here or come
//! from Appendix A of RFC 9980.
//!
//! Output: one line per cell,
//!
//!     group | operation | status | detail
//!
//! status is one of
//!
//!   ok        the operation worked,
//!   FAIL      the operation did not work (the error text follows),
//!   rejected  a construction that RFC 9980 forbids was refused,
//!   ACCEPTED  a construction that RFC 9980 forbids was not refused
//!             (a finding, not a failure of the probe),
//!   info      a value that is reported, not judged.
//!
//! The exit status is 1 if any line is FAIL, else 0.

use std::io::{self, Write};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use anyhow::{anyhow, Context, Result};

use sequoia_openpgp as openpgp;
use sequoia_policy_config::ConfiguredStandardPolicy;

use openpgp::cert::prelude::*;
use openpgp::crypto::mpi;
use openpgp::crypto::{Password, SessionKey};
use openpgp::packet::key::{Key4, Key6, PrimaryRole, SecretParts, SubordinateRole};
use openpgp::packet::prelude::*;
use openpgp::parse::stream::*;
use openpgp::parse::Parse;
use openpgp::policy::{AsymmetricAlgorithm, HashAlgoSecurity, Policy, StandardPolicy};
use openpgp::serialize::stream::*;
use openpgp::serialize::MarshalInto;
use openpgp::types::*;
use openpgp::{Cert, KeyHandle, Packet, PacketPile, Profile};

const MSG: &[u8] = b"Testing\n";

static FAILS: AtomicUsize = AtomicUsize::new(0);
static ACCEPTED: AtomicUsize = AtomicUsize::new(0);

fn line(group: &str, op: &str, status: &str, detail: &str) {
    // One cell per line; keep the detail on one line.
    let detail = detail.replace('\n', " ");
    println!("{} | {} | {} | {}", group, op, status, detail);
    let _ = io::stdout().flush();
}

fn chain(e: &anyhow::Error) -> String {
    e.chain().map(|c| c.to_string()).collect::<Vec<_>>().join(": ")
}

/// An operation that is expected to work.
fn row(group: &str, op: &str, r: Result<String>) -> bool {
    match r {
        Ok(d) => {
            line(group, op, "ok", &d);
            true
        }
        Err(e) => {
            FAILS.fetch_add(1, Ordering::SeqCst);
            line(group, op, "FAIL", &chain(&e));
            false
        }
    }
}

/// A construction that RFC 9980 forbids: an error is the good outcome.
fn forbidden(group: &str, op: &str, r: Result<String>) {
    match r {
        Ok(d) => {
            ACCEPTED.fetch_add(1, Ordering::SeqCst);
            line(group, op, "ACCEPTED", &d);
        }
        Err(e) => line(group, op, "rejected", &chain(&e)),
    }
}

fn info(group: &str, op: &str, d: String) {
    line(group, op, "info", &d);
}

// ---------------------------------------------------------------------
// Helpers for streaming verification and decryption.

struct Helper<'a> {
    policy: &'a dyn Policy,
    /// Certificates with (unencrypted) secret keys, for decryption.
    secrets: Vec<&'a Cert>,
    /// Certificates for signature verification.
    certs: Vec<&'a Cert>,
    good: Vec<String>,
    bad: Vec<String>,
    session_key: Option<String>,
}

impl<'a> Helper<'a> {
    fn new(policy: &'a dyn Policy, secrets: Vec<&'a Cert>, certs: Vec<&'a Cert>) -> Self {
        Helper { policy, secrets, certs, good: vec![], bad: vec![], session_key: None }
    }

    fn sigs(&self) -> String {
        format!("good signatures: {} [{}]; bad: {} [{}]",
                self.good.len(), self.good.join("; "),
                self.bad.len(), self.bad.join("; "))
    }
}

impl<'a> VerificationHelper for Helper<'a> {
    fn get_certs(&mut self, _ids: &[KeyHandle]) -> openpgp::Result<Vec<Cert>> {
        Ok(self.certs.iter().map(|c| (*c).clone()).collect())
    }

    fn check(&mut self, structure: MessageStructure) -> openpgp::Result<()> {
        // Record every result; the caller judges.
        for layer in structure.into_iter() {
            if let MessageLayer::SignatureGroup { results } = layer {
                for r in results {
                    match r {
                        Ok(GoodChecksum { sig, ka, .. }) => self.good.push(format!(
                            "v{} signature, {}, {}, by v{} key {}",
                            sig.version(), sig.pk_algo(), sig.hash_algo(),
                            ka.key().version(), ka.key().fingerprint())),
                        Err(e) => self.bad.push(e.to_string()),
                    }
                }
            }
        }
        Ok(())
    }
}

impl<'a> DecryptionHelper for Helper<'a> {
    fn decrypt(&mut self, pkesks: &[PKESK], _skesks: &[SKESK],
               sym_algo: Option<SymmetricAlgorithm>,
               decrypt: &mut dyn FnMut(Option<SymmetricAlgorithm>, &SessionKey) -> bool)
               -> openpgp::Result<Option<Cert>>
    {
        let _ = self.policy;
        for pkesk in pkesks {
            for cert in &self.secrets {
                for ka in cert.keys().secret() {
                    let key = ka.key().clone();
                    if key.pk_algo() != pkesk.pk_algo() {
                        continue;
                    }
                    let mut pair = match key.into_keypair() {
                        Ok(p) => p,
                        Err(_) => continue,
                    };
                    if let Some((algo, sk)) = pkesk.decrypt(&mut pair, sym_algo) {
                        if decrypt(algo, &sk) {
                            self.session_key = Some(format!(
                                "PKESK v{} for {} opened with v{} key {}",
                                pkesk.version(), pkesk.pk_algo(),
                                ka.key().version(), ka.key().fingerprint()));
                            return Ok(None);
                        }
                    }
                }
            }
        }
        Err(anyhow!("no PKESK could be decrypted with the given secret keys"))
    }
}

fn primary_signer(cert: &Cert) -> Result<openpgp::crypto::KeyPair> {
    cert.primary_key().key().clone().parts_into_secret()
        .context("primary key has no secret")?
        .into_keypair()
}

fn sign_inline(cert: &Cert, hash: Option<HashAlgorithm>) -> Result<Vec<u8>> {
    let mut sink = vec![];
    {
        let message = Message::new(&mut sink);
        let mut signer = Signer::new(message, primary_signer(cert)?)?;
        if let Some(h) = hash {
            signer = signer.hash_algo(h)?;
        }
        let message = signer.build()?;
        let mut w = LiteralWriter::new(message).build()?;
        w.write_all(MSG)?;
        w.finalize()?;
    }
    Ok(sink)
}

fn sign_detached(cert: &Cert, hash: Option<HashAlgorithm>) -> Result<Vec<u8>> {
    let mut sink = vec![];
    {
        let message = Message::new(&mut sink);
        let mut signer = Signer::new(message, primary_signer(cert)?)?.detached();
        if let Some(h) = hash {
            signer = signer.hash_algo(h)?;
        }
        let mut w = signer.build()?;
        w.write_all(MSG)?;
        w.finalize()?;
    }
    Ok(sink)
}

/// Verifies an inline-signed message.  Ok only if the content matches
/// and there is at least one good and no bad signature.
fn verify_inline(p: &dyn Policy, msg: &[u8], cert: &Cert) -> Result<String> {
    let h = Helper::new(p, vec![], vec![cert]);
    let mut v = VerifierBuilder::from_bytes(msg)?.with_policy(p, None, h)?;
    let mut content = vec![];
    io::copy(&mut v, &mut content)?;
    let h = v.into_helper();
    if content != MSG {
        return Err(anyhow!("content differs"));
    }
    if h.good.is_empty() || !h.bad.is_empty() {
        return Err(anyhow!("{}", h.sigs()));
    }
    Ok(h.sigs())
}

fn verify_detached(p: &dyn Policy, sig: &[u8], data: &[u8], cert: &Cert) -> Result<String> {
    let h = Helper::new(p, vec![], vec![cert]);
    let mut v = DetachedVerifierBuilder::from_bytes(sig)?.with_policy(p, None, h)?;
    v.verify_bytes(data)?;
    let h = v.into_helper();
    if h.good.is_empty() || !h.bad.is_empty() {
        return Err(anyhow!("{}", h.sigs()));
    }
    Ok(h.sigs())
}

/// Encrypts MSG to all transport-encryption keys of `recipients`,
/// optionally signed by `signer`.  With `seipdv1`, the recipients are
/// treated as if they advertised only SEIPDv1.
fn encrypt(p: &dyn Policy, recipients: &[&Cert], signer: Option<&Cert>, seipdv1: bool)
           -> Result<Vec<u8>>
{
    encrypt_with(p, recipients, signer, seipdv1, None)
}

fn encrypt_with(p: &dyn Policy, recipients: &[&Cert], signer: Option<&Cert>, seipdv1: bool,
                sym: Option<SymmetricAlgorithm>)
                -> Result<Vec<u8>>
{
    let mut rs: Vec<Recipient> = vec![];
    for cert in recipients {
        let mut n = 0;
        for ka in cert.keys().with_policy(p, None).supported().alive().revoked(false)
            .for_transport_encryption()
        {
            n += 1;
            if seipdv1 {
                rs.push(Recipient::new(Features::empty().set_seipdv1(),
                                       KeyHandle::from(ka.key().keyid()),
                                       ka.key()));
            } else {
                rs.push(ka.into());
            }
        }
        if n == 0 {
            return Err(anyhow!("no usable encryption key in {}", cert.fingerprint()));
        }
    }
    let mut sink = vec![];
    {
        let message = Message::new(&mut sink);
        let mut enc = Encryptor::for_recipients(message, rs);
        if let Some(sym) = sym {
            enc = enc.symmetric_algo(sym);
        }
        let mut message = enc.build()?;
        if let Some(s) = signer {
            message = Signer::new(message, primary_signer(s)?)?.build()?;
        }
        let mut w = LiteralWriter::new(message).build()?;
        w.write_all(MSG)?;
        w.finalize()?;
    }
    Ok(sink)
}

/// Describes the outer packets of an encrypted message.
fn describe(msg: &[u8]) -> String {
    match PacketPile::from_bytes(msg) {
        Err(e) => format!("unparsable: {}", e),
        Ok(pile) => pile.children().map(|p| match p {
            Packet::PKESK(k) => format!("PKESK v{} {}", k.version(), k.pk_algo()),
            Packet::SKESK(k) => format!("SKESK v{}", k.version()),
            Packet::SEIP(SEIP::V1(_)) => "SEIPD v1".to_string(),
            Packet::SEIP(SEIP::V2(s)) =>
                format!("SEIPD v2 {}/{}", s.symmetric_algo(), s.aead()),
            Packet::SEIP(_) => "SEIPD other".to_string(),
            other => format!("{}", other.tag()),
        }).collect::<Vec<_>>().join(", "),
    }
}

/// Decrypts.  Ok only if the plaintext matches; if `sender` is given,
/// also requires one good and no bad signature.
fn decrypt(p: &dyn Policy, msg: &[u8], secret: &Cert, sender: Option<&Cert>) -> Result<String> {
    let h = Helper::new(p, vec![secret], sender.into_iter().collect());
    let mut d = DecryptorBuilder::from_bytes(msg)?.with_policy(p, None, h)?;
    let mut content = vec![];
    io::copy(&mut d, &mut content)?;
    let h = d.into_helper();
    if content != MSG {
        return Err(anyhow!("plaintext differs"));
    }
    let mut out = h.session_key.clone().unwrap_or_default();
    if sender.is_some() {
        if h.good.is_empty() || !h.bad.is_empty() {
            return Err(anyhow!("decrypted, but {}", h.sigs()));
        }
        out = format!("{}; {}", out, h.sigs());
    }
    Ok(out)
}

fn key_line<P: openpgp::packet::key::KeyParts, R: openpgp::packet::key::KeyRole>(
    k: &Key<P, R>) -> String
{
    let fp = k.fingerprint();
    format!("v{} {} (ID {}), fingerprint {} octets, key ID {}, public key material {} octets, \
             mpis().bits() = {:?}",
            k.version(), k.pk_algo(), u8::from(k.pk_algo()),
            fp.as_bytes().len(), k.keyid(),
            k.mpis().serialized_len(), k.mpis().bits())
}

fn keygrip<P: openpgp::packet::key::KeyParts, R: openpgp::packet::key::KeyRole>(
    k: &Key<P, R>) -> Result<String>
{
    Ok(sequoia_ipc::Keygrip::of(k.mpis())?.to_string())
}

fn gen_v6(sig: PublicKeyAlgorithmSpecification, kem: PublicKeyAlgorithmSpecification,
          uid: &str) -> Result<Cert>
{
    let (cert, _rev) = CertBuilder::new()
        .set_profile(Profile::RFC9580)?
        .add_userid(uid)
        .set_signing_algorithm(sig)
        .set_encryption_algorithm(kem)
        .set_primary_key_flags(KeyFlags::empty().set_certification().set_signing())
        .add_subkey(KeyFlags::empty().set_transport_encryption().set_storage_encryption(),
                    None, None)
        .generate()?;
    Ok(cert)
}

/// Password-protects all secret keys, serialises, re-parses, reports
/// the protection parameters, and unlocks again.
fn protect_roundtrip(cert: &Cert) -> Result<String> {
    let pw: Password = "probe passphrase".into();
    let mut packets: Vec<Packet> = vec![];
    for ka in cert.keys().secret() {
        let key = ka.key().clone().encrypt_secret(&pw)?;
        if ka.primary() {
            packets.push(Packet::SecretKey(key.role_into_primary()));
        } else {
            packets.push(Packet::SecretSubkey(key.role_into_subordinate()));
        }
    }
    let (locked, _) = cert.clone().insert_packets(packets)?;
    let armored = locked.as_tsk().armored().to_vec()?;
    let parsed = Cert::from_bytes(&armored)?;
    let mut out = vec![];
    for ka in parsed.keys().secret() {
        match ka.key().secret() {
            SecretKeyMaterial::Encrypted(e) => out.push(format!(
                "{}: {}, {}, AEAD {}",
                ka.key().pk_algo(),
                match e.s2k() {
                    openpgp::crypto::S2K::Iterated { hash, hash_bytes, .. } =>
                        format!("iterated and salted S2K ({}, {} octets hashed)",
                                hash, hash_bytes),
                    openpgp::crypto::S2K::Argon2 { .. } => "Argon2 S2K".to_string(),
                    other => format!("{:?}", other),
                },
                e.algo(),
                e.aead_algo().map(|a| a.to_string()).unwrap_or_else(|| "none".into()))),
            SecretKeyMaterial::Unencrypted(_) =>
                return Err(anyhow!("{} is not encrypted after the round trip",
                                   ka.key().pk_algo())),
        }
        if ka.key().clone().decrypt_secret(&"wrong".into()).is_ok() {
            return Err(anyhow!("a wrong password unlocked the key"));
        }
        let unlocked = ka.key().clone().decrypt_secret(&pw)?;
        let orig = cert.keys().secret()
            .find(|o| o.key().fingerprint() == ka.key().fingerprint())
            .ok_or_else(|| anyhow!("key lost"))?;
        if unlocked.secret() != orig.key().secret() {
            return Err(anyhow!("unlocked secret differs from the original"));
        }
    }
    Ok(format!("{} octets armored; {}", armored.len(), out.join("; ")))
}

fn prefs(p: &dyn Policy, cert: &Cert) -> Result<String> {
    let vc = cert.with_policy(p, None)?;
    Ok(format!(
        "features: {:?}; preferred symmetric: {:?}; preferred AEAD ciphersuites: {:?}; \
         preferred hashes: {:?}",
        vc.features(), vc.preferred_symmetric_algorithms(),
        vc.preferred_aead_ciphersuites(), vc.preferred_hash_algorithms()))
}

// ---------------------------------------------------------------------
// The v6 matrix.

struct Suite {
    name: &'static str,
    sig: fn() -> PublicKeyAlgorithmSpecification,
    kem: fn() -> PublicKeyAlgorithmSpecification,
    /// Whether the signature has two components (EdDSA and ML-DSA).
    composite: bool,
}

fn tamper(p: &dyn Policy, group: &str, cert: &Cert, s: &Suite) {
    let sig = match sign_detached(cert, None) {
        Ok(s) => s,
        Err(e) => {
            row(group, "tampered signature", Err(e));
            return;
        }
    };
    // The detached signature is one signature packet; its
    // algorithm-specific part is the tail of the packet.
    let (first_len, second_len) = match PacketPile::from_bytes(&sig).ok()
        .and_then(|pile| pile.children().next().cloned())
    {
        Some(Packet::Signature(sg)) => match sg.mpis() {
            mpi::Signature::MLDSA65_Ed25519 { eddsa, mldsa } => (eddsa.len(), mldsa.len()),
            mpi::Signature::MLDSA87_Ed448 { eddsa, mldsa } => (eddsa.len(), mldsa.len()),
            other => (0, other.serialized_len()),
        },
        _ => {
            row(group, "tampered signature", Err(anyhow!("no signature packet")));
            return;
        }
    };
    let n = sig.len();
    // Flip one bit in the last component.
    let mut t = sig.clone();
    t[n - second_len / 2] ^= 1;
    let what = if s.composite { "ML-DSA part" } else { "signature" };
    forbidden(group, &format!("verify with one bit flipped in the {}", what),
              verify_detached(p, &t, MSG, cert));
    if s.composite {
        // Flip one bit in the EdDSA component only (RFC 9980,
        // Section 3.2: both must validate).
        let mut t = sig.clone();
        t[n - second_len - first_len / 2] ^= 1;
        forbidden(group, "verify with one bit flipped in the EdDSA part",
                  verify_detached(p, &t, MSG, cert));
    }
}

fn v6_suite(p: &dyn Policy, s: &Suite) -> Option<Cert> {
    let g = s.name;
    let t0 = Instant::now();
    let cert = match gen_v6((s.sig)(), (s.kem)(), &format!("{} <probe@example.org>", g)) {
        Ok(c) => c,
        Err(e) => {
            row(g, "generate v6 certificate", Err(e));
            return None;
        }
    };
    row(g, "generate v6 certificate", Ok(format!(
        "{:.1} s; primary: {}; subkey: {}",
        t0.elapsed().as_secs_f32(),
        key_line(cert.primary_key().key()),
        cert.keys().subkeys().next().map(|k| key_line(k.key())).unwrap_or_default())));

    row(g, "valid under StandardPolicy", cert.with_policy(p, None)
        .map(|vc| format!("primary key flags {:?}", vc.primary_key().key_flags())));
    match prefs(p, &cert) {
        Ok(d) => info(g, "preferences set by CertBuilder", d),
        Err(e) => { row(g, "preferences set by CertBuilder", Err(e)); }
    }

    row(g, "serialise and re-parse certificate", (|| {
        let bytes = cert.armored().to_vec()?;
        let c = Cert::from_bytes(&bytes)?;
        if c != cert.clone().strip_secret_key_material() {
            return Err(anyhow!("re-parsed certificate differs"));
        }
        Ok(format!("{} octets armored", bytes.len()))
    })());
    row(g, "serialise and re-parse secret key (unprotected)", (|| {
        let bytes = cert.as_tsk().armored().to_vec()?;
        let c = Cert::from_bytes(&bytes)?;
        if c != cert || !c.is_tsk() {
            return Err(anyhow!("re-parsed secret key differs"));
        }
        Ok(format!("{} octets armored", bytes.len()))
    })());
    row(g, "protect, serialise, re-parse, unlock secret key", protect_roundtrip(&cert));

    let t0 = Instant::now();
    let signed = sign_inline(&cert, None);
    row(g, "sign (inline)", signed.as_ref().map(|s| format!(
        "{:.1} s; {} octets", t0.elapsed().as_secs_f32(), s.len()))
        .map_err(|e| anyhow!("{}", chain(e))));
    if let Ok(s) = &signed {
        row(g, "verify (inline)", verify_inline(p, s, &cert));
    }
    let detached = sign_detached(&cert, None);
    row(g, "sign (detached)", detached.as_ref().map(|s| format!("{} octets", s.len()))
        .map_err(|e| anyhow!("{}", chain(e))));
    if let Ok(s) = &detached {
        row(g, "verify (detached)", verify_detached(p, s, MSG, &cert));
        forbidden(g, "verify (detached) over different data",
                  verify_detached(p, s, b"Something else\n", &cert));
    }
    tamper(p, g, &cert, s);

    // Thunderbird 161.0 always asks for SHA-256 when it signs
    // (rnp_op_sign_set_hash and rnp_op_encrypt_set_hash with "SHA256").
    let sha256 = sign_detached(&cert, Some(HashAlgorithm::SHA256));
    row(g, "sign (detached) with SHA256, the hash Thunderbird sets",
        sha256.as_ref().map(|s| format!("{} octets", s.len()))
        .map_err(|e| anyhow!("{}", chain(e))));
    if let Ok(s) = &sha256 {
        row(g, "verify (detached) SHA256 signature", verify_detached(p, s, MSG, &cert));
    }

    let enc = encrypt(p, &[&cert], None, false);
    row(g, "encrypt", enc.as_ref().map(|c| describe(c)).map_err(|e| anyhow!("{}", chain(e))));
    if let Ok(c) = &enc {
        row(g, "decrypt", decrypt(p, c, &cert, None));
    }
    let enc = encrypt(p, &[&cert], Some(&cert), false);
    row(g, "sign and encrypt", enc.as_ref().map(|c| describe(c))
        .map_err(|e| anyhow!("{}", chain(e))));
    if let Ok(c) = &enc {
        row(g, "decrypt and verify", decrypt(p, c, &cert, Some(&cert)));
    }

    row(g, "Keygrip::of(primary key)", keygrip(cert.primary_key().key()));
    if let Some(k) = cert.keys().subkeys().next() {
        row(g, "Keygrip::of(encryption subkey)", keygrip(k.key()));
    }
    Some(cert)
}

// ---------------------------------------------------------------------
// The v4 case (RFC 9980, Sections 3.5 and 4.3.2).

fn v4_case(p: &dyn Policy) -> Option<Cert> {
    let g = "v4 + ML-KEM-768+X25519";
    let cert = (|| -> Result<Cert> {
        let (cert, _) = CertBuilder::new()
            .set_profile(Profile::RFC4880)?
            .add_userid("v4 <probe@example.org>")
            .set_encryption_algorithm(PublicKeyAlgorithmSpecification::mlkem768_x25519())
            .set_primary_key_flags(KeyFlags::empty().set_certification().set_signing())
            .add_subkey(KeyFlags::empty().set_transport_encryption().set_storage_encryption(),
                        None, None)
            .generate()?;
        Ok(cert)
    })();
    let cert = match cert {
        Ok(c) => c,
        Err(e) => {
            row(g, "generate v4 certificate with ML-KEM subkey (CertBuilder)", Err(e));
            return None;
        }
    };
    row(g, "generate v4 certificate with ML-KEM subkey (CertBuilder)", Ok(format!(
        "primary: {}; subkey: {}", key_line(cert.primary_key().key()),
        cert.keys().subkeys().next().map(|k| key_line(k.key())).unwrap_or_default())));
    row(g, "valid under StandardPolicy", cert.with_policy(p, None).map(|_| String::new()));
    match prefs(p, &cert) {
        Ok(d) => info(g, "preferences set by CertBuilder", d),
        Err(e) => { row(g, "preferences set by CertBuilder", Err(e)); }
    }
    row(g, "serialise and re-parse secret key (unprotected)", (|| {
        let bytes = cert.as_tsk().armored().to_vec()?;
        let c = Cert::from_bytes(&bytes)?;
        if c != cert || !c.is_tsk() {
            return Err(anyhow!("re-parsed secret key differs"));
        }
        Ok(format!("{} octets armored", bytes.len()))
    })());
    row(g, "protect, serialise, re-parse, unlock secret key", protect_roundtrip(&cert));

    let enc = encrypt(p, &[&cert], Some(&cert), false);
    row(g, "sign and encrypt (features as advertised)", enc.as_ref().map(|c| describe(c))
        .map_err(|e| anyhow!("{}", chain(e))));
    if let Ok(c) = &enc {
        row(g, "decrypt and verify", decrypt(p, c, &cert, Some(&cert)));
    }
    let enc = encrypt(p, &[&cert], Some(&cert), true);
    row(g, "sign and encrypt (recipient treated as SEIPDv1 only)",
        enc.as_ref().map(|c| describe(c)).map_err(|e| anyhow!("{}", chain(e))));
    if let Ok(c) = &enc {
        row(g, "decrypt and verify (PKESK v3, SEIPD v1)", decrypt(p, c, &cert, Some(&cert)));
    }
    row(g, "Keygrip::of(legacy EdDSA primary key)", keygrip(cert.primary_key().key()));
    if let Some(k) = cert.keys().subkeys().next() {
        row(g, "Keygrip::of(ML-KEM subkey)", keygrip(k.key()));
    }

    // Thunderbird's experimental path adds such a subkey to an
    // existing v4 certificate.
    row(g, "add ML-KEM subkey to an existing classic v4 certificate", (|| {
        let (classic, _) = CertBuilder::general_purpose(Some("classic <probe@example.org>"))
            .set_profile(Profile::RFC4880)?
            .generate()?;
        let before = classic.keys().count();
        let sub: Key<SecretParts, SubordinateRole> =
            Key::V4(Key4::generate_mlkem768_x25519()?);
        let vc = classic.with_policy(p, None)?;
        let new = SubkeyBuilder::new(
            vc, sub.parts_into_unspecified(),
            KeyFlags::empty().set_transport_encryption().set_storage_encryption())?
            .set_primary_key_signer(primary_signer(&classic)?)
            .attach_cert()?;
        let vc = new.with_policy(p, None)?;
        let pq = vc.keys().for_transport_encryption()
            .filter(|k| k.key().pk_algo() == PublicKeyAlgorithm::MLKEM768_X25519).count();
        if pq != 1 {
            return Err(anyhow!("{} valid ML-KEM subkeys after attaching", pq));
        }
        let c = encrypt(p, &[&new], None, false)?;
        let d = describe(&c);
        decrypt(p, &c, &new, None)?;
        Ok(format!("{} keys before, {} after; encrypting to all encryption subkeys gives: {}",
                   before, new.keys().count(), d))
    })());

    // What RFC 9980 forbids for v4 keys must not be generated.
    forbidden(g, "generate v4 ML-KEM-1024+X448 key (RFC 9980, 4.3.2)",
              PublicKeyAlgorithmSpecification::mlkem1024_x448()
              .generate_key(Profile::RFC4880).map(|k| key_line(&k)));
    forbidden(g, "generate v4 ML-DSA-65+Ed25519 key (RFC 9980, 5.3.2)",
              PublicKeyAlgorithmSpecification::mldsa65_ed25519()
              .generate_key(Profile::RFC4880).map(|k| key_line(&k)));
    forbidden(g, "generate v4 ML-DSA-87+Ed448 key (RFC 9980, 5.3.2)",
              PublicKeyAlgorithmSpecification::mldsa87_ed448()
              .generate_key(Profile::RFC4880).map(|k| key_line(&k)));
    forbidden(g, "generate v4 SLH-DSA-SHAKE-128s key (RFC 9980, 6.2.2)",
              PublicKeyAlgorithmSpecification::slhdsa128s()
              .generate_key(Profile::RFC4880).map(|k| key_line(&k)));
    forbidden(g, "generate v4 SLH-DSA-SHAKE-128f key (RFC 9980, 6.2.2)",
              PublicKeyAlgorithmSpecification::slhdsa128f()
              .generate_key(Profile::RFC4880).map(|k| key_line(&k)));
    forbidden(g, "generate v4 SLH-DSA-SHAKE-256s key (RFC 9980, 6.2.2)",
              PublicKeyAlgorithmSpecification::slhdsa256s()
              .generate_key(Profile::RFC4880).map(|k| key_line(&k)));
    Some(cert)
}

// ---------------------------------------------------------------------
// The system crypto policy.

/// Builds the policy the way `rnp_ffi_create` of the Octopus does
/// (src/lib.rs): the system crypto policy, read by
/// sequoia-policy-config from the file named in SEQUOIA_CRYPTO_POLICY
/// or from /etc/crypto-policies/back-ends/sequoia.config, on top of
/// StandardPolicy; then MD5 and SHA-1 are rejected where Thunderbird
/// expects it.  A file that cannot be parsed is reported as FAIL here;
/// the Octopus only warns and goes on with what was parsed.
fn octopus_policy(g: &str) -> StandardPolicy<'static> {
    info(g, &format!("environment variable {}", ConfiguredStandardPolicy::ENV_VAR),
         match std::env::var(ConfiguredStandardPolicy::ENV_VAR) {
             Ok(v) => format!("set to {:?}", v),
             Err(_) => "not set".to_string(),
         });
    info(g, &format!("file {}", ConfiguredStandardPolicy::CONFIG_FILE),
         match std::fs::metadata(ConfiguredStandardPolicy::CONFIG_FILE) {
             Ok(m) => format!("exists, {} octets", m.len()),
             Err(e) => format!("not readable: {}", e),
         });

    let mut policy = ConfiguredStandardPolicy::new();
    row(g, "parse_default_config", policy.parse_default_config()
        .map(|read| if read {
            "a configuration was read".to_string()
        } else {
            "no configuration found: this is StandardPolicy unchanged".to_string()
        }));
    let mut policy = policy.build();

    let now = std::time::SystemTime::now();
    for (algo, prop) in [
        (HashAlgorithm::MD5, HashAlgoSecurity::CollisionResistance),
        (HashAlgorithm::MD5, HashAlgoSecurity::SecondPreImageResistance),
        (HashAlgorithm::SHA1, HashAlgoSecurity::CollisionResistance),
    ] {
        if policy.hash_cutoff(algo, prop).unwrap_or(now) >= now {
            policy.reject_hash_property_at(algo, prop, std::time::UNIX_EPOCH);
        }
    }
    policy
}

/// What the Octopus's policy says about the RFC 9980 algorithms, and
/// whether the generated certificates can be used under it.
fn system_policy(certs: &[(&str, Option<&Cert>)]) {
    let g = "system policy";
    let policy = octopus_policy(g);
    let p: &dyn Policy = &policy;

    let now = std::time::SystemTime::now();
    for (name, a) in [
        ("ML-DSA-65+Ed25519", AsymmetricAlgorithm::MLDSA65_Ed25519),
        ("ML-DSA-87+Ed448", AsymmetricAlgorithm::MLDSA87_Ed448),
        ("SLH-DSA-SHAKE-128s", AsymmetricAlgorithm::SLHDSA128s),
        ("SLH-DSA-SHAKE-128f", AsymmetricAlgorithm::SLHDSA128f),
        ("SLH-DSA-SHAKE-256s", AsymmetricAlgorithm::SLHDSA256s),
        ("ML-KEM-768+X25519", AsymmetricAlgorithm::MLKEM768_X25519),
        ("ML-KEM-1024+X448", AsymmetricAlgorithm::MLKEM1024_X448),
    ] {
        row(g, &format!("asymmetric algorithm {} accepted", name),
            match policy.asymmetric_algo_cutoff(a) {
                None => Ok("no cutoff".to_string()),
                Some(t) if t > now => Ok(format!("cutoff in the future: {:?}", t)),
                Some(t) => Err(anyhow!("rejected, cutoff {:?}", t)),
            });
    }

    for (name, cert) in certs {
        let g = format!("system policy: {}", name);
        let cert = match cert {
            Some(c) => *c,
            None => {
                row(&g, "certificate", Err(anyhow!("was not generated")));
                continue;
            }
        };
        row(&g, "certificate valid", cert.with_policy(p, None)
            .map(|vc| format!("primary key flags {:?}", vc.primary_key().key_flags())));
        row(&g, "signing-capable key usable", (|| {
            let n = cert.keys().with_policy(p, None).supported().alive().revoked(false)
                .for_signing().count();
            if n == 0 {
                return Err(anyhow!("no signing-capable key is valid"));
            }
            Ok(format!("{} key(s)", n))
        })());
        row(&g, "encryption-capable key usable", (|| {
            let n = cert.keys().with_policy(p, None).supported().alive().revoked(false)
                .for_transport_encryption().count();
            if n == 0 {
                return Err(anyhow!("no encryption-capable key is valid"));
            }
            Ok(format!("{} key(s)", n))
        })());
        row(&g, "sign and verify", sign_inline(cert, None)
            .and_then(|m| verify_inline(p, &m, cert)));
        row(&g, "sign, encrypt, decrypt and verify", encrypt(p, &[cert], Some(cert), false)
            .and_then(|m| decrypt(p, &m, cert, Some(cert))));
    }
}

// ---------------------------------------------------------------------
// Constructions RFC 9980 forbids, built with the public API.

fn negative(p: &dyn Policy, mldsa: Option<&Cert>, slh: Option<&Cert>,
            kem1024: Option<&Cert>, v4: Option<&Cert>)
{
    let g = "negative";

    // RFC 9980, 5.3.1 and 6.2.1: a hash with a digest of less than
    // 256 bits MUST be rejected by the verifier.
    for (name, cert, section) in [("ML-DSA-65+Ed25519", mldsa, "5.3.1"),
                                  ("SLH-DSA-SHAKE-128f", slh, "6.2.1")] {
        let Some(cert) = cert else { continue };
        for h in [HashAlgorithm::SHA224, HashAlgorithm::SHA1] {
            let op = format!("{} signature over {} (RFC 9980, {})", name, h, section);
            match sign_detached(cert, Some(h)) {
                Err(e) => line(g, &format!("create {}", op), "rejected", &chain(&e)),
                Ok(sig) => {
                    ACCEPTED.fetch_add(1, Ordering::SeqCst);
                    line(g, &format!("create {}", op), "ACCEPTED",
                         &format!("{} octets", sig.len()));
                    forbidden(g, &format!("verify {} under StandardPolicy", op),
                              verify_detached(p, &sig, MSG, cert));
                }
            }
        }
    }

    // RFC 9980, 5.3.2: ML-DSA composites only in v6 keys; 5.3.1: only
    // v6 signatures.  Put v6 ML-DSA key material into a v4 key packet.
    let r = (|| -> Result<(Cert, String)> {
        let k6 = Key6::<SecretParts, PrimaryRole>::generate_mldsa65_ed25519()?;
        let secret = match k6.secret() {
            SecretKeyMaterial::Unencrypted(u) => u.map(|m| m.clone()),
            _ => return Err(anyhow!("unexpected")),
        };
        let k4: Key4<SecretParts, PrimaryRole> = Key4::with_secret(
            std::time::SystemTime::now() - std::time::Duration::new(60, 0),
            PublicKeyAlgorithm::MLDSA65_Ed25519, k6.mpis().clone(), secret.into())?;
        let key: Key<SecretParts, PrimaryRole> = Key::V4(k4);
        let mut signer = key.clone().into_keypair()?;
        let uid = UserID::from("v4 ML-DSA <probe@example.org>");
        let cert = Cert::try_from(vec![Packet::SecretKey(key.clone())])?;
        let sig = uid.bind(
            &mut signer, &cert,
            SignatureBuilder::new(SignatureType::PositiveCertification)
                .set_key_flags(KeyFlags::empty().set_certification().set_signing())?)?;
        let d = format!("self-signature made: v{} {} {}", sig.version(), sig.pk_algo(),
                        sig.hash_algo());
        let (cert, _) = cert.insert_packets(vec![Packet::from(uid), sig.into()])?;
        Ok((cert, d))
    })();
    match r {
        Err(e) => line(g, "build v4 certificate with ML-DSA-65+Ed25519 primary key (RFC 9980, 5.3.2)",
                       "rejected", &chain(&e)),
        Ok((cert, d)) => {
            ACCEPTED.fetch_add(1, Ordering::SeqCst);
            line(g, "build v4 certificate with ML-DSA-65+Ed25519 primary key (RFC 9980, 5.3.2)",
                 "ACCEPTED", &format!("{}; {}", key_line(cert.primary_key().key()), d));
            forbidden(g, "re-parse that v4 ML-DSA certificate",
                      cert.to_vec().map_err(Into::into)
                      .and_then(|b| Cert::from_bytes(&b))
                      .map(|c| format!("{} user IDs with valid self-signature",
                                       c.userids().filter(|u| u.self_signatures().count() > 0)
                                       .count())));
            forbidden(g, "v4 ML-DSA certificate valid under StandardPolicy",
                      cert.with_policy(p, None)
                      .map(|vc| format!("valid; primary user ID {:?}",
                                        vc.primary_userid().map(|u| u.userid().to_string())
                                        .unwrap_or_default())));
            match sign_detached(&cert, None) {
                Err(e) => line(g, "sign with the v4 ML-DSA key (RFC 9980, 5.3.1)", "rejected",
                               &chain(&e)),
                Ok(sig) => {
                    ACCEPTED.fetch_add(1, Ordering::SeqCst);
                    line(g, "sign with the v4 ML-DSA key (RFC 9980, 5.3.1)", "ACCEPTED",
                         &format!("{} octets", sig.len()));
                    forbidden(g, "verify the v4 ML-DSA signature under StandardPolicy",
                              verify_detached(p, &sig, MSG, &cert));
                }
            }
        }
    }

    // RFC 9980, 4.3.1: with a v3 PKESK for an ML-KEM composite, the
    // symmetric algorithm MUST be AES-128, AES-192 or AES-256.
    if let Some(v4) = v4 {
        for sym in [SymmetricAlgorithm::Camellia256, SymmetricAlgorithm::Twofish] {
            let op = format!("v3 PKESK for ML-KEM-768+X25519 with {} (RFC 9980, 4.3.1)", sym);
            if !sym.is_supported() {
                info(g, &format!("create {}", op), "symmetric algorithm not supported \
                                                     by this backend".into());
                continue;
            }
            match encrypt_with(p, &[v4], None, true, Some(sym)) {
                Err(e) => line(g, &format!("create {}", op), "rejected", &chain(&e)),
                Ok(c) => {
                    ACCEPTED.fetch_add(1, Ordering::SeqCst);
                    line(g, &format!("create {}", op), "ACCEPTED", &describe(&c));
                    forbidden(g, &format!("decrypt {}", op), decrypt(p, &c, v4, None));
                }
            }
        }
    }

    // RFC 9980, 7.2: a subkey binding signature over one of these
    // algorithms MUST NOT be made with MD5, SHA-1 or RIPEMD-160, and
    // a receiver MUST treat such a signature as invalid.
    for h in [HashAlgorithm::SHA1, HashAlgorithm::RipeMD, HashAlgorithm::MD5] {
        let op = format!("v4 ML-KEM-768+X25519 subkey bound with {} (RFC 9980, 7.2)", h);
        if !h.is_supported() {
            info(g, &format!("create {}", op), "hash algorithm not supported by this backend".into());
            continue;
        }
        let r = (|| -> Result<Cert> {
            let (classic, _) = CertBuilder::general_purpose(Some("classic <probe@example.org>"))
                .set_profile(Profile::RFC4880)?
                .generate()?;
            let sub: Key<SecretParts, SubordinateRole> =
                Key::V4(Key4::generate_mlkem768_x25519()?);
            let mut signer = primary_signer(&classic)?;
            // Bind by hand: SubkeyBuilder would choose the hash itself.
            let sig = sub.bind(
                &mut signer, &classic,
                SignatureBuilder::new(SignatureType::SubkeyBinding)
                    .set_hash_algo(h)
                    .set_key_flags(KeyFlags::empty().set_transport_encryption()
                                   .set_storage_encryption())?)?;
            if sig.hash_algo() != h {
                return Err(anyhow!("the library made the binding signature with {} instead",
                                   sig.hash_algo()));
            }
            let (new, _) = classic.insert_packets(
                vec![Packet::SecretSubkey(sub), sig.into()])?;
            Ok(new)
        })();
        match r {
            Err(e) => line(g, &format!("create {}", op), "rejected", &chain(&e)),
            Ok(cert) => {
                let hashes: Vec<String> = cert.keys().subkeys()
                    .filter(|k| k.key().pk_algo() == PublicKeyAlgorithm::MLKEM768_X25519)
                    .flat_map(|k| k.self_signatures().map(|s| s.hash_algo().to_string())
                              .collect::<Vec<_>>())
                    .collect();
                ACCEPTED.fetch_add(1, Ordering::SeqCst);
                line(g, &format!("create {}", op), "ACCEPTED",
                     &format!("binding signature hash after insertion: [{}]",
                              hashes.join(", ")));
                forbidden(g, &format!("use {} under StandardPolicy", op), (|| {
                    let vc = cert.with_policy(p, None)?;
                    let n = vc.keys()
                        .filter(|k| k.key().pk_algo() == PublicKeyAlgorithm::MLKEM768_X25519)
                        .count();
                    if n == 0 {
                        Err(anyhow!("the ML-KEM subkey is not valid under the policy"))
                    } else {
                        Ok(format!("{} valid ML-KEM subkey", n))
                    }
                })());
            }
        }
    }

    // Mixed recipients (RFC 9980, Section 8.1 allows them).
    if let (Some(pq), Some(v4)) = (mldsa, v4) {
        let r = (|| -> Result<String> {
            let (classic, _) = CertBuilder::general_purpose(Some("classic <probe@example.org>"))
                .set_profile(Profile::RFC4880)?
                .generate()?;
            let c = encrypt(p, &[pq, v4, &classic], Some(pq), false)?;
            let d = describe(&c);
            decrypt(p, &c, pq, Some(pq))?;
            decrypt(p, &c, v4, Some(pq))?;
            decrypt(p, &c, &classic, Some(pq))?;
            Ok(format!("{}; all three recipients decrypt and verify", d))
        })();
        row("mixed recipients", "v6 PQ + v4 with ML-KEM subkey + classic v4", r);
    }
    // A classic recipient whose certificate advertises only SEIPDv1
    // (as certificates made by other implementations may) together
    // with a v6 post-quantum recipient.
    for (name, pq) in [("ML-KEM-768+X25519", mldsa), ("ML-KEM-1024+X448", kem1024)] {
        let Some(pq) = pq else { continue };
        let r = (|| -> Result<String> {
            let (classic, _) = CertBuilder::general_purpose(Some("seipdv1 <probe@example.org>"))
                .set_profile(Profile::RFC4880)?
                .set_features(Features::empty().set_seipdv1())?
                .generate()?;
            let c = encrypt(p, &[pq, &classic], None, false)?;
            let d = describe(&c);
            decrypt(p, &c, pq, None)?;
            decrypt(p, &c, &classic, None)?;
            Ok(format!("{}; both recipients decrypt", d))
        })();
        row("mixed recipients",
            &format!("v6 certificate with {} subkey + classic v4 certificate that advertises \
                      only SEIPDv1", name), r);
    }
    if let Some(k) = kem1024 {
        let r = encrypt(p, &[k], None, true).map(|c| describe(&c));
        match r {
            Ok(d) => info("mixed recipients",
                          "ML-KEM-1024+X448 recipient treated as SEIPDv1 only", d),
            Err(e) => info("mixed recipients",
                           "ML-KEM-1024+X448 recipient treated as SEIPDv1 only",
                           format!("error: {}", chain(&e))),
        }
    }

    // Forward compatibility: a subkey with an algorithm ID that
    // sequoia-openpgp does not know (37 is the first ID of
    // draft-ietf-openpgp-nist-bp-comp, which is out of scope).
    if let Some(pq) = mldsa {
        let r = (|| -> Result<String> {
            let unknown: Key<openpgp::packet::key::PublicParts, SubordinateRole> =
                Key::V6(Key6::new(
                    std::time::SystemTime::now() - std::time::Duration::new(60, 0),
                    PublicKeyAlgorithm::Unknown(37),
                    mpi::PublicKey::Unknown {
                        mpis: vec![].into_boxed_slice(),
                        rest: vec![0x42; 64].into_boxed_slice(),
                    })?);
            let vc = pq.with_policy(p, None)?;
            let new = SubkeyBuilder::new(
                vc, unknown.parts_into_unspecified(),
                KeyFlags::empty().set_transport_encryption())?
                .set_primary_key_signer(primary_signer(pq)?)
                .attach_cert()?;
            let bytes = new.to_vec()?;
            let parsed = Cert::from_bytes(&bytes)?;
            let n_keys = parsed.keys().count();
            let vc = parsed.with_policy(p, None)?;
            let algos: Vec<String> = vc.keys().map(|k| k.key().pk_algo().to_string()).collect();
            let c = encrypt(p, &[&parsed], None, false)?;
            let d = describe(&c);
            decrypt(p, &c, pq, None)?;
            Ok(format!("{} keys after re-parsing; keys valid under StandardPolicy: [{}]; \
                        encrypt (supported keys only): {}; decrypt ok",
                       n_keys, algos.join(", "), d))
        })();
        row("unknown algorithm", "certificate with an extra subkey of algorithm ID 37", r);
    }
}

// ---------------------------------------------------------------------
// RFC 9980 Appendix A.

fn vectors(p: &dyn Policy, dir: &str) {
    let manifest = match std::fs::read_to_string(format!("{}/manifest.tsv", dir)) {
        Ok(m) => m,
        Err(e) => {
            row("vectors", "read manifest.tsv", Err(e.into()));
            return;
        }
    };
    let mut sk: Option<Cert> = None;
    let mut pk: Option<Cert> = None;
    for l in manifest.lines() {
        let f: Vec<&str> = l.split('\t').collect();
        if f.len() < 6 {
            continue;
        }
        let (section, kind, file, title, fpr, sfpr) = (f[0], f[1], f[2], f[3], f[4], f[5]);
        let g = format!("RFC 9980 {}", section);
        let data = match std::fs::read(format!("{}/{}", dir, file)) {
            Ok(d) => d,
            Err(e) => {
                row(&g, title, Err(e.into()));
                continue;
            }
        };
        match kind {
            "PRIVATE KEY BLOCK" | "PUBLIC KEY BLOCK" => {
                let r = (|| -> Result<(Cert, String)> {
                    let c = Cert::from_bytes(&data)?;
                    let mut d = format!(
                        "primary: {}; subkey: {}", key_line(c.primary_key().key()),
                        c.keys().subkeys().next().map(|k| key_line(k.key()))
                            .unwrap_or_default());
                    if fpr != "-" {
                        let got = c.fingerprint().to_hex().to_lowercase();
                        if got != fpr {
                            return Err(anyhow!("primary fingerprint {} differs from the RFC's {}",
                                               got, fpr));
                        }
                        let got = c.keys().subkeys().next()
                            .map(|k| k.key().fingerprint().to_hex().to_lowercase())
                            .unwrap_or_default();
                        if got != sfpr {
                            return Err(anyhow!("subkey fingerprint {} differs from the RFC's {}",
                                               got, sfpr));
                        }
                        d.push_str("; both fingerprints as stated in the RFC");
                    }
                    if kind == "PRIVATE KEY BLOCK" {
                        if !c.is_tsk() || c.keys().secret().count() != c.keys().count() {
                            return Err(anyhow!("secret key material missing"));
                        }
                        if c.keys().unencrypted_secret().count() != c.keys().count() {
                            return Err(anyhow!("secret key material is encrypted"));
                        }
                    }
                    Ok((c, d))
                })();
                match r {
                    Ok((c, d)) => {
                        row(&g, &format!("parse {}", title), Ok(d));
                        row(&g, &format!("{} valid under StandardPolicy", title),
                            c.with_policy(p, None).map(|vc| format!(
                                "{} of {} keys valid, {} of them supported by the backend",
                                vc.keys().count(), c.keys().count(),
                                vc.keys().supported().count())));
                        if kind == "PRIVATE KEY BLOCK" {
                            sk = Some(c);
                            pk = None;
                        } else {
                            if let Some(s) = &sk {
                                row(&g, "public key equals the secret key's public part",
                                    if s.clone().strip_secret_key_material() == c {
                                        Ok(String::new())
                                    } else {
                                        Err(anyhow!("they differ"))
                                    });
                            }
                            pk = Some(c);
                        }
                    }
                    Err(e) => {
                        row(&g, &format!("parse {}", title), Err(e));
                        if kind == "PRIVATE KEY BLOCK" {
                            sk = None;
                            pk = None;
                        }
                    }
                }
            }
            "MESSAGE" => match (&sk, &pk) {
                (Some(s), Some(c)) => {
                    info(&g, &format!("structure of {}", title), describe(&data));
                    row(&g, &format!("decrypt and verify {}", title),
                        decrypt(p, &data, s, Some(c)));
                }
                _ => { row(&g, title, Err(anyhow!("the keys of this section did not parse"))); }
            },
            "SIGNATURE" => match &pk {
                Some(c) => {
                    row(&g, &format!("verify {}", title), verify_detached(p, &data, MSG, c));
                }
                None => { row(&g, title, Err(anyhow!("the key of this section did not parse"))); }
            },
            other => { row(&g, title, Err(anyhow!("unknown block kind {}", other))); }
        }
    }
}

fn main() {
    let p = &StandardPolicy::new();
    let args: Vec<String> = std::env::args().collect();

    println!("# sequoia-openpgp {}; backend: {}", openpgp::VERSION, openpgp::crypto::backend());
    println!("# group | operation | status | detail");

    use PublicKeyAlgorithm::*;
    for a in [X25519, X448, Ed25519, Ed448, MLDSA65_Ed25519, MLDSA87_Ed448,
              SLHDSA128s, SLHDSA128f, SLHDSA256s, MLKEM768_X25519, MLKEM1024_X448] {
        info("backend", &format!("PublicKeyAlgorithm {} (ID {}) is_supported", a, u8::from(a)),
             a.is_supported().to_string());
    }
    for (n, cs) in [("CipherSuite::MLDSA65_Ed25519", CipherSuite::MLDSA65_Ed25519),
                    ("CipherSuite::MLDSA87_Ed448", CipherSuite::MLDSA87_Ed448)] {
        info("backend", &format!("{} is_supported", n),
             cs.is_supported().map(|_| "true".to_string())
             .unwrap_or_else(|e| format!("false: {}", e)));
    }
    for a in [AEADAlgorithm::OCB, AEADAlgorithm::GCM, AEADAlgorithm::EAX] {
        info("backend", &format!("AEAD {} is_supported", a), a.is_supported().to_string());
    }
    info("backend", "default AEAD / symmetric algorithm",
         format!("{} / {}", AEADAlgorithm::default(), SymmetricAlgorithm::default()));

    type Spec = PublicKeyAlgorithmSpecification;
    let suites = [
        Suite { name: "ML-DSA-65+Ed25519 / ML-KEM-768+X25519",
                sig: Spec::mldsa65_ed25519, kem: Spec::mlkem768_x25519, composite: true },
        Suite { name: "ML-DSA-87+Ed448 / ML-KEM-1024+X448",
                sig: Spec::mldsa87_ed448, kem: Spec::mlkem1024_x448, composite: true },
        Suite { name: "SLH-DSA-SHAKE-128s / ML-KEM-768+X25519",
                sig: Spec::slhdsa128s, kem: Spec::mlkem768_x25519, composite: false },
        Suite { name: "SLH-DSA-SHAKE-128f / ML-KEM-768+X25519",
                sig: Spec::slhdsa128f, kem: Spec::mlkem768_x25519, composite: false },
        Suite { name: "SLH-DSA-SHAKE-256s / ML-KEM-1024+X448",
                sig: Spec::slhdsa256s, kem: Spec::mlkem1024_x448, composite: false },
    ];
    let certs: Vec<Option<Cert>> = suites.iter().map(|s| v6_suite(p, s)).collect();

    let v4 = v4_case(p);
    negative(p, certs[0].as_ref(), certs[3].as_ref(), certs[1].as_ref(), v4.as_ref());

    let mut named: Vec<(&str, Option<&Cert>)> =
        suites.iter().zip(certs.iter()).map(|(s, c)| (s.name, c.as_ref())).collect();
    named.push(("v4 + ML-KEM-768+X25519", v4.as_ref()));
    system_policy(&named);

    if let Some(dir) = args.get(1) {
        vectors(p, dir);
    } else {
        println!("# no vector directory given: RFC 9980 Appendix A not run");
    }

    let fails = FAILS.load(Ordering::SeqCst);
    println!("# summary: {} FAIL, {} ACCEPTED (forbidden constructions that were not refused)",
             fails, ACCEPTED.load(Ordering::SeqCst));
    std::process::exit(if fails > 0 { 1 } else { 0 });
}
