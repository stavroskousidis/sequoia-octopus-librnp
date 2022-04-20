use libc::{
    c_char,
};

use sequoia_openpgp as openpgp;

use crate::{
    RnpResult,
    RnpContext,
    RnpInput,
    str_to_rnp_buffer,
    flags::*,
    error::*,
};

#[derive(serde::Serialize, Debug, Default)]
struct KeyImportResults {
    keys: Vec<KeyImportResult>,
}

#[derive(serde::Serialize, Debug)]
struct KeyImportResult {
    public: String,
    secret: String,
    fingerprint: String,
}

impl Default for KeyImportResult {
    fn default() -> Self {
        KeyImportResult {
            public: RnpKeyImportStatus::Unknown.into(),
            secret: RnpKeyImportStatus::Unknown.into(),
            fingerprint: Default::default(),
        }
    }
}

enum RnpKeyImportStatus {
    Unknown,
    Unchanged,
    Updated,
    New,
}

impl From<RnpKeyImportStatus> for String {
    fn from(s: RnpKeyImportStatus) -> Self {
        use RnpKeyImportStatus::*;
        match s {
            Unknown => "unknown".into(),
            Unchanged => "unchanged".into(),
            Updated => "updated".into(),
            New => "new".into(),
        }
    }
}

#[derive(serde::Serialize, Debug, Default)]
struct SigImportResults {
    sigs: Vec<SigImportResult>,
}

#[derive(serde::Serialize, Debug)]
struct SigImportResult {
    public: String,
    secret: String,
    #[serde(rename = "signer fingerprint")]
    signer_fingerprint: String,
}

impl Default for SigImportResult {
    fn default() -> Self {
        SigImportResult {
            public: RnpSigImportStatus::Unknown.into(),
            secret: RnpSigImportStatus::Unknown.into(),
            signer_fingerprint: Default::default(),
        }
    }
}

#[derive(PartialEq)]
enum RnpSigImportStatus {
    Unknown,
    UnknownKey,
    Unchanged,
    New,
}

impl From<RnpSigImportStatus> for String {
    fn from(s: RnpSigImportStatus) -> Self {
        use RnpSigImportStatus::*;
        match s {
            Unknown => "unknown".into(),
            UnknownKey => "unknown key".into(),
            Unchanged => "unchanged".into(),
            New => "new".into(),
        }
    }
}

/// XXX: RNP reports per subkey results, we don't, and it is not clear
/// that we want that (or that any caller may want that).  Currently,
/// TB doesn't use this information at all, but is planning to do so
/// in the future (again, not clear if they care about subkeys).
#[no_mangle] pub unsafe extern "C"
fn rnp_import_keys(ctx: *mut RnpContext,
                   input: *mut RnpInput,
                   flags: u32,
                   results: *mut *mut c_char)
                   -> RnpResult {
    rnp_function!(rnp_import_keys, crate::TRACE);

    let ctx = assert_ptr_mut!(ctx);
    let input = assert_ptr_mut!(input);

    let public = flags & RNP_LOAD_SAVE_PUBLIC_KEYS > 0;
    let secret = flags & RNP_LOAD_SAVE_SECRET_KEYS > 0;
    let keep_going = flags & RNP_LOAD_SAVE_PERMISSIVE > 0;
    let single = flags & RNP_LOAD_SAVE_SINGLE > 0;
    t!("public = {}, secret = {}, keep_going = {}, single = {}",
       public, secret, keep_going, single);

    let mut import_results = KeyImportResults::default();

    let f = || -> openpgp::Result<()> {
        // First, load into an accumulator.  If any cert is bad, and
        // not keep_going, then the whole operation should fail.
        let certs = sequoia_openpgp_mt::keyring::parse(input)?;
        let mut acc = Vec::new();
        for cert in certs {
            t!("Considering cert {:?}", cert.as_ref().map(|c| c.fingerprint()));
            match cert {
                Err(_) if keep_going => continue,
                Err(e) => {
                    warn!("bad key and !keep_going, aborting: {}", e);
                    return Err(e);
                },
                Ok(v) => acc.push(v),
            }

            if single {
                // Just load the first key.
                break;
            }
        }

        for cert in acc {
            use RnpKeyImportStatus::*;

            let mut r = KeyImportResult::default();
            let fp = cert.fingerprint();
            r.fingerprint = fp.to_hex();

            let status;
            if let Some(known) = ctx.certs.read().by_primary_fp(&fp) {
                if *known == cert {
                    status = Unchanged;
                } else {
                    // XXX: This is not quite correct.  False
                    // positive if cert has less information than
                    // known.  Then, it is not really an update.
                    status = Updated;
                }
            } else {
                status = New;
                // ctx is still mutably borrowed.  Do the
                // insertion in a second step to appease the
                // borrow checker.
            }

            let imported_secret = secret && cert.is_tsk();

            if let Unchanged = status {
                // Nothing to do.
            } else {
                // Appease the borrow checker.
                if secret {
                    ctx.insert_key(cert);
                } else {
                    ctx.insert_cert(cert);
                }
            }

            r.public = status.into();
            if imported_secret {
                r.secret = r.public.clone();
            }

            t!("Imported {:?}", r);
            import_results.keys.push(r);
        }

        if ! results.is_null() {
            *results = str_to_rnp_buffer(
                serde_json::to_string_pretty(&import_results)?);
        }

        Ok(())
    };

    if let Err(e) = f() {
        warn!("rnp_import_keys: {}", e);
        RNP_ERROR_GENERIC
    } else {
        RNP_SUCCESS
    }
}

/// Import detached signatures by adding them to the cert or key that issued them.
///
/// Warning: We assume that signatures are first-party signatures (see sequoia#692)!
/// WARNING: We do not handle third-party revocations!
///
/// Does not import anything in case of any faulty input.
#[no_mangle]
pub unsafe extern "C" fn rnp_import_signatures(
    ctx: *mut RnpContext,
    input: *mut RnpInput,
    _flags: u32,
    results: *mut *mut c_char,
) -> RnpResult {
    use openpgp::packet::{Packet, Signature};

    rnp_function!(rnp_import_signatures, crate::TRACE);

    let ctx = assert_ptr_mut!(ctx);
    let input = assert_ptr_mut!(input);

    let mut import_results = SigImportResults::default();

    let mut f = || -> openpgp::Result<()> {

        fn parse_input(input: &mut RnpInput) -> openpgp::Result<Vec<Signature>> {
            use openpgp::parse::{PacketParser, PacketParserResult, Parse};

            let mut ppr: PacketParserResult = PacketParser::from_reader(input)?;
            let mut signatures: Vec<Signature> = Vec::new();

            while let PacketParserResult::Some(pp) = ppr {
                let (packet, next_ppr) = pp.next()?;
                ppr = next_ppr;

                match packet {
                    Packet::Signature(sig) => {
                        signatures.push(sig);
                    }
                    Packet::Marker(_) => {
                        // ignore Marker packets
                    }
                    Packet::Unknown(unknown) => {
                        if unknown.tag() == openpgp::packet::Tag::Signature {
                            t!("Found unknown signature packet {:?}", unknown);
                        } else {
                            Err(anyhow::anyhow!(
                                "Found unknown packet: {}",
                                unknown.tag()
                            ))?
                        }
                    }
                    p => Err(anyhow::anyhow!(
                        "Found unexpected packet: {}",
                        p.tag()
                    ))?,
                };
            }
            Ok(signatures)
        }

        // First, parse the input and stop if there is an error.
        // Then, try to import each signature, collect outcome in import_results.
        let signatures = parse_input(input)?;
        for sig in signatures.into_iter() {
            t!("Considering signature by {:?}, {}", sig.get_issuers(), sig.typ());

            let issuers = &sig.get_issuers();
            let mut issuers = issuers.iter();

            let mut merged = false;

            // Iterate over the issuer hints, merge signature for the fist issuer
            // found in one of the keystores.
            while let Some(issuer) = issuers.next() {
                if merged {
                    break
                }
                t!("Considering issuer {}", issuer);

                // XXX: We assume that signatures are first-party
                // signatures (see sequoia#692)!
                // We do not handle third-party revocations!

                let mut inner = |issuer: &openpgp::KeyHandle|
                    -> openpgp::Result<SigImportResult> {

                    fn try_merge(
                        sig: Signature,
                        cert: openpgp::Cert,
                        ) -> openpgp::Result<openpgp::Cert> {
                        let old_count = cert.bad_signatures().count();
                        let cert_new = cert
                            .insert_packets(Packet::Signature(sig.clone()))?;
                        if old_count < cert_new.bad_signatures().count()
                            {
                                Err(anyhow::anyhow!("signature does not match"))
                            } else {
                                Ok(cert_new)
                            }
                    }

                    // Find key and/or cert which issued the signature.
                    let cert = match issuer {
                        openpgp::KeyHandle::Fingerprint(fp) => {
                            ctx.certs.read().by_primary_fp(&fp).map(|c| c.clone())
                        }
                        openpgp::KeyHandle::KeyID(id) => {
                            ctx.certs.read().by_primary_id(&id).next().map(|c| c.clone())
                        }
                    };
                    let cert = cert.ok_or_else(|| anyhow::anyhow!("no cert found"))?;

                    t!("Found cert: {:?}", cert.fingerprint());

                    let cert_merged = try_merge(sig.clone(), cert.clone())?;

                    let mut r = SigImportResult::default();
                    r.signer_fingerprint = cert.fingerprint().to_hex();
                    let status = if cert.eq(&cert_merged) {
                        RnpSigImportStatus::Unchanged
                    } else {
                        RnpSigImportStatus::New
                    };

                    let has_secret = cert_merged.is_tsk();
                    if has_secret {
                        if status == RnpSigImportStatus::New {
                            ctx.insert_key(cert_merged)
                        };
                    } else {
                        if status == RnpSigImportStatus::New {
                            ctx.insert_cert(cert_merged);
                        };
                    }

                    if has_secret {
                        r.public = status.into();
                        r.secret = r.public.clone();
                    } else {
                        r.public = status.into();
                        r.secret = RnpSigImportStatus::UnknownKey.into();
                    }

                    Ok(r)
                };

                let r = inner(issuer);

                if let Ok(r) = r {
                    t!("Imported {:?}", r);
                    import_results.sigs.push(r);

                    // The sig was merged for this issuer, stop.
                    merged = true;
                }

                if ! merged {
                    t!("No cert or key found");

                    // TODO: rnp returns this result if it ends up not finding the
                    // issuer in either keyring.
                    // It's quite unhelpful, but maybe consumers expect a result entry
                    // for each sig?
                    let r = SigImportResult {
                        public: RnpSigImportStatus::UnknownKey.into(),
                        secret: RnpSigImportStatus::UnknownKey.into(),
                        signer_fingerprint: Default::default(),
                    };
                    import_results.sigs.push(r);
                }
            }
        }

        if ! results.is_null() {
            *results = str_to_rnp_buffer(
                serde_json::to_string_pretty(&import_results)?);
        }
        Ok(())
    };


    if let Err(e) = f() {
        warn!("rnp_import_signatures: {}", e);
        RNP_ERROR_GENERIC
    } else {
        RNP_SUCCESS
    }
}
