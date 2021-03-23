use libc::{
    c_char,
};

use sequoia_openpgp as openpgp;

use crate::{
    RnpResult,
    RnpContext,
    RnpInput,
    keyring::parse_keyring,
    str_to_rnp_buffer,
    flags::*,
    error::*,
};

#[derive(serde::Serialize, Debug, Default)]
struct ImportResults {
    keys: Vec<ImportResult>,
}

#[derive(serde::Serialize, Debug)]
struct ImportResult {
    public: String,
    secret: String,
    fingerprint: String,
}

impl Default for ImportResult {
    fn default() -> Self {
        ImportResult {
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

    let mut import_results = ImportResults::default();

    let f = || -> openpgp::Result<()> {
        // First, load into an accumulator.  If any cert is bad, and
        // not keep_going, then the whole operation should fail.
        let certs = parse_keyring(input)?;
        let mut acc = Vec::new();
        for cert in certs {
            t!("Considering cert {:?}", cert.as_ref().map(|c| c.fingerprint()));
            match cert {
                Err(_) if keep_going => continue,
                Err(e) => {
                    _warn!("bad key and !keep_going, aborting: {}", e);
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

            let mut r = ImportResult::default();
            let fp = cert.fingerprint();
            r.fingerprint = fp.to_string();

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

stub!(rnp_import_signatures);
