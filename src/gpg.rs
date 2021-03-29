// Copyright 2019-2020 Heiko Schaefer <heiko@schaefer.name>
//
// This file is part of OpenPGP CA
// https://gitlab.com/openpgp-ca/openpgp-ca
//
// SPDX-FileCopyrightText: 2019-2020 Heiko Schaefer <heiko@schaefer.name>
// SPDX-License-Identifier: GPL-3.0-or-later

use std::collections::BTreeMap;

use std::fmt;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::process::Stdio;

use sha2::Sha256;
use sha2::Digest;

use anyhow::{Context, Result};
use csv::StringRecord;

use sequoia_openpgp as openpgp;
use openpgp::Fingerprint;

/// Errors used in this module.
///
/// Note: This enum cannot be exhaustively matched to allow future
/// extensions.
#[non_exhaustive]
#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The output is unchanged.
    #[error("Output unchanged")]
    Unchanged,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct OutputHash {
    hash: Vec<u8>,
}

pub fn make_context() -> Result<Ctx> {
    let ctx = Ctx::ephemeral().context(
        "SKIP: Failed to create GnuPG context. Is GnuPG installed?",
    )?;

    ctx.start("gpg-agent").context(
        "SKIP: Failed to to start gpg-agent. Is the GnuPG agent installed?",
    )?;

    Ok(ctx)
}

/// A GnuPG context.
#[derive(Debug)]
pub struct Ctx {
    homedir: Option<PathBuf>,
    components: BTreeMap<String, PathBuf>,
    directories: BTreeMap<String, PathBuf>,
    sockets: BTreeMap<String, PathBuf>,
    #[allow(dead_code)] // We keep it around for the cleanup.
    ephemeral: Option<tempfile::TempDir>,
}

impl Ctx {
    /// Creates a new context for the default GnuPG home directory.
    pub fn new() -> Result<Self> {
        Self::make(None, None)
    }

    /// Creates a new context for the given GnuPG home directory.
    pub fn with_homedir<P>(homedir: P) -> Result<Self>
    where
        P: AsRef<Path>,
    {
        Self::make(Some(homedir.as_ref()), None)
    }

    /// Creates a new ephemeral context.
    ///
    /// The created home directory will be deleted once this object is
    /// dropped.
    pub fn ephemeral() -> Result<Self> {
        Self::make(None, Some(tempfile::tempdir()?))
    }

    /// don't delete home directory.
    /// this is intended for manually debugging data that was created in a
    /// test-run.
    pub fn leak_tempdir(&mut self) -> Option<PathBuf> {
        if self.ephemeral.is_some() {
            let _ = self.stop_all();
            let _ = self.remove_socket_dir();
        }
        self.ephemeral.take().map(tempfile::TempDir::into_path)
    }

    fn make(
        homedir: Option<&Path>,
        ephemeral: Option<tempfile::TempDir>,
    ) -> Result<Self> {
        let mut components: BTreeMap<String, PathBuf> = Default::default();
        let mut directories: BTreeMap<String, PathBuf> = Default::default();
        let mut sockets: BTreeMap<String, PathBuf> = Default::default();

        let homedir: Option<PathBuf> = ephemeral
            .as_ref()
            .map(|tmp| tmp.path())
            .or(homedir)
            .map(|p| p.into());

        for fields in
            Self::gpgconf(&homedir, &["--list-components"], 3)?.into_iter()
        {
            components.insert(
                String::from_utf8(fields[0].clone())?,
                String::from_utf8(fields[2].clone())?.into(),
            );
        }

        for fields in Self::gpgconf(&homedir, &["--list-dirs"], 2)?.into_iter()
        {
            let (mut key, value) = (fields[0].clone(), fields[1].clone());
            if key.ends_with(b"-socket") {
                let l = key.len();
                key.truncate(l - b"-socket".len());
                sockets.insert(
                    String::from_utf8(key)?,
                    String::from_utf8(value)?.into(),
                );
            } else {
                directories.insert(
                    String::from_utf8(key)?,
                    String::from_utf8(value)?.into(),
                );
            }
        }

        Ok(Ctx {
            homedir,
            components,
            directories,
            sockets,
            ephemeral,
        })
    }

    fn gpgconf(
        homedir: &Option<PathBuf>,
        arguments: &[&str],
        nfields: usize,
    ) -> Result<Vec<Vec<Vec<u8>>>> {
        let nl = |&c: &u8| c as char == '\n';
        let colon = |&c: &u8| c as char == ':';

        let mut gpgconf = Command::new("gpgconf");
        if let Some(homedir) = homedir {
            gpgconf.arg("--homedir").arg(homedir);

            // https://dev.gnupg.org/T4496
            gpgconf.env("GNUPGHOME", homedir);
        }

        for argument in arguments {
            gpgconf.arg(argument);
        }
        let output = gpgconf.output().map_err(|e| -> anyhow::Error {
            GnupgError::GPGConf(e.to_string()).into()
        })?;

        if output.status.success() {
            let mut result = Vec::new();
            for line in output.stdout.split(nl) {
                if line.is_empty() {
                    // EOF.
                    break;
                }

                let fields = line
                    .splitn(nfields, colon)
                    .map(|f| f.to_vec())
                    .collect::<Vec<_>>();

                if fields.len() != nfields {
                    return Err(GnupgError::GPGConf(format!(
                        "Malformed response, expected {} fields, \
                         on line: {:?}",
                        nfields, line
                    ))
                    .into());
                }

                result.push(fields);
            }
            Ok(result)
        } else {
            Err(GnupgError::GPGConf(
                String::from_utf8_lossy(&output.stderr).into_owned(),
            )
            .into())
        }
    }

    /// Returns the path to a GnuPG component.
    pub fn component<C>(&self, component: C) -> Result<&Path>
    where
        C: AsRef<str>,
    {
        self.components
            .get(component.as_ref())
            .map(|p| p.as_path())
            .ok_or_else(|| {
                GnupgError::GPGConf(format!(
                    "No such component {:?}",
                    component.as_ref()
                ))
                .into()
            })
    }

    /// Returns the path to a GnuPG directory.
    pub fn directory<C>(&self, directory: C) -> Result<&Path>
    where
        C: AsRef<str>,
    {
        self.directories
            .get(directory.as_ref())
            .map(|p| p.as_path())
            .ok_or_else(|| {
                GnupgError::GPGConf(format!(
                    "No such directory {:?}",
                    directory.as_ref()
                ))
                .into()
            })
    }

    /// Returns the path to a GnuPG socket.
    pub fn socket<C>(&self, socket: C) -> Result<&Path>
    where
        C: AsRef<str>,
    {
        self.sockets
            .get(socket.as_ref())
            .map(|p| p.as_path())
            .ok_or_else(|| {
                GnupgError::GPGConf(format!(
                    "No such socket {:?}",
                    socket.as_ref()
                ))
                .into()
            })
    }

    /// Creates directories for RPC communication.
    pub fn create_socket_dir(&self) -> Result<()> {
        Self::gpgconf(&self.homedir, &["--create-socketdir"], 1)?;
        Ok(())
    }

    /// Removes directories for RPC communication.
    ///
    /// Note: This will stop all servers once they note that their
    /// socket is gone.
    pub fn remove_socket_dir(&self) -> Result<()> {
        Self::gpgconf(&self.homedir, &["--remove-socketdir"], 1)?;
        Ok(())
    }

    /// Starts a GnuPG component.
    pub fn start(&self, component: &str) -> Result<()> {
        self.create_socket_dir()?;
        Self::gpgconf(&self.homedir, &["--launch", component], 1)?;
        Ok(())
    }

    /// Stops a GnuPG component.
    pub fn stop(&self, component: &str) -> Result<()> {
        Self::gpgconf(&self.homedir, &["--kill", component], 1)?;
        Ok(())
    }

    /// Stops all GnuPG components.
    pub fn stop_all(&self) -> Result<()> {
        self.stop("all")
    }
}

impl Drop for Ctx {
    fn drop(&mut self) {
        if self.ephemeral.is_some() {
            let _ = self.stop_all();
            let _ = self.remove_socket_dir();
        }
    }
}

impl std::error::Error for GnupgError {}

impl fmt::Display for GnupgError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GnupgError::GPGConf(s) => write!(f, "gpgconf: {}", s),
            GnupgError::OperationFailed(s) => {
                write!(f, "Operation failed: {}", s)
            }
            GnupgError::ProtocolError(s) => {
                write!(f, "Protocol violation: {}", s)
            }
        }
    }
}

#[derive(Debug)]
/// Errors used in this module.
pub enum GnupgError {
    /// Errors related to `gpgconf`.
    GPGConf(String),

    /// The remote operation failed.
    OperationFailed(String),

    /// The remote party violated the protocol.
    ProtocolError(String),
}

pub fn import(ctx: &Ctx, what: &[u8]) -> Result<()> {
    let doit = || -> Result<()> {
        let mut gpg = Command::new("gpg")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .arg("--homedir")
            .arg(ctx.directory("homedir")?)
            .arg("--import")
            .spawn()?;
        gpg.stdin.as_mut().expect("attached").write_all(what)?;
        gpg.wait()?;
        Ok(())
    };

    doit().context("Running gpg --import")?;
    Ok(())
}

pub fn export(ctx: &Ctx, search: Option<&str>, if_changed: Option<&OutputHash>)
    -> Result<(String, OutputHash)>
{
    let doit = || -> Result<(String, OutputHash)> {
        let mut gpg = Command::new("gpg");
        gpg
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .arg("--homedir")
            .arg(ctx.directory("homedir")?)
            .arg("--armor")
            .arg("--export");
        if let Some(search) = search {
            gpg.arg(search);
        }

        let gpg = gpg.output()?;

        let mut output_hasher = Sha256::new();
        output_hasher.update(&gpg.stdout);
        let output_hash = OutputHash {
            hash: output_hasher.finalize()[..].to_vec()
        };
        if let Some(if_changed) = if_changed {
            if &output_hash == if_changed {
                // Result is unchanged.
                return Err(Error::Unchanged.into());
            }
        }

        Ok((String::from_utf8_lossy(&gpg.stdout).into_owned(), output_hash))
    };

    Ok(doit()?)
}

// If if_changed is not None, this hashes the output before parsing.
// If the output's hash (as returned by a previous call to this
// function) matches if_changed, this function returns an error.
fn list_keys_raw(ctx: &Ctx, if_changed: Option<&OutputHash>)
    -> Result<(Vec<StringRecord>, OutputHash)>
{
    let doit = || -> Result<_> {
        let mut gpg = Command::new("gpg");
        gpg
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .arg("--homedir")
            .arg(ctx.directory("homedir")?)
            .arg("--list-keys")
            .arg("--with-colons");

        let gpg = gpg.output()?;

        let mut output_hasher = Sha256::new();
        output_hasher.update(&gpg.stdout);
        let output_hash = OutputHash {
            hash: output_hasher.finalize()[..].to_vec()
        };
        if let Some(if_changed) = if_changed {
            if &output_hash == if_changed {
                // Result is unchanged.
                return Err(Error::Unchanged.into());
            }
        }

        // Although csv takes a byte string, it expects valid UTF-8.
        // Doing a lossy conversion might break a few User IDs, but
        // everyone uses UTF-8 these days.
        let output = String::from_utf8_lossy(&gpg.stdout);
        let output = output.as_bytes();
        let mut rdr = csv::ReaderBuilder::new()
            .has_headers(false)
            .delimiter(b':')
            .flexible(true)
            .from_reader(std::io::Cursor::new(output));

        // We don't expect gpg to return invalid records.  But, let's
        // ignore any just in case.
        let r = rdr.records().filter_map(|rec| {
            match rec {
                Ok(rec) => Some(rec),
                Err(err) => {
                    warn!("Parsing gpg --list-keys --with-colons:\n  {}",
                          err);
                    None
                }
            }
        }).collect();

        Ok((r, output_hash))
    };

    Ok(doit().context("Running gpg --list-keys --with-colons")?)
}

#[derive(Debug, PartialEq, Eq)]
pub enum Validity {
    Marginal,
    Fully,
    Ultimately,
}

pub fn list_validity(ctx: &Ctx, if_changed: Option<&OutputHash>)
    -> Result<(Vec<(Fingerprint, Vec<(String, Validity)>)>, OutputHash)>
{
    rnp_function!(list_validity, super::TRACE);

    let (res, output_hash) = list_keys_raw(&ctx, if_changed)?;

    let mut validity: Vec<(Fingerprint, Vec<(String, Validity)>)>
        = Vec::new();
    let mut key_validity: Vec<(String, Validity)> = Vec::new();

    let mut fingerprint: Option<Fingerprint> = None;
    for line in res.into_iter() {
        match line.get(0) {
            Some("pub") => {
                if ! key_validity.is_empty() {
                    validity.push((fingerprint.expect("set"),
                                   key_validity));
                    key_validity = Vec::new();
                }

                t!("Start of new certificate");
                fingerprint = None;
            }
            // The first fpr is for the primary key; ignore subkeys.
            Some("fpr") => if fingerprint.is_none() {
                fingerprint = if let Some(fingerprint) = line.get(9) {
                    t!("  Considering {}", fingerprint);
                    fingerprint.parse().ok()
                } else {
                    continue;
                }
            }
            Some("uid") if fingerprint.is_some() => {
                let uid: String = if let Some(uid) = line.get(9) {
                    // XXX: Unquote it:
                    //
                    //   The value is quoted like a C string to avoid
                    //   control characters (the colon is quoted
                    //   =\x3a=).
                    t!("  Considering {}", uid);
                    uid.into()
                } else {
                    continue;
                };

                match line.get(1).unwrap_or("") {
                    // Marginal.
                    "m" => {
                        t!("{}: {} is marginally trusted.",
                           fingerprint.as_ref().expect("set"), uid);
                        key_validity.push((uid, Validity::Marginal));
                    }
                    "f" => {
                        t!("{}: {} is fully trusted.",
                           fingerprint.as_ref().expect("set"), uid);
                        key_validity.push((uid, Validity::Fully));
                    }
                    "u" => {
                        t!("{}: {} is ultimately trusted.",
                           fingerprint.as_ref().expect("set"), uid);
                        key_validity.push((uid, Validity::Ultimately));
                    }
                    _ => (),
                }
            }
            _ => {
                continue;
            }
        }
    }

    if ! key_validity.is_empty() {
        validity.push((fingerprint.expect("set"),
                       key_validity));
    }

    Ok((validity, output_hash))
}
