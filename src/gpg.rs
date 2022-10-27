// Copyright 2019-2020 Heiko Schaefer <heiko@schaefer.name>
//
// This file is part of OpenPGP CA
// https://gitlab.com/openpgp-ca/openpgp-ca
//
// SPDX-FileCopyrightText: 2019-2020 Heiko Schaefer <heiko@schaefer.name>, 2019-2021 pep Foundation
// SPDX-License-Identifier: LGPL-2.0-or-later

use std::collections::BTreeMap;

use std::fmt;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::process::Stdio;
use std::time::SystemTime;

use anyhow::{Context, Result};
use csv::StringRecord;

use sequoia_openpgp as openpgp;
use openpgp::{
    crypto::hash::Digest,
    Fingerprint,
    types::HashAlgorithm,
};

// Setting this to false will cause the creation of a context to fail.
const ENABLE_GPG: bool = true;

/// Errors used in this module.
///
/// Note: This enum cannot be exhaustively matched to allow future
/// extensions.
#[non_exhaustive]
#[derive(thiserror::Error, Debug, Clone)]
pub enum Error {
    /// The output is unchanged.
    ///
    /// Returns the new cache tag.  Use it to update the stored tag.
    /// This way, if a file is modified but the output is the same,
    /// you will store the new modification time.
    #[error("Output unchanged")]
    Unchanged(CacheTag),
}

#[derive(Debug, Clone)]
pub struct CacheTag {
    /// Best effort modification time of the keyrings and trust
    /// databases.
    mtime: Option<SystemTime>,
    /// Hash digest of the gpg output.
    hash: Vec<u8>,
}

/// SHA512 is almost twice as fast as SHA256 on 64-bit architectures
/// because it operates on 64-bit words.
#[cfg(target_pointer_width = "64")]
const OUTPUT_HASH_ALGO: HashAlgorithm = HashAlgorithm::SHA512;

/// But, on 32-bit architectures, pick the hash that fits the word
/// size as it will be slightly more efficient.
#[cfg(target_pointer_width = "32")]
const OUTPUT_HASH_ALGO: HashAlgorithm = HashAlgorithm::SHA256;

impl CacheTag {
    /// Creates a new CacheTag for the given data.
    fn new(ctx: &Ctx) -> Result<Self> {
        let homedir: PathBuf = ctx.directory("homedir")?.into();
        let mtime = [
            "pubring.gpg",
            "pubring.kbx",
            "private-keys-v1.d",
            "trustdb.gpg",
            "tofu.db",
        ].iter()
            .filter_map(|name| std::fs::metadata(homedir.join(name)).ok())
            .filter_map(|m| m.modified().ok())
            .max();

        Ok(CacheTag {
            mtime,
            hash: vec![],
        })
    }

    /// Hashes the output.
    fn hash_output(mut self, output: &[u8]) -> Result<Self> {
        let mut output_hasher = OUTPUT_HASH_ALGO.context()?;
        output_hasher.update(&output);
        self.hash = output_hasher.into_digest()?;
        Ok(self)
    }

    /// Steals the output hash from `other`.
    ///
    /// Use this to copy the hash digest from the stored tag when
    /// short-circuiting on the modification time.
    fn hash_steal(mut self, other: &Self) -> Self {
        self.hash = other.hash.clone();
        self
    }

    /// Compares the two modification timestamps.
    ///
    /// If either mtime is not available, this returns false.
    fn mtime_eq(&self, other: &CacheTag) -> bool {
        match (self.mtime, other.mtime) {
            (Some(a), Some(b)) => a == b,
            _ => false,
        }
    }

    /// Compares the two hashes.
    ///
    /// If either digest is not available, this returns false.
    fn hash_eq(&self, other: &CacheTag) -> bool {
        self.hash.len() > 0
            && other.hash.len() > 0
            && self.hash == other.hash
    }
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
        if ! ENABLE_GPG {
            return Err(anyhow::anyhow!("gpg disabled at compile time"));
        }

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

        let mut gpgconf = new_background_command("gpgconf");
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
        let mut gpg = new_background_command("gpg")
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

pub fn export(ctx: &Ctx, search: Option<&str>, if_changed: Option<&CacheTag>)
    -> Result<(String, CacheTag)>
{
    let doit = || -> Result<(String, CacheTag)> {
        let tag = CacheTag::new(ctx)?;
        if let Some(if_changed) = if_changed {
            if tag.mtime_eq(if_changed) {
                // Result is unchanged.
                return
                    Err(Error::Unchanged(tag.hash_steal(if_changed)).into());
            }
        }

        let mut gpg = new_background_command("gpg");
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

        let tag = tag.hash_output(&gpg.stdout)?;
        if let Some(if_changed) = if_changed {
            if tag.hash_eq(if_changed) {
                // Result is unchanged.
                return Err(Error::Unchanged(tag).into());
            }
        }

        Ok((String::from_utf8_lossy(&gpg.stdout).into_owned(), tag))
    };

    Ok(doit()?)
}

fn new_background_command<S>(program: S) -> Command
where
    S: AsRef<std::ffi::OsStr>,
{
    let command = Command::new(program);

    #[cfg(windows)]
    let command = {
        use std::os::windows::process::CommandExt;

        // see https://docs.microsoft.com/en-us/windows/win32/procthread/process-creation-flags
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        let mut command = command;
        command.creation_flags(CREATE_NO_WINDOW);
        command
    };

    command
}

// If if_changed is not None, this hashes the output before parsing.
// If the output's hash (as returned by a previous call to this
// function) matches if_changed, this function returns an error.
fn list_keys_raw(ctx: &Ctx, secret: bool, filter: Option<String>,
                 if_changed: Option<&CacheTag>)
    -> Result<(Vec<StringRecord>, CacheTag)>
{
    rnp_function!(list_keys_raw, false);
    t!("filter: {:?}", filter);
    t!("if_chnaged: {:?}", if_changed);

    let doit = || -> Result<_> {
        let tag = CacheTag::new(ctx)?;
        if let Some(if_changed) = if_changed {
            if tag.mtime_eq(if_changed) {
                // Result is unchanged.
                return
                    Err(Error::Unchanged(tag.hash_steal(if_changed)).into());
            }
        }

        let mut gpg = new_background_command("gpg");
        gpg
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .arg("--homedir")
            .arg(ctx.directory("homedir")?)
            .arg("--with-colons");
        if secret {
            gpg.arg("--list-secret-keys");
        } else {
            gpg.arg("--list-keys");
        }
        if let Some(filter) = filter {
            gpg.arg(filter);
        }

        t!("gpg command: {:?}", gpg);

        let gpg = gpg.output()?;

        let tag = tag.hash_output(&gpg.stdout)?;
        if let Some(if_changed) = if_changed {
            if tag.hash_eq(if_changed) {
                // Result is unchanged.
                return Err(Error::Unchanged(tag).into());
            }
        }

        let r = list_keys_raw_parse(&gpg.stdout)?;

        Ok((r, tag))
    };

    Ok(doit().with_context(
        || format!(
            "Running gpg {} --with-colons",
            if secret { "--list-secret-keys" } else { "--list-keys" }))?)
}

fn list_keys_raw_parse(stdout: &[u8])
    -> Result<Vec<StringRecord>>
{
    // Although csv takes a byte string, it expects valid UTF-8.
    // Doing a lossy conversion might break a few User IDs, but
    // everyone uses UTF-8 these days.
    let output = String::from_utf8_lossy(stdout);
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
                global_warn!("Parsing gpg --list-keys --with-colons:\n  {}",
                      err);
                None
            }
        }
    }).collect();

    Ok(r)
}

#[derive(Debug, PartialEq, Eq)]
pub enum Validity {
    Marginal,
    Fully,
    Ultimately,
}

pub fn list_validity(ctx: &Ctx, filter: Option<String>,
                     if_changed: Option<&CacheTag>)
    -> Result<(Vec<(Fingerprint, Vec<(String, Validity)>)>, CacheTag)>
{
    rnp_function!(list_validity, super::TRACE);

    let (res, tag) = list_keys_raw(&ctx, false, filter, if_changed)?;

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

    Ok((validity, tag))
}

pub fn list_secret_keys(ctx: &Ctx, filter: Option<String>,
                        if_changed: Option<&CacheTag>)
    -> Result<(Vec<(Fingerprint, Fingerprint)>, CacheTag)>
{
    rnp_function!(list_secret_keys, super::TRACE);

    let (res, tag) = list_keys_raw(&ctx, true, filter, if_changed)?;
    let secret_keys = list_secret_keys_parse(res)?;

    Ok((secret_keys, tag))
}

pub fn list_secret_keys_parse(res: Vec<csv::StringRecord>)
    -> Result<Vec<(Fingerprint, Fingerprint)>>
{
    rnp_function!(list_secret_keys_parse, super::TRACE);

    let mut secret_keys: Vec<(Fingerprint, Fingerprint)> = Vec::new();

    let mut primary_fingerprint: Option<Fingerprint> = None;
    let mut key_has_secret = false;
    let mut keys = 0;

    // The output looks like:
    //
    //   $ gpg --with-colons -K neal@walfield | grep -E '^(pub|sec|fpr|ssb|sub)'
    //   sec:r:1024:17:3BF609C68BAFCDBD:991801296:::u:::sca:::+:::::0:
    //   fpr:::::::::11C294DF1D6C9698FEFE231D3BF609C68BAFCDBD:
    //   ssb:r:1024:16:3DAD5ECF8191AFAE:991801300::::::e:::+::::
    //   fpr:::::::::BAE80223CD24C35F8A56518E3DAD5ECF8191AFAE:
    //   sec:u:3744:1:AACB3243630052D9:1428396777:1618145210::u:::scESCA:::#:::::0:
    //   fpr:::::::::8F17777118A33DDA9BA48E62AACB3243630052D9:
    //   ssb:u:2048:1:7223B56678E02528:1428399766:1618145244:::::s:::D27...
    //   fpr:::::::::C03FA6411B03AE12576461187223B56678E02528:
    //   ssb:u:2048:1:C2B819056C652598:1428399800:1618145277:::::e:::D27...
    //   fpr:::::::::50E6D924308DBF223CFB510AC2B819056C652598:
    //   ssb:u:2048:1:A3506AFB820ABD08:1428399828:1618145266:::::a:::D27...
    //   fpr:::::::::2DC50AB55BE2F3B04C2D2CF8A3506AFB820ABD08:
    //
    // In short, we have: key and subkey records, which don't include
    // the fingerprint, and we have 'fpr' records, which include the
    // fingerprint of the preceding key.
    for line in res.into_iter() {
        match line.get(0) {
            Some("pub") => {
                t!("Start of new certificate");
                primary_fingerprint = None;
                key_has_secret = false;
                keys = 0;
            }
            Some("sec") => {
                t!("Start of new key");
                primary_fingerprint = None;
                key_has_secret = true;
                keys = 0;
            }

            Some("sub") => {
                t!("New subkey");
                key_has_secret = false;
                keys += 1;
            }
            Some("ssb") => {
                t!("New secret subkey");
                key_has_secret = true;
                keys += 1;
            }

            // The first fpr is for the primary key.  The rest are for
            // subkeys.
            Some("fpr") => {
                let fpr: Fingerprint = if let Some(fpr) = line.get(9) {
                    t!("  Considering {}", fpr);
                    match fpr.parse() {
                        Ok(fpr) => fpr,
                        Err(err) => {
                            t!("Parsing {:?} as fingerprint: {}",
                               fpr, err);
                            continue;
                        }
                    }
                } else {
                    continue;
                };

                if keys == 0 {
                    // Primary.
                    if key_has_secret {
                        secret_keys.push((fpr.clone(), fpr.clone()));
                    }

                    primary_fingerprint = Some(fpr);
                } else if let Some(ref primary_fingerprint) = primary_fingerprint {
                    // Subkey.
                    if key_has_secret {
                        secret_keys.push((primary_fingerprint.clone(),
                                          fpr.clone()));
                    }
                }

            }
            _ => {
                continue;
            }
        }
    }

    Ok(secret_keys)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_secret_keys() -> Result<()> {
        // $ gpg --with-colons -K neal@walfield.org
        let raw = r#"sec:r:1024:17:3BF609C68BAFCDBD:991801296:::u:::sca:::+:::::0:
fpr:::::::::11C294DF1D6C9698FEFE231D3BF609C68BAFCDBD:
grp:::::::::05962113260A2C8EA6A109FF29BDFB0135046EDB:
uid:r::::1279109191::1B1B7482B7F9ECDBAF1240DE9DCD998175520447::Neal H. Walfield <neal@walfield.org>::::::::::0:
uid:r::::1005763171::EE96475411968ECFDFA4119223DAE7EC591E3DFF::Neal H Walfield <neal@gnu.org>::::::::::0:
uid:r::::991801296::9AD6D7918766A121EF89B575DBBB55F50A219D5E::Neal H Walfield <neal@cs.uml.edu>::::::::::0:
uid:r::::991801340::296A2626DFCCD551020324659B64A82F1C213358::Neal H Walfield <neal@walfield.org>::::::::::0:
uid:r::::1279108858::EDDE4C7DDAD6767B658E6AA40460D9335D3FD6B1::Neal H. Walfield <neal@cs.jhu.edu>::::::::::0:
uid:r::::1279109115::DA1FB102143127EFC07BF8FF3B33F14D71A9F4D6::Neal H. Walfield <neal@gnu.org>::::::::::0:
uid:r::::1279109142::B0ABC32AD3E5DDA33FA25A55EEDDC9B9DFBFC51F::Neal H. Walfield <neal@cs.uml.edu>::::::::::0:
uid:r::::991801401::A6F224DB69F3D02EADAB0D8DCE5C70C1E67F7A49::Neal H Walfield <neal@debian.org>::::::::::0:
ssb:r:1024:16:3DAD5ECF8191AFAE:991801300::::::e:::+::::
fpr:::::::::BAE80223CD24C35F8A56518E3DAD5ECF8191AFAE:
grp:::::::::E10FC1BFDDBAA7E7E5D9ED5EF7426F8FEFDDEAC5:
sec:u:3744:1:AACB3243630052D9:1428396777:1618145210::u:::scESCA:::#:::::0:
fpr:::::::::8F17777118A33DDA9BA48E62AACB3243630052D9:
grp:::::::::C45986381F54F967C2F6B104521C8634090F326A:
uid:u::::1555073210::1B1B7482B7F9ECDBAF1240DE9DCD998175520447::Neal H. Walfield <neal@walfield.org>::::::::::0:
uid:u::::1555073229::59A9F6DB32F4942939989604985D0D623843E722::Neal H. Walfield <neal@gnupg.org>::::::::::0:
uid:r::::::5737B70A0641BECFB13CA64599114B0D0BE9A824::Neal H. Walfield <neal@g10code.com>::::::::::0:
uid:u::::1555073229::29DE54352C7620F4C908DB6E860BD77EFA13B709::Neal H. Walfield <neal@pep.foundation>::::::::::0:
uid:u::::1555073229::56E1B5E6FB1E1FA0F1EFC398C4638563C873DF5B::Neal H. Walfield <neal@pep-project.org>::::::::::0:
uid:u::::1555073229::168858B59F321107B0057756E417110B167C1DF4::Neal H. Walfield <neal@sequoia-pgp.org>::::::::::0:
ssb:u:2048:1:7223B56678E02528:1428399766:1618145244:::::s:::D2760001240102000006030166360000:::23:
fpr:::::::::C03FA6411B03AE12576461187223B56678E02528:
grp:::::::::BE2FE8C8793141322AC30E3EAFD1E4F9D8DACCC4:
ssb:u:2048:1:C2B819056C652598:1428399800:1618145277:::::e:::D2760001240102000006030166360000:::23:
fpr:::::::::50E6D924308DBF223CFB510AC2B819056C652598:
grp:::::::::9873FD355DE470DDC151CD9919AC9785C3C2FDDE:
ssb:u:2048:1:A3506AFB820ABD08:1428399828:1618145266:::::a:::D2760001240102000006030166360000:::23:
fpr:::::::::2DC50AB55BE2F3B04C2D2CF8A3506AFB820ABD08:
grp:::::::::9483454871CC1239D4C2A1416F2742D39A14DB14:
"#;

        let r = list_keys_raw_parse(raw.as_bytes())?;
        let r = list_secret_keys_parse(r)?;

        assert_eq!(
            r,
            vec![
                ("11C294DF1D6C9698FEFE231D3BF609C68BAFCDBD".parse().unwrap(),
                 "11C294DF1D6C9698FEFE231D3BF609C68BAFCDBD".parse().unwrap()),
                ("11C294DF1D6C9698FEFE231D3BF609C68BAFCDBD".parse().unwrap(),
                 "BAE80223CD24C35F8A56518E3DAD5ECF8191AFAE".parse().unwrap()),
                ("8F17777118A33DDA9BA48E62AACB3243630052D9".parse().unwrap(),
                 "8F17777118A33DDA9BA48E62AACB3243630052D9".parse().unwrap()),
                ("8F17777118A33DDA9BA48E62AACB3243630052D9".parse().unwrap(),
                 "C03FA6411B03AE12576461187223B56678E02528".parse().unwrap()),
                ("8F17777118A33DDA9BA48E62AACB3243630052D9".parse().unwrap(),
                 "50E6D924308DBF223CFB510AC2B819056C652598".parse().unwrap()),
                ("8F17777118A33DDA9BA48E62AACB3243630052D9".parse().unwrap(),
                 "2DC50AB55BE2F3B04C2D2CF8A3506AFB820ABD08".parse().unwrap()),
            ]);

        // $ gpg --with-colons -k neal@walfield.org
        let raw = r#"tru::1:1617140210:1618145210:3:1:5
pub:r:1024:17:3BF609C68BAFCDBD:991801296:::u:::sca::::::::0:
fpr:::::::::11C294DF1D6C9698FEFE231D3BF609C68BAFCDBD:
uid:r::::1279109191::1B1B7482B7F9ECDBAF1240DE9DCD998175520447::Neal H. Walfield <neal@walfield.org>::::::::::0:
uid:r::::1005763171::EE96475411968ECFDFA4119223DAE7EC591E3DFF::Neal H Walfield <neal@gnu.org>::::::::::0:
uid:r::::991801296::9AD6D7918766A121EF89B575DBBB55F50A219D5E::Neal H Walfield <neal@cs.uml.edu>::::::::::0:
uid:r::::991801340::296A2626DFCCD551020324659B64A82F1C213358::Neal H Walfield <neal@walfield.org>::::::::::0:
uid:r::::1279108858::EDDE4C7DDAD6767B658E6AA40460D9335D3FD6B1::Neal H. Walfield <neal@cs.jhu.edu>::::::::::0:
uid:r::::1279109115::DA1FB102143127EFC07BF8FF3B33F14D71A9F4D6::Neal H. Walfield <neal@gnu.org>::::::::::0:
uid:r::::1279109142::B0ABC32AD3E5DDA33FA25A55EEDDC9B9DFBFC51F::Neal H. Walfield <neal@cs.uml.edu>::::::::::0:
uid:r::::991801401::A6F224DB69F3D02EADAB0D8DCE5C70C1E67F7A49::Neal H Walfield <neal@debian.org>::::::::::0:
sub:r:1024:16:3DAD5ECF8191AFAE:991801300::::::e:::::::
fpr:::::::::BAE80223CD24C35F8A56518E3DAD5ECF8191AFAE:
pub:r:1024:17:87234295786B0BAD:976762276:::-:::sca::::::::0:
fpr:::::::::520054A53C19CBB2E7F5639687234295786B0BAD:
uid:r::::979410749::A6F224DB69F3D02EADAB0D8DCE5C70C1E67F7A49::Neal H Walfield <neal@debian.org>::::::::::0:
uid:r::::976762276::9AD6D7918766A121EF89B575DBBB55F50A219D5E::Neal H Walfield <neal@cs.uml.edu>::::::::::0:
uid:r::::976769586::296A2626DFCCD551020324659B64A82F1C213358::Neal H Walfield <neal@walfield.org>::::::::::0:
sub:r:1024:16:BCD1834A0CB6D455:976762281::::::e:::::::
fpr:::::::::9C6961D19B435818A3B26E08BCD1834A0CB6D455:
pub:u:3744:1:AACB3243630052D9:1428396777:1618145210::u:::scESCA::::::::0:
fpr:::::::::8F17777118A33DDA9BA48E62AACB3243630052D9:
uid:u::::1555073210::1B1B7482B7F9ECDBAF1240DE9DCD998175520447::Neal H. Walfield <neal@walfield.org>::::::::::0:
uid:u::::1555073229::59A9F6DB32F4942939989604985D0D623843E722::Neal H. Walfield <neal@gnupg.org>::::::::::0:
uid:r::::::5737B70A0641BECFB13CA64599114B0D0BE9A824::Neal H. Walfield <neal@g10code.com>::::::::::0:
uid:u::::1555073229::29DE54352C7620F4C908DB6E860BD77EFA13B709::Neal H. Walfield <neal@pep.foundation>::::::::::0:
uid:u::::1555073229::56E1B5E6FB1E1FA0F1EFC398C4638563C873DF5B::Neal H. Walfield <neal@pep-project.org>::::::::::0:
uid:u::::1555073229::168858B59F321107B0057756E417110B167C1DF4::Neal H. Walfield <neal@sequoia-pgp.org>::::::::::0:
sub:u:2048:1:7223B56678E02528:1428399766:1618145244:::::s::::::23:
fpr:::::::::C03FA6411B03AE12576461187223B56678E02528:
sub:u:2048:1:C2B819056C652598:1428399800:1618145277:::::e::::::23:
fpr:::::::::50E6D924308DBF223CFB510AC2B819056C652598:
sub:u:2048:1:A3506AFB820ABD08:1428399828:1618145266:::::a::::::23:
fpr:::::::::2DC50AB55BE2F3B04C2D2CF8A3506AFB820ABD08:
"#;

        let r = list_keys_raw_parse(raw.as_bytes())?;
        let r = list_secret_keys_parse(r)?;

        assert_eq!(r, vec![]);

        Ok(())
    }
}
