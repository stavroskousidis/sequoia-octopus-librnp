use std::{
    collections::{
        HashMap,
        HashSet,
        hash_map::Entry,
    },
    fmt,
    fs,
    fs::File,
    io::Write,
    iter::FromIterator,
    path::PathBuf,
    sync::{
        Arc,
        atomic,
        atomic::AtomicUsize,
        Condvar,
        mpsc,
        Mutex,
        RwLock,
        RwLockReadGuard,
        RwLockWriteGuard,
    },
    thread,
    time::{
        Duration,
        SystemTime,
    },
};

use anyhow::Result;

use sequoia_openpgp as openpgp;
use openpgp::{
    Fingerprint,
    KeyID,
    Cert,
    packet::prelude::*,
    serialize::Serialize,
};

use crate::{
    gpg,
    Keygrip,
    keygrip::keygrip_of,
    parcimonie::Parcimonie,
    policy::OctopusPolicy,
    wot::{WoT, WoTWorkerHandle},
};

/// Controls tracing in this module.
const TRACE: bool = crate::TRACE;

#[derive(Debug)]
struct MapEntry<E: std::fmt::Debug> {
    cert: Arc<RwLock<Cert>>,
    // We cache the fingerprint so that we can figure out what
    // certificate is in here without locking cert.
    fingerprint: Fingerprint,
    extra: E,
}

impl<E: std::fmt::Debug> MapEntry<E> {
    pub fn cert(&self) -> RwLockReadGuard<Cert> {
        self.cert.read().unwrap()
    }

    pub fn cert_mut(&self) -> RwLockWriteGuard<Cert> {
        self.cert.write().unwrap()
    }

    pub fn cert_cell(&self) -> Arc<RwLock<Cert>> {
        Arc::clone(&self.cert)
    }

    fn fingerprint(&self) -> &Fingerprint {
        &self.fingerprint
    }

    fn extra(&self) -> &E {
        &self.extra
    }
}

impl MapEntry<()> {
    // This function takes a reader lock on cert.
    fn new(cert: &Arc<RwLock<Cert>>) -> Self {
        MapEntry {
            cert: Arc::clone(cert),
            fingerprint: cert.read().unwrap().fingerprint(),
            extra: (),
        }
    }
}

impl MapEntry<Fingerprint> {
    // referent is the key (not the certificate!) that refers to this
    // entry.
    //
    // This function takes a reader lock on cert.
    fn new2(cert: &Arc<RwLock<Cert>>, referent: Fingerprint) -> Self {
        MapEntry {
            cert: Arc::clone(cert),
            fingerprint: cert.read().unwrap().fingerprint(),
            extra: referent,
        }
    }
}

pub struct KeystoreData {
    gpg_ctx: Option<gpg::Ctx>,

    // The bool indicates whether the key is considered external.
    by_primary_fp: HashMap<Fingerprint, MapEntry<bool>>,
    by_primary_id: HashMap<KeyID, Vec<MapEntry<()>>>,
    by_primary_grip: HashMap<Keygrip, Vec<MapEntry<()>>>,
    by_subkey_fp: HashMap<Fingerprint, Vec<MapEntry<()>>>,
    by_subkey_id: HashMap<KeyID, Vec<MapEntry<()>>>,
    // It is possible for there to be a certificate that has multiple
    // subkeys with the same grip!  If we remove one subkey, then the
    // grip should not be removed.  To distinguish this case, we also
    // track the subkey.
    by_subkey_grip: HashMap<Keygrip, Vec<MapEntry<Fingerprint>>>,

    // Keys that are managed by the agent.
    keys_on_agent: HashSet<Fingerprint>,
    keys_on_agent_last_refresh: SystemTime,
    keys_on_agent_tag: Option<gpg::CacheTag>,

    // The last time that the keystore was *possibly* modified.  Each
    // write attempt is a tick.  Unfortunately, this can also result
    // in false negatives, because Keystore::cert_cell can be used to
    // store a reference.  Right now that function is only used
    // outside of the Keystore to lock and unlock secret key material.
    // But, since this is just a safety measure, this is good enough.
    last_update: AtomicUsize,

    // The location of the keystore.  If set, the keystore is
    // periodically flushed to disk in the background.
    directory: Option<PathBuf>,
    flush_thread: Option<thread::JoinHandle<()>>,

    background_thread: Option<thread::JoinHandle<()>>,
}

impl Default for KeystoreData {
    fn default() -> Self {
        Self {
            gpg_ctx: None,

            by_primary_fp: Default::default(),
            by_primary_id: Default::default(),
            by_primary_grip: Default::default(),
            by_subkey_fp: Default::default(),
            by_subkey_id: Default::default(),
            by_subkey_grip: Default::default(),

            keys_on_agent: Default::default(),
            keys_on_agent_last_refresh: std::time::UNIX_EPOCH,
            keys_on_agent_tag: None,

            last_update: AtomicUsize::new(0),

            directory: None,
            flush_thread: None,

            background_thread: None,
        }
    }
}

pub struct Keystore {
    data: Arc<RwLock<KeystoreData>>,
    parcimonie: Option<Parcimonie>,

    /// Write-side of a channel to send commands to the background thread.
    background_sender:
    Option<Arc<Mutex<mpsc::Sender<BackgroundCommand>>>>,

    // Whether the keystore is in the process of loading a keyring.
    // See Keystore::load_keyring_in_background and
    // Keystore::block_on_load.
    background_busy: Arc<(Mutex<usize>, Condvar)>,

    /// Controls the WoT worker thread.
    wot_handle: Option<WoTWorkerHandle>,
}

enum BackgroundCommand {
    /// Update the GnuPG keyring.
    LoadGnuPGKeyring,

    /// Import a keyring in the background.
    LoadKeyring {
        keyring: Vec<u8>,
        import_secret_keys: bool,
    },
}

impl Default for Keystore {
    fn default() -> Self {
        Self {
            data: Arc::new(RwLock::new(Default::default())),
            parcimonie: None,

            background_sender: None,
            background_busy: Arc::new((Mutex::new(0), Condvar::new())),
            wot_handle: None,
        }
    }
}

impl fmt::Debug for Keystore {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Keystore")
            .field("parcimonie", &self.parcimonie.is_some())
            .field("data", &self.data)
            .finish()
    }
}

impl Keystore {
    // Starts a parcimonie instance to keep this keystore up to date.
    //
    // If there is already parcimonie instance running, this does
    // nothing.
    pub fn start_parcimonie(&mut self, policy: OctopusPolicy)
                            -> Result<()>
    {
        if self.parcimonie.is_none() {
            self.parcimonie = Some(Parcimonie::new(policy, self)?);
        }
        Ok(())
    }

    pub fn create_ref(&self) -> Arc<RwLock<KeystoreData>> {
        Arc::clone(&self.data)
    }

    pub fn read(&self) -> RwLockReadGuard<KeystoreData> {
        self.data.read().unwrap()
    }

    pub fn write(&self) -> RwLockWriteGuard<KeystoreData> {
        self.data.write().unwrap()
    }

    /// Returns whether the key appears to be on the gpg agent.
    ///
    /// This is at most a few seconds out of date.
    pub fn key_on_agent(&self, key: &Fingerprint) -> bool {
        let (key_on_agent, need_refresh)
            = self.data.read().unwrap().key_on_agent(key);
        if need_refresh {
            self.data.write().unwrap().key_on_agent_hard(key)
        } else {
            key_on_agent
        }
    }

    // The location of the keystore (where the pubring.gpg and
    // secring.gpg files are).  If set, the keystore is periodically
    // flushed to disk in the background.
    pub fn set_directory(&mut self, directory: PathBuf) -> Result<()> {
        let mut ks = self.data.write().unwrap();

        ks.directory = Some(directory);

        if ks.flush_thread.is_none() {
            // Start a thread to periodically flush everything to
            // disk.
            let ks_ref = self.create_ref();
            ks.flush_thread
                = Some(thread::Builder::new()
                       .name("sq flusher".to_string())
                       .spawn(move || {
                    KeystoreData::flush_thread(ks_ref);
                })?);
        }
        Ok(())
    }

    // Start the thread that checks for updates to the gpg key store.
    //
    // Returns whether or not a thread was started.  That is, if the
    // thread was already running, this returns false.
    fn background_threads_start(&mut self,
                        policy: Arc<RwLock<OctopusPolicy>>)
        -> openpgp::Result<bool>
    {
        if self.background_sender.is_some() {
            // Already started.
            return Ok(false);
        }

        let mut ks = self.data.write().unwrap();
        if self.background_sender.is_some() {
            // Someone else already started the thread while we were
            // blocked on self.data.
            assert!(ks.background_thread.is_some());
            return Ok(false);
        }
        assert!(ks.background_thread.is_none());
        assert!(self.background_sender.is_none());
        assert!(self.wot_handle.is_none());

        let wot_handle =
            WoT::background_thread_start(self.create_ref(), policy.clone())?;

        let ks_ref = self.create_ref();
        let (sender, receiver) = mpsc::channel();

        let background_busy = Arc::clone(&self.background_busy);

        // Cause block_on_load to wait until the gpg keyring is
        // loaded.
        let mut background_busy_ = self.background_busy.0.lock().unwrap();
        assert_eq!(*background_busy_, 0);
        *background_busy_ += 1;
        drop(background_busy_);

        let wh = wot_handle.clone();
        ks.background_thread
            = Some(thread::Builder::new().name("sq loader".to_string())
                   .spawn(move || KeystoreData::background_thread(
                       ks_ref, wh,receiver, background_busy))?);

        self.background_sender = Some(Arc::new(Mutex::new(sender)));
        self.wot_handle = Some(wot_handle);

        Ok(true)
    }

    /// Load the gpg keyring into the keystore.
    ///
    /// Parse and load a keyring.  If this encounters some corruption
    /// in the keyring and is able to recover, it does not report an
    /// error.
    ///
    /// This also starts a thread to monitor the gpg store.  This
    /// imports updates from the gpg keyring (XXX: but not removals!).
    pub fn load_gpg_keyring_in_background(&mut self,
                            policy: Arc<RwLock<OctopusPolicy>>)
        -> openpgp::Result<()>
    {
        rnp_function!(Keystore::load_gpg_keyring, TRACE);

        if !self.background_threads_start(policy)? {
            // If we just started the thread, then it will read the
            // gpg keyring on its own.  Otherwise, signal that it
            // should reread it now.
            self.background_sender.as_ref().expect("started thread")
                .lock().unwrap()
                .send(BackgroundCommand::LoadGnuPGKeyring)?;
        }
        Ok(())
    }

    /// Loads the specified keyring in the background.
    ///
    /// If import_secret_keys is true, then it also imports any secret
    /// key material.  Otherwise, secret key material is stripped.
    pub fn load_keyring_in_background(&mut self, keyring: Vec<u8>,
                                      import_secret_keys: bool,
                                      policy: Arc<RwLock<OctopusPolicy>>)
        -> openpgp::Result<()>
    {
        rnp_function!(Keystore::load_keyring_in_background, TRACE);

        if let Err(err) = self.background_threads_start(policy) {
            warn!("Failed to start gpg thread: {}", err);
            KeystoreData::load_keyring(
                &mut self.data, &keyring, import_secret_keys, false)?;
        } else {
            *self.background_busy.0.lock().unwrap() += 1;

            self.background_sender.as_ref().expect("started thread")
                .lock().unwrap()
                .send(BackgroundCommand::LoadKeyring {
                    keyring,
                    import_secret_keys,
                })?;
        }

        Ok(())
    }

    /// Updates the Web-of-Trust information in the background.
    pub fn update_wot_in_background(&mut self,
                                    policy: Arc<RwLock<OctopusPolicy>>)
                                    -> openpgp::Result<()> {
        rnp_function!(Keystore::update_wot_in_background, super::TRACE);

        self.background_threads_start(policy)?;
        self.wot_handle.as_ref().expect("started thread").notify();

        Ok(())
    }

    /// Blocks the current thread until any keyrings that are being
    /// loaded in the background have been loaded.
    ///
    /// This includes the initial load of the gpg keyring, and any
    /// keyrings added via `Keystore::load_keyring_in_background`.
    ///
    /// Returns whether we blocked.
    pub fn block_on_load(&mut self) -> openpgp::Result<bool> {
        // We do *not* start the gpg thread if it is not already
        // running.  This must only be done by rnp_load_keys.
        rnp_function!(Keystore::block_on_load, TRACE);

        let background_busy = self.background_busy.0.lock().unwrap();
        if *background_busy == 0 {
            return Ok(false);
        }

        // We're going to block TB.  We can't convince TB to show a
        // progress bar, but we can show one ourselves.  At least on
        // non-Windows systems.
        let mut child = None;
        if ! cfg!(windows) {
            use std::process::Command;
            use std::process::Stdio;

            // zenity requires something on stdin.
            let mut command = Command::new("zenity");
            command
                .stdin(Stdio::piped())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .arg("--text=Loading keys, please wait.")
                .arg("--progress")
                .arg("--pulsate")
                .arg("--no-cancel");
            t!("Running command: {:?}", command);

            match command.spawn() {
                Ok(c) => child = Some(c),
                Err(err) => t!("Running zenity: {}", err),
            };

            // Try kdialog.
            if child.is_none() {
                let mut command = Command::new("kdialog");
                command
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .arg("--passivepopup")
                    .arg("Loading OpenPGP keys, please wait")
                    .arg("10s");
                t!("Running command: {:?}", command);
                match command.spawn() {
                    Ok(c) => child = Some(c),
                    Err(err) => t!("Running kdialog: {}", err),
                };
            }
        };

        assert!(self.background_sender.is_some());

        drop(self.background_busy.1
             .wait_while(background_busy, |background_busy| *background_busy > 0)
             .unwrap());

        if let Some(mut child) = child {
            if let Err(err) = child.kill() {
                t!("Killing zenity: {}", err);
            }
        }

        Ok(true)
    }
}

const VEC_MAP_ENTRY_EMPTY: Vec<MapEntry<()>> = Vec::new();
const VEC_MAP_ENTRY_EMPTY_REF: &Vec<MapEntry<()>> = &VEC_MAP_ENTRY_EMPTY;

const VEC_MAP_ENTRY_FPR_EMPTY: Vec<MapEntry<Fingerprint>> = Vec::new();
const VEC_MAP_ENTRY_FPR_EMPTY_REF: &Vec<MapEntry<Fingerprint>>
    = &VEC_MAP_ENTRY_FPR_EMPTY;

impl fmt::Debug for KeystoreData {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "KeystoreData {{")?;

        writeln!(f, "  by_primary_fp {{")?;
        for (k, e) in self.by_primary_fp.iter() {
            writeln!(f, "    {} => {}", k, e.extra())?;
        }
        writeln!(f, "  }}")?;
        writeln!(f, "  by_primary_id {{")?;
        for (k, v) in self.by_primary_id.iter() {
            writeln!(f, "    {} =>\n      {}",
                     k,
                     v.iter()
                        .map(|e| e.fingerprint().to_string())
                        .collect::<Vec<String>>().join(",\n      "))?;
        }
        writeln!(f, "  }}")?;
        writeln!(f, "  by_primary_grip {{")?;
        for (g, v) in self.by_primary_grip.iter() {
            writeln!(f, "    {} =>\n      {}",
                     g,
                     v.iter()
                        .map(|e| {
                            format!("{}",
                                    e.fingerprint().to_string())
                        })
                        .collect::<Vec<String>>().join(",\n      "))?;
        }
        writeln!(f, "  }}")?;

        writeln!(f, "  by_subkey_fp {{")?;
        for (k, v) in self.by_subkey_fp.iter() {
            writeln!(f, "    {} =>\n      {}",
                     k,
                     v.iter()
                        .map(|e| e.fingerprint().to_string())
                        .collect::<Vec<String>>().join(",\n      "))?;
        }
        writeln!(f, "  }}")?;
        writeln!(f, "  by_subkey_id {{")?;
        for (k, v) in self.by_subkey_id.iter() {
            writeln!(f, "    {} =>\n      {}",
                     k,
                     v.iter()
                        .map(|e| e.fingerprint().to_string())
                        .collect::<Vec<String>>().join(",\n      "))?;
        }
        writeln!(f, "  }}")?;
        writeln!(f, "  by_subkey_grip {{")?;
        for (g, v) in self.by_subkey_grip.iter() {
            writeln!(f, "    {} =>\n      {}",
                     g,
                     v.iter()
                        .map(|e| {
                            format!("{} (via {})",
                                    e.fingerprint().to_string(),
                                    e.extra)
                        })
                        .collect::<Vec<String>>().join(",\n      "))?;
        }
        writeln!(f, "  }}")?;

        writeln!(f, "}}")?;
        Ok(())
    }
}

impl KeystoreData {
    /// Returns the time (in ticks) where the keystore could have
    /// possibly been modified.
    pub fn last_update(&self) -> usize {
        self.last_update.load(atomic::Ordering::Relaxed)
    }

    /// Marks the keystore as updated.
    pub fn mark_updated(&self) {
        self.last_update.fetch_add(1, atomic::Ordering::Relaxed);
    }

    // Periodically flush the key store to disk.
    fn flush_thread(ks: Arc<RwLock<Self>>) {
        rnp_function!(KeystoreData::flush_thread, TRACE);
        let mut last_flush = 0;

        loop {
            // About once an hour (but not quite to avoid possible
            // resonance).
            thread::sleep(Duration::new(59 * 60, 0));

            let ks = ks.read().unwrap();

            let last_update = ks.last_update();
            if last_flush == last_update {
                t!("Not flushing keystore to disk: no changes");
                continue;
            } else {
                last_flush = last_update
            }

            if let Some(ref dir) = ks.directory {
                let pubring_tmp = dir.join("pubring.gpg~");
                let secring_tmp = dir.join("secring.gpg~");

                t!("Writing keystore to {:?} and {:?}",
                   pubring_tmp, secring_tmp);

                let mut pubring_fd = match File::create(&pubring_tmp) {
                    Ok(fd) => fd,
                    Err(err) => {
                        t!("Creating {:?}: {}", pubring_tmp, err);
                        continue;
                    }
                };
                let mut secring_fd = match File::create(&secring_tmp) {
                    Ok(fd) => fd,
                    Err(err) => {
                        t!("Creating {:?}: {}", secring_tmp, err);
                        continue;
                    }
                };

                let mut ok = true;
                let mut pub_count = 0;
                let mut sec_count = 0;
                for cert in ks.to_save() {
                    let r = if cert.is_tsk() {
                        sec_count += 1;
                        cert.as_tsk().serialize(&mut secring_fd)
                    } else {
                        pub_count += 1;
                        cert.serialize(&mut pubring_fd)
                    };

                    if let Err(err) = r {
                        t!("Serializing {} {}: {}",
                           if cert.is_tsk() { "secret key" } else { "certificate" },
                           cert.fingerprint(), err);
                        ok = false;
                        break;
                    }
                }

                if ok && pub_count == 0 {
                    // We didn't write any bytes.  Currently,
                    // Thunderbird will not invoke rnp_load_keys if a
                    // keyring is a zero-sized file.  To avoid that,
                    // i.e. make sure that rnp_load_keys is invoked,
                    // we write a placeholder there.  See the comments
                    // in rnp_ffi_create for details.
                    if let Err(_) =
                        openpgp::Packet::Marker(Default::default())
                        .serialize(&mut pubring_fd)
                    {
                        ok = false;
                    }
                }
                if ok && sec_count == 0 {
                    // Likewise.
                    if let Err(_) =
                        openpgp::Packet::Marker(Default::default())
                        .serialize(&mut secring_fd)
                    {
                        ok = false;
                    }
                }

                if ok {
                    if let Err(err) = pubring_fd.flush() {
                        t!("Failed to flush {:?}: {}", pubring_tmp, err);
                        continue;
                    }
                    drop(pubring_fd);
                    if let Err(err) = secring_fd.flush() {
                        t!("Failed to flush {:?}: {}", secring_tmp, err);
                        continue;
                    }
                    drop(secring_fd);

                    let pubring = dir.join("pubring.gpg");
                    if let Err(err) = fs::rename(&pubring_tmp, &pubring) {
                        warn!("Failed to rename {:?} to {:?}: {}",
                              pubring_tmp, pubring, err);
                    }

                    let secring = dir.join("secring.gpg");
                    if let Err(err) = fs::rename(&secring_tmp, &secring) {
                        warn!("Failed to rename {:?} to {:?}: {}",
                              secring_tmp, secring, err);
                    }

                    t!("Keystore flushed to {:?} and {:?}",
                       pubring, secring);
                }
            }
        }
    }

    fn load_keyring(ks: &Arc<RwLock<KeystoreData>>,
                    keyring: &[u8], import_secret_keys: bool, external: bool)
        -> openpgp::Result<()>
    {
        rnp_function!(KeystoreData::load_keyring, TRACE);

        // Parse the keyring without the lock.
        use sequoia_openpgp_mt::keyring;
        let certs = match keyring::parse(std::io::Cursor::new(keyring)) {
            Ok(certs) => certs,
            Err(err) => {
                t!("Parsing keyring: {}", err);
                return Err(err);
            }
        };

        // And now take the lock to insert the certificates.
        let mut inserted = 0;
        let mut errors = 0;

        let mut ks = ks.write().unwrap();
        for cert in certs {
            match cert {
                Ok(mut c) => {
                    if ! import_secret_keys {
                        c = c.strip_secret_key_material();
                    }
                    ks.insert_(c, external);
                    inserted += 1;
                }
                Err(e) => {
                    // We definitely don't want to error out when
                    // importing stuff from gpg.  So, warn, but don't
                    // stop.
                    warn!("sequoia-octopus: Error parsing cert: {}", e);
                    errors += 1;
                },
            }
        }
        drop(ks);

        t!("Successfully added {} certificates, {} errors",
           inserted, errors);

        Ok(())
    }

    /// The background worker thread.
    ///
    /// Monitor certificate stores (like the GnuPG keyring) for
    /// updates, reads certificates in the background, and updates the
    /// Web-of-Trust calculations.
    fn background_thread(ks: Arc<RwLock<Self>>,
                         wot_handle: WoTWorkerHandle,
                         receiver: mpsc::Receiver<BackgroundCommand>,
                         background_busy: Arc<(Mutex<usize>, Condvar)>) {
        rnp_function!(KeystoreData::background_thread, TRACE);

        struct GpgState {
            last_check: std::time::SystemTime,
            first_time: bool,
            check_now: bool,
            keyring_tag: Option<gpg::CacheTag>,
            ctx: Option<gpg::Ctx>,
        }

        let mut gpg = GpgState {
            last_check: std::time::UNIX_EPOCH,
            first_time: true,
            check_now: true,
            keyring_tag: None,
            ctx: None,
        };
        loop {
            // About once an hour (but not quite to avoid possible
            // resonance).  The first time through, we don't import
            // the keyring.  We did that from the main thread, because
            // reasons.
            let timeout = if gpg.check_now {
                Duration::new(0, 0)
            } else {
                let threshold = Duration::new(61 * 60, 0);
                let elapsed = SystemTime::now().duration_since(gpg.last_check)
                    .unwrap_or_else(|_| {
                        // Clock skew?  Who knows.  Just wait a bit
                        // and try again.
                        gpg.last_check = SystemTime::now();
                        Duration::new(0, 0)
                    });
                if elapsed > threshold {
                    Duration::new(0, 0)
                } else {
                    threshold - elapsed
                }
            };

            if timeout > Duration::new(0, 0) {
                t!("Waiting (at most) {:?}", timeout);
            }

            let r = receiver.recv_timeout(timeout);
            match r {
                Ok(BackgroundCommand::LoadKeyring {
                    keyring,
                    import_secret_keys,
                }) => {
                    if let Err(err) = KeystoreData::load_keyring(
                        &ks, &keyring, import_secret_keys, false)
                    {
                        warn!("Loading keyring: {}", err);
                    }

                    let mut background_busy_ = background_busy.0.lock().unwrap();
                    assert!(*background_busy_ > 0);
                    *background_busy_ -= 1;
                    if *background_busy_ == 0 {
                        background_busy.1.notify_all();
                    }
                    drop(background_busy_);

                    // Trigger a WoT update.
                    wot_handle.notify();
                    continue;
                }

                Ok(BackgroundCommand::LoadGnuPGKeyring) => {
                    gpg.check_now = true;
                    // We loop to drain the message queue.
                    continue;
                },
                // Poll now.
                Err(mpsc::RecvTimeoutError::Timeout) => (),
                // ks was destroyed.
                Err(_) => {
                    t!("Keystore disconnected.  Time to shutdown.");
                    return;
                }
            }

            gpg.check_now = false;

            let now = SystemTime::now();
            let elapsed = now.duration_since(gpg.last_check);
            match elapsed {
                Err(err) => {
                    t!("Error computing time since last update: {}", err);
                    continue;
                },
                Ok(elapsed) => {
                    if elapsed < Duration::new(90, 0) {
                        t!("Throttling GnuPG certstore updates.");
                        continue;
                    }
                }
            }

            if gpg.ctx.is_none() {
                // See if the user install gpg in the meantime.
                gpg.ctx = gpg::Ctx::new().ok();
            }
            if let Some(gpg_ctx) = gpg.ctx.as_ref() {
                t!("Checking for gpg updates (last check was: {:?} ago)...",
                   elapsed);

                // Import the gpg keyring.
                match gpg::export(
                    gpg_ctx, None, gpg.keyring_tag.as_ref())
                {
                    Ok((keyring, keyring_tag_tmp)) => {
                        t!("Got {} bytes", keyring.len());
                        gpg.keyring_tag = Some(keyring_tag_tmp);


                        if let Err(err) = KeystoreData::load_keyring(
                            &ks, &keyring, false, true)
                        {
                            warn!("Loading keyring: {}", err);
                        }
                    }
                    Err(err) => {
                        t!("Exporting gpg keyring: {}", err);
                    }
                }
            }

            if gpg.first_time {
                gpg.first_time = false;

                let mut background_busy_ = background_busy.0.lock().unwrap();
                assert!(*background_busy_ > 0);
                *background_busy_ -= 1;
                if *background_busy_ == 0 {
                    background_busy.1.notify_all();
                }
                drop(background_busy_);
            }

            // Trigger a WoT update.
            wot_handle.notify();

            gpg.last_check = SystemTime::now();
        }
    }

    /// Returns a reference to a gpg::Ctx.
    fn gpg_ctx(&mut self) -> Option<&gpg::Ctx> {
        rnp_function!(KeystoreData::gpg_ctx, TRACE);

        if self.gpg_ctx.is_none() {
            match gpg::Ctx::new() {
                Ok(ctx) => self.gpg_ctx = Some(ctx),
                Err(err) => t!("Creating a gpg context: {}", err),
            }
        }
        self.gpg_ctx.as_ref()
    }

    /// Returns whether the specified key appears to be on the gpg
    /// agent.
    ///
    /// This always tries to refresh the cache first.
    pub fn key_on_agent_hard(&mut self, key: &Fingerprint) -> bool {
        rnp_function!(KeystoreData::key_on_agent_hard, TRACE);

        self.gpg_ctx();
        if let Some(ctx) = self.gpg_ctx.as_ref() {
            match gpg::list_secret_keys(ctx, None, self.keys_on_agent_tag.as_ref())
            {
                Err(err) => {
                    match err.downcast::<gpg::Error>() {
                        // Unchanged.  Short-circuit.
                        Ok(gpg::Error::Unchanged(tag)) => {
                            self.keys_on_agent_tag = Some(tag);
                        },
                        Err(e) => t!("List gpg secret keys: {}", e),
                    }
                }
                Ok((secret_keys, hash)) => {
                    self.keys_on_agent_tag = Some(hash);
                    self.keys_on_agent = HashSet::from_iter(
                        secret_keys.into_iter().map(|(_primary, key)| key));
                }
            }
        }
        // We even set this on error, as we want to throttle them too.
        self.keys_on_agent_last_refresh = SystemTime::now();

        self.keys_on_agent.get(key).is_some()
    }

    /// Returns whether the key appears to be on the gpg agent.
    ///
    /// These values are cached.
    ///
    /// The first return value is whether, according to the cache, the
    /// key is on the agent.
    ///
    /// The second return value is whether the cache is old and should
    /// be refreshed.
    ///
    /// If the cache should be refreshed, you should follow up with a
    /// call to `key_on_agent_hard`.
    ///
    /// The calls are split so that this function doesn't need a write
    /// lock.
    pub fn key_on_agent(&self, key: &Fingerprint) -> (bool, bool) {
        rnp_function!(KeystoreData::key_on_agent, TRACE);

        let now = SystemTime::now();
        let elapsed = now.duration_since(self.keys_on_agent_last_refresh);
        let expired = match elapsed {
            // If the cache is more than 1 minute out of date,
            // refresh it.
            Ok(elapsed) => {
                if elapsed > Duration::new(60, 0) {
                    true
                } else {
                    false
                }
            }
            Err(_err) => {
                true
            }
        };

        (self.keys_on_agent.get(key).is_some(), expired)
    }

    /// Returns the number of certificates in the key store.
    pub fn count(&self) -> usize {
        self.by_primary_fp.len()
    }

    /// Returns an iterator over the fingerprint of each certificates
    /// in the store.
    pub fn fingerprints<'a>(&'a self) -> impl Iterator<Item=Fingerprint> + 'a {
        self.by_primary_fp.keys().map(|fpr| fpr.clone())
    }

    /// Returns an iterator over the keyid of each certificate in the
    /// store.
    pub fn keyids<'a>(&'a self) -> impl Iterator<Item=KeyID> + 'a {
        self.by_primary_id.keys().map(|id| id.clone())
    }

    /// Returns an iterator over the key grips of the primary key of
    /// each certificate in the store.
    pub fn keygrips<'a>(&'a self) -> impl Iterator<Item=Keygrip> + 'a {
        self.by_primary_grip.keys().map(|grip| grip.clone())
    }

    /// Returns a clone of the specified certificate's RefCell.
    ///
    /// fp is the certificate's fingerprint.
    pub fn cert_cell_by_primary_fp(&self, fp: &Fingerprint)
                                   -> Option<Arc<RwLock<Cert>>>
    {
        self.by_primary_fp.get(fp).map(|e| e.cert_cell())
    }

    /// Returns a clone of the specified certificates' storage cells.
    ///
    /// `fp` is a certificate or subkey fingerprint.
    pub fn cert_cell_by_fp<'a>(&'a self, fp: &Fingerprint)
                               -> impl Iterator<Item = Arc<RwLock<Cert>>> + 'a
    {
        std::iter::once(fp.clone())
            .chain(self.by_subkey_fp.get(fp)
                   .unwrap_or(VEC_MAP_ENTRY_EMPTY_REF)
                   .iter()
                   .map(|e| e.fingerprint().clone()))
            .filter_map(|fp| self.by_primary_fp.get(&fp).map(|e| e.cert_cell()))
    }

    /// Returns a reference to the cert with the given fingerprint, if
    /// any.
    pub fn by_primary_fp(&self, fp: &Fingerprint)
        -> Option<RwLockReadGuard<Cert>>
    {
        self.by_primary_fp.get(fp).map(|e| e.cert())
    }

    /// Returns a reference to each cert with the given keyid.
    pub fn by_primary_id(&self, id: &KeyID)
        -> impl Iterator<Item=RwLockReadGuard<Cert>>
    {
        self.by_primary_id.get(id)
            .unwrap_or(VEC_MAP_ENTRY_EMPTY_REF)
            .iter()
            .map(|e| e.cert())
    }

    /// Returns a reference to each cert for which the primary key has
    /// the given keygrip.
    pub fn by_primary_grip(&self, grip: &Keygrip)
        -> impl Iterator<Item=RwLockReadGuard<Cert>>
    {
        self.by_primary_grip.get(grip)
            .unwrap_or(VEC_MAP_ENTRY_EMPTY_REF)
            .iter()
            .map(|e| e.cert())
    }

    /// Returns a reference to each cert containing a subkey with the
    /// given fingerprint.
    pub fn by_subkey_fp(&self, fp: &Fingerprint)
        -> impl Iterator<Item=RwLockReadGuard<Cert>>
    {
        self.by_subkey_fp.get(fp)
            .unwrap_or(VEC_MAP_ENTRY_EMPTY_REF)
            .iter()
            .map(|e| e.cert())
    }

    /// Returns a reference to each cert containing a subkey with the
    /// given keyid, if any.
    pub fn by_subkey_id(&self, id: &KeyID)
        -> impl Iterator<Item=RwLockReadGuard<Cert>>
    {
        self.by_subkey_id.get(id)
            .unwrap_or(VEC_MAP_ENTRY_EMPTY_REF)
            .iter()
            .map(|e| e.cert())
    }

    /// Returns a reference to each cert containing a primary key or
    /// subkey with the given fingerprint.
    ///
    /// If a certificate contains a primary key and a subkey with the
    /// same fingerprint, that certificate is returned twice.
    pub fn by_fp(&self, fp: &Fingerprint)
        -> impl Iterator<Item=RwLockReadGuard<Cert>>
    {
        self.by_primary_fp(fp)
            .into_iter()
            .chain(self.by_subkey_fp(fp))
    }


    /// Returns a reference to each cert containing a subkey with the
    /// given keygrip, if any.
    ///
    /// If a certificate contains multiple subkeys with the same
    /// keygrip, then the certificate is returned multiple times, one
    /// for each such subkey.
    pub fn by_subkey_grip(&self, grip: &Keygrip)
        -> impl Iterator<Item=RwLockReadGuard<Cert>>
    {
        self.by_subkey_grip.get(grip)
            .unwrap_or(VEC_MAP_ENTRY_FPR_EMPTY_REF)
            .iter()
            .map(|e| e.cert())
    }

    /// Returns an iterator over all the certs in the key store.
    pub fn iter(&self) -> impl Iterator<Item = RwLockReadGuard<Cert>> {
        self.by_primary_fp.values().map(|e| e.cert())
    }

    /// Returns an iterator over the certs in the key store, which are
    /// not marked as external.
    pub fn to_save(&self) -> impl Iterator<Item = RwLockReadGuard<Cert>> {
        self.by_primary_fp.values().filter_map(|e| {
            if *e.extra() {
                None
            } else {
                Some(e.cert())
            }
        })
    }

    /// Inserts a cert.
    ///
    /// This function prefers secret key material in the cert that is
    /// being merged.
    fn insert_(&mut self, cert: Cert, is_external: bool) {
        rnp_function!(Keystore::insert_, TRACE);

        let fp = cert.fingerprint();
        let id = KeyID::from(&fp);
        let grip = keygrip_of(cert.primary_key().key().mpis()).ok();

        t!("Inserting {}, {:?} (external: {})",
           fp, cert.userids().nth(0).map(|ua| ua.userid()), is_external);

        let cert_cell: Arc<RwLock<Cert>>;

        let is_update = match self.by_primary_fp.entry(fp.clone()) {
            Entry::Occupied(mut oe) => {
                t!("Already exists in keystore, merging.");

                let e = oe.get_mut();
                cert_cell = Arc::clone(&e.cert);

                let mut cert_ref = cert_cell.write().unwrap();

                if cert_ref.as_tsk() == cert.as_tsk() {
                    // They are identical.  There is nothing to do.
                    t!("Update doesn't change certificate.  Short-circuiting.");
                    return;
                }

                // Merge.  We want to prefer secret keys in `cert`
                // over the one in the store.  Cert::insert_packets
                // replaces existing key material.  Hence, we insert
                // only those packets that are either secret keys or
                // public ones that are not in `cert_ref`.
                let known_keys: HashSet<Fingerprint> =
                    cert_ref.keys().map(|k| k.key().fingerprint()).collect();
                let cert_update = cert_ref.clone()
                    .insert_packets(cert.into_tsk().into_packets()
                                    .filter(|p| match p {
                        // Insert only unknown public keys.
                        Packet::PublicKey(k) =>
                            ! known_keys.contains(&k.fingerprint()),
                        Packet::PublicSubkey(k) =>
                            ! known_keys.contains(&k.fingerprint()),

                        // Insert everything else, including secret keys.
                        _ => true,
                    }))
                    .expect("does not fail if the primary keys are equal").0;

                if cert_ref.as_tsk() == cert_update.as_tsk() {
                    // They are identical.  There is nothing to do.
                    t!("Update doesn't add anything new.  Short-circuiting.");
                    return;
                }

                *cert_ref = cert_update;

                e.extra = e.extra && is_external;

                true
            }
            Entry::Vacant(ve) => {
                t!("New certificate, adding.");

                cert_cell = Arc::new(RwLock::new(cert));
                ve.insert(MapEntry {
                    cert: Arc::clone(&cert_cell),
                    fingerprint: fp.clone(),
                    extra: is_external,
                });

                false
            }
        };

        self.mark_updated();

        // If this is an update, then the primary key id and primary
        // key grip mapping exist and are correct.
        if ! is_update {
            self.by_primary_id
                .entry(id)
                .and_modify(|v| v.push(MapEntry::new(&cert_cell)))
                .or_insert(vec![ MapEntry::new(&cert_cell) ]);

            if let Some(g) = grip {
                self.by_primary_grip
                    .entry(g)
                    .and_modify(|v| v.push(MapEntry::new(&cert_cell)))
                    .or_insert(vec![ MapEntry::new(&cert_cell) ]);
            }
        }

        // Add subkey indices.  If this is an update, indices may
        // already exist.  Don't duplicate them.
        {
            let cert_locked = cert_cell.read().unwrap();
            let cert_fp = cert_locked.fingerprint();

            for sk in cert_locked.keys().subkeys() {
                macro_rules! add {
                    ($v:expr, $id:expr) => ({
                        let present = $v.iter()
                            .position(|e| {
                                e.extra == $id
                                    && e.fingerprint() == &fp
                            })
                            .is_some();
                        if present {
                            t!("Sub-x mapping already present");
                        } else {
                            t!("Sub-x mapping not yet present");
                        }

                        if is_update && ! present {
                            $v.push(MapEntry {
                                cert: Arc::clone(&cert_cell),
                                fingerprint: cert_fp.clone(),
                                extra: $id,
                            });
                        } else if ! is_update {
                            assert!(! present);
                            $v.push(MapEntry {
                                cert: Arc::clone(&cert_cell),
                                fingerprint: cert_fp.clone(),
                                extra: $id,
                            });
                        }
                    });
                }

                t!("Adding subkey fingerprint mapping for {}", sk.key().fingerprint());
                self.by_subkey_fp.entry(sk.key().fingerprint())
                    .and_modify(|v| add!(v, ()))
                    .or_insert(vec![ MapEntry::new(&cert_cell) ]);

                t!("Adding subkey keyid mapping for {}", sk.key().keyid());
                self.by_subkey_id.entry(sk.key().keyid())
                    .and_modify(|v| add!(v, ()))
                    .or_insert(vec![ MapEntry::new(&cert_cell) ]);

                if let Ok(g) = keygrip_of(sk.key().mpis()) {
                    t!("Adding subkey keygrip mapping for {}", g);
                    self.by_subkey_grip.entry(g)
                        .and_modify(|v| add!(v, sk.key().fingerprint()))
                        .or_insert(vec![ MapEntry::new2(&cert_cell, sk.key().fingerprint()) ]);
                }
            }
        }

        t!("Done.");
    }

    /// Inserts a cert.
    ///
    /// The certificate is inserted as-is; secret key material is not
    /// stripped.
    pub fn insert(&mut self, cert: Cert) {
        self.insert_(cert, false)
    }

    /// Inserts a cert, which comes from an external source.
    pub fn insert_external(&mut self, cert: Cert) {
        self.insert_(cert, true)
    }

    /// Removes the subkey or certificate with fingerprint `fp`.
    ///
    /// Returns true if at least one key/cert has been removed.
    pub fn remove_all(&mut self, fp: &Fingerprint) -> bool {
        let mut removed_one = false;

        macro_rules! remove {
            ($fp:expr, $e:expr) => ({
                let fp: &Fingerprint = $fp;
                let e: Entry<_, Vec<MapEntry<_>>> = $e;

                match e {
                    Entry::Occupied(mut oe) => {
                        if let Some(i) = oe.get_mut()
                            .iter().position(|e| e.fingerprint() == fp)
                        {
                            if oe.get().len() == 1 {
                                assert_eq!(i, 0);
                                oe.remove_entry();
                            } else {
                                oe.get_mut().remove(i);
                            }
                        } else {
                            unreachable!("entry not present");
                        }
                    }
                    Entry::Vacant(_) => unreachable!("entry not present"),
                }
            });
        }

        // First, remove the cert with that fingerprint.
        if let Some(e) = self.by_primary_fp.remove(fp) {
            removed_one = true;

            // Remove other primary key indices.
            remove!(fp, self.by_primary_id.entry(KeyID::from(fp)));
            if let Ok(g) = keygrip_of(e.cert().primary_key().key().mpis()) {
                remove!(fp, self.by_primary_grip.entry(g));
            }

            // And remove any subkey indices.
            for sk in e.cert().keys().subkeys() {
                remove!(fp, self.by_subkey_fp.entry(sk.key().fingerprint()));
                remove!(fp, self.by_subkey_id.entry(sk.key().keyid()));
                if let Ok(g) = keygrip_of(sk.key().mpis()) {
                    remove!(fp, self.by_subkey_grip.entry(g));
                }
            }
        }

        // Remove all subkeys with that fingerprint.
        if let Some(subkeys) = self.by_subkey_fp.remove(fp) {
            for e in subkeys.into_iter() {
                let mut cert = e.cert_mut();
                let cert_fp = cert.fingerprint();

                // Strip the subkey.
                let mut had_one = false;
                *cert = cert.clone().retain_subkeys(|ska| {
                    if ska.key().fingerprint() == *fp {
                        had_one = true;
                        removed_one = true;

                        remove!(&cert_fp, self.by_subkey_id.entry(ska.key().keyid()));
                        if let Ok(g) = keygrip_of(ska.key().mpis()) {
                            remove!(&cert_fp, self.by_subkey_grip.entry(g));
                        }

                        false
                    } else {
                        true
                    }
                });

                assert!(had_one);
            }
        }

        if removed_one {
            self.mark_updated();
        }

        removed_one
    }

    /// Removes secret key material associated with `fp`.
    ///
    /// Returns true if any secret key material has been removed.
    pub fn remove_secret_key_material(&mut self, fp: &Fingerprint) -> bool {
        let mut removed_one = false;

        // First, remove the cert with that fingerprint.
        if let Some(e) = self.by_primary_fp.get_mut(fp) {
            let mut cert_ref = e.cert_mut();
            if cert_ref.is_tsk() {
                removed_one = true;
                *cert_ref = cert_ref.clone().strip_secret_key_material();
            }
        }

        // Then, remove secret key material from all subkeys with that
        // fingerprint.
        if let Some(v) = self.by_subkey_fp.get_mut(fp) {
            for e in v {
                // There's no easy way to remove secret key material
                // from an individual subkey.  Instead we convert it
                // to packets, strip the secret key material, and then
                // convert it back.
                let mut cert_ref = e.cert_mut();
                let packets = cert_ref.clone().into_tsk().into_packets()
                    .collect::<Vec<_>>();
                *cert_ref = Cert::from_packets(
                    packets.into_iter()
                        .map(|packet| {
                            match packet {
                                Packet::SecretSubkey(k)
                                    if &k.fingerprint() == fp =>
                                {
                                    removed_one = true;
                                    Packet::PublicSubkey(k.take_secret().0)
                                }
                                packet => packet,
                            }
                        }))
                    .expect("still valid");
            }
        }

        if removed_one {
            self.mark_updated();
        }

        removed_one
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use anyhow::Context;

    use openpgp::policy::StandardPolicy;
    use openpgp::types::SignatureType;
    use openpgp::packet::signature::subpacket::SubpacketTag;

    // Makes sure the maps contain the specified number of keys.
    //
    // If a subkey appears on multiple certificates, it is only
    // counted once.
    fn ks_count<P, S>(ks: &KeystoreData, n_pks: P, n_sks: S, ignore_grips: bool)
        where P: Into<Option<usize>>, S: Into<Option<usize>>
    {
        if let Some(n_pks) = n_pks.into() {
            assert_eq!(ks.by_primary_fp.len(), n_pks,
                       "Expected {} primary fps, got {}\n{:?}",
                       n_pks, ks.by_primary_fp.len(), ks);
            assert_eq!(ks.by_primary_id.len(), n_pks,
                       "Expected {} primary key ids, got {}\n{:?}",
                       n_pks, ks.by_primary_id.len(), ks);
            if ! ignore_grips {
                assert_eq!(ks.by_primary_grip.len(), n_pks,
                           "Expected {} primary grips, got {}\n{:?}",
                           n_pks, ks.by_primary_grip.len(), ks);
            }
        }

        if let Some(n_sks) = n_sks.into() {
            assert_eq!(ks.by_subkey_fp.len(), n_sks,
                       "Expected {} subkey fps, got {}\n{:?}",
                       n_sks, ks.by_subkey_fp.len(), ks);
            assert_eq!(ks.by_subkey_id.len(), n_sks,
                       "Expected {} subkey key ids, got {}\n{:?}",
                       n_sks, ks.by_subkey_id.len(), ks);
            if ! ignore_grips {
                assert_eq!(ks.by_subkey_grip.len(), n_sks,
                           "Expected {} subkey grips, got {}\n{:?}",
                           n_sks, ks.by_subkey_grip.len(), ks);
            }
        }
    }

    // Makes sure the keystore's maps contain the specified keys
    // either as primary keys (the first bool) or as subkeys (the
    // second bool).
    fn ks_contains(ks: &KeystoreData,
                   checks: &[(&Key<key::PublicParts, key::UnspecifiedRole>,
                              bool, bool)])
    {
        for (key, as_primary, as_sub) in checks.iter() {
            let fpr = key.fingerprint();
            match ks.by_primary_fp(&fpr) {
                Some(_) if *as_primary => (),
                Some(_) =>
                    panic!("{} found in by_primary_fp, expected nothing\n{:?}",
                           fpr, ks),
                None if ! *as_primary => (),
                None =>
                    panic!("{} not found in by_primary_fp, but expected\n{:?}",
                           fpr, ks),
            }

            if ks.by_subkey_fp(&fpr)
                .any(|c| c.keys().any(|ka| ka.key().fingerprint() == fpr))
            {
                if ! *as_sub {
                    panic!("{} found in by_subkey_fp, expected nothing\n{:?}",
                           fpr, ks);
                }
            } else {
                if *as_sub {
                    panic!("{} not found in by_subkey_fp, but expected\n{:?}",
                           fpr, ks);
                }
            }

            // By keyid.
            let keyid = key.keyid();
            if ks.by_primary_id(&keyid).any(|c| c.fingerprint() == fpr)
            {
                if ! *as_primary {
                    panic!("{} found in by_primary_id, expected nothing\n{:?}",
                           fpr, ks);
                }
            } else {
                if *as_primary {
                    panic!("{} not found in by_primary_id, but expected\n{:?}",
                           fpr, ks);
                }
            }

            if ks.by_subkey_id(&keyid)
                .any(|c| c.keys().any(|ka| ka.key().keyid() == keyid))
            {
                if ! *as_sub {
                    panic!("{} found in by_subkey_id, expected nothing\n{:?}",
                           fpr, ks);
                }
            } else {
                if *as_sub {
                    panic!("{} not found in by_subkey_id, but expected\n{:?}",
                           fpr, ks);
                }
            }

            // By grip.
            if let Ok(grip) = keygrip_of(key.mpis()) {
                if ks.by_primary_grip(&grip).any(|c| c.fingerprint() == fpr)
                {
                    if ! *as_primary {
                        panic!("Found {} in by_primary_grip, expected nothing\n{:?}",
                               fpr, ks);
                    }
                } else {
                    if *as_primary {
                        panic!("{} not found in by_primary_grip, but expected\n{:?}",
                               fpr, ks);
                    }
                }

                if ks.by_subkey_grip(&grip)
                    .any(|c| c.keys().any(|ka| ka.key().keyid() == keyid))
                {
                    if ! *as_sub {
                        panic!("Found {} in by_subkey_grip, expected nothing\n{:?}",
                               fpr, ks);
                    }
                } else {
                    if *as_sub {
                        panic!("{} not found in by_subkey_grip, but expected\n{:?}",
                               fpr, ks);
                    }
                }
            }
        }
    }

    // Asserts that a key does not appear in the key store, either in
    // the indices or in any of the certificates.
    fn ks_is_missing(ks: &KeystoreData,
                     key: &Key<key::PublicParts, key::UnspecifiedRole>)
    {
        // First check the maps.
        ks_contains(ks, &[ (key, false, false) ]);

        // Now iterate over everything and make sure it is really gone.
        for (table, cert) in
            ks.by_primary_fp.values()
                .map(|e| {
                    ("by_primary_fp", e.cert())
                })
                .chain(ks.by_primary_id.values().flat_map(|v| {
                    v.iter().map(|e| ("by_primary_id", e.cert()))
                }))
                .chain(ks.by_primary_grip.values().flat_map(|v| {
                    v.iter().map(|e| ("by_primary_grip", e.cert()))
                }))
                .chain(ks.by_subkey_fp.values().flat_map(|v| {
                    v.iter().map(|e| ("by_subkey_fp", e.cert()))
                }))
                .chain(ks.by_subkey_id.values().flat_map(|v| {
                    v.iter().map(|e| ("by_subkey_id", e.cert()))
                }))
                .chain(ks.by_subkey_grip.values().flat_map(|v| {
                    v.iter().map(|e| ("by_subkey_grip", e.cert()))
                }))
        {
            for k in cert.keys() {
                assert!(k.key().fingerprint() != key.fingerprint(),
                        "{}: {} still exists in {}, {:?}\n{:?}",
                        table,
                        key.fingerprint(),
                        k.key().fingerprint(),
                        cert.with_policy(&StandardPolicy::new(), None)
                            .map(|cert| {
                                cert.primary_userid()
                                    .map(|ua| {
                                        String::from_utf8_lossy(ua.userid().value())
                                            .into_owned()
                                    })
                                    .unwrap_or("<No UserID>"[..].into())
                            })
                            .unwrap_or("<Invalid>".into()),
                        ks);
            }
        }
    }

    // Have cert adopt the specified key.  Uses template to create the
    // self signature.
    fn adopt(cert: Cert,
             key: Key<key::SecretParts, key::SubordinateRole>,
             template: &Signature)
             -> openpgp::Result<Cert>
    {
        let mut builder: SignatureBuilder = match template.typ() {
            SignatureType::SubkeyBinding =>
                template.clone().into(),
            SignatureType::DirectKey
                | SignatureType::PositiveCertification
                | SignatureType::CasualCertification
                | SignatureType::PersonaCertification
                | SignatureType::GenericCertification =>
            {
                // Convert to a binding
                // signature.
                let kf = template.key_flags()
                    .context("Missing required \
                              subpacket, KeyFlags")?;
                SignatureBuilder::new(
                    SignatureType::SubkeyBinding)
                    .set_key_flags(kf)?
            },
            _ => panic!("Unsupported binding \
                         signature: {:?}",
                        template),
        };

        // Get a signer.
        let pk = cert.primary_key().key();
        let mut pk_signer = pk.clone().parts_into_secret()?.into_keypair()?;


        // Add the keys and signatures to cert.
        let mut packets: Vec<Packet> = vec![];

        // If there is a valid backsig, recreate it.
        let need_backsig = builder.key_flags()
            .map(|kf| kf.for_signing() || kf.for_certification())
            .expect("Missing keyflags");

        if need_backsig {
            // Derive a signer.
            let mut subkey_signer
                = key.clone().parts_into_secret()?.into_keypair()?;

            let backsig = builder.embedded_signatures()
                .filter(|backsig| {
                    (*backsig).clone().verify_primary_key_binding(
                        cert.primary_key().key(),
                        &key).is_ok()
                })
                .nth(0)
                .map(|sig| SignatureBuilder::from(sig.clone()))
                .unwrap_or_else(|| {
                    SignatureBuilder::new(SignatureType::PrimaryKeyBinding)
                })
                .sign_primary_key_binding(&mut subkey_signer, pk, &key)?;

            builder = builder.set_embedded_signature(backsig)?;
        } else {
            builder = builder.modify_hashed_area(|mut a| {
                a.remove_all(SubpacketTag::EmbeddedSignature);
                Ok(a)
            })?;
        }

        let sig = builder.sign_subkey_binding(&mut pk_signer, pk, &key)?;

        // Verify it.
        if let Err(err) = sig.verify_subkey_binding(pk_signer.public(), pk, &key) {
            panic!("invalid signature: {}", err);
        }

        packets.push(key.clone().into());
        packets.push(sig.into());

        let cert = cert.clone().insert_packets(packets.clone())?.0;

        Ok(cert)
    }

    #[test]
    fn insert_remove() -> openpgp::Result<()> {
        let ks = Keystore::default();
        let mut ks = ks.write();
        ks_count(&ks, 0, 0, false);

        // Generate a key and insert it.
        let (alice, revocation) = openpgp::cert::CertBuilder::general_purpose(
            Some("alice")).generate()?;
        ks.insert(alice.clone());

        let n_subkeys = alice.keys().subkeys().count();
        ks_count(&ks, 1, n_subkeys, false);
        ks_contains(&ks, &[
            (&alice.primary_key().key().role_as_unspecified(), true, false)
        ]);
        for sk in alice.keys().subkeys() {
            // Try lookups.
            ks_contains(&ks, &[
                (&sk.key().role_as_unspecified(), false, true)
            ]);
        }

        // Now, remove one subkey.
        let removed_sk: &Key<key::PublicParts, key::UnspecifiedRole>
            = alice.keys().subkeys().nth(0).unwrap().key().role_as_unspecified();
        let fp = removed_sk.fingerprint();
        let r = ks.remove_all(&fp);
        assert!(r);

        ks_is_missing(&ks, &removed_sk);

        // Remove the subkey from our copy of Alice's cert, and redo
        // all the lookups.
        let alice = alice.retain_subkeys(|sk| sk.key().fingerprint() != fp);
        let n_subkeys = alice.keys().subkeys().count();
        ks_count(&ks, 1, n_subkeys, false);
        ks_contains(&ks, &[
            (&alice.primary_key().key().role_as_unspecified(), true, false)
        ]);
        for sk in alice.keys().subkeys() {
            // Try lookups.
            ks_contains(&ks, &[
                (&sk.key().role_as_unspecified(), false, true)
            ]);
        }

        // Merge the revocation certificate.
        {
            let cell =
                ks.cert_cell_by_primary_fp(&alice.fingerprint()).unwrap();
            let mut cert = cell.write().unwrap();
            *cert = cert.clone().insert_packets(Some(revocation))?.0;
        }
        use openpgp::types::RevocationStatus;
        let p = &openpgp::policy::StandardPolicy::new();

        let fp = alice.fingerprint();
        let id = KeyID::from(&fp);
        let grip = Keygrip::of(alice.primary_key().key().mpis())?;
        assert!(matches!(
            ks.by_primary_fp(&fp).unwrap().revocation_status(p, None),
            RevocationStatus::Revoked(_)));
        assert!(matches!(
            ks.by_primary_id(&id).nth(0).unwrap().revocation_status(p, None),
            RevocationStatus::Revoked(_)));
        assert!(matches!(
            ks.by_primary_grip(&grip).nth(0).unwrap().revocation_status(p, None),
            RevocationStatus::Revoked(_)));
        ks_contains(&ks, &[
            (&alice.primary_key().key().role_as_unspecified(), true, false)
        ]);

        for sk in alice.keys().subkeys() {
            let fp = sk.key().fingerprint();
            let id = KeyID::from(&fp);
            let grip = Keygrip::of(sk.key().mpis())?;

            assert!(ks.by_primary_fp(&fp).is_none());
            assert_eq!(ks.by_primary_id(&id).count(), 0);
            assert_eq!(ks.by_primary_grip(&grip).count(), 0);
            assert!(matches!(
                ks.by_subkey_fp(&fp).nth(0).unwrap().revocation_status(p, None),
                RevocationStatus::Revoked(_)));
            assert!(matches!(
                ks.by_subkey_id(&id).nth(0).unwrap().revocation_status(p, None),
                RevocationStatus::Revoked(_)));
            assert!(matches!(
                ks.by_subkey_grip(&grip).nth(0).unwrap().revocation_status(p, None),
                RevocationStatus::Revoked(_)));

            ks_contains(&ks, &[
                (&sk.key().role_as_unspecified(), false, true)
            ]);
        }

        // Finally, remove the cert.
        let r = ks.remove_all(&alice.fingerprint());
        assert!(r);

        ks_count(&ks, 0, 0, false);

        Ok(())
    }

    // The keys of RFC 9980, Appendix A are indexed by fingerprint,
    // key ID, and keygrip, and the indices stay consistent when keys
    // are removed.
    #[test]
    fn insert_remove_rfc9980() -> openpgp::Result<()> {
        use crate::testdata::rfc9980;

        let ks = Keystore::default();
        let mut ks = ks.write();
        ks_count(&ks, 0, 0, false);

        let certs: Vec<Cert> =
            rfc9980::VECTORS.iter().map(|v| v.cert()).collect();
        for (i, cert) in certs.iter().enumerate() {
            assert_eq!(cert.keys().subkeys().count(), 1);
            ks.insert(cert.clone());
            ks_count(&ks, i + 1, i + 1, false);
        }

        for (v, cert) in rfc9980::VECTORS.iter().zip(certs.iter()) {
            let primary = cert.primary_key().key().role_as_unspecified();
            let subkey = cert.keys().subkeys().nth(0).unwrap().key()
                .role_as_unspecified();
            ks_contains(&ks, &[ (primary, true, false),
                                (subkey, false, true) ]);

            // ks_contains only considers the keygrip index if the key
            // has a keygrip.
            let grip: Keygrip = v.primary.grip.parse()?;
            assert_eq!(ks.by_primary_grip(&grip).count(), 1);
            assert_eq!(ks.by_subkey_grip(&grip).count(), 0);
            let grip: Keygrip = v.subkey.grip.parse()?;
            assert_eq!(ks.by_primary_grip(&grip).count(), 0);
            assert_eq!(ks.by_subkey_grip(&grip).count(), 1);
        }

        // Remove every other certificate's subkey.
        let mut n_pks = certs.len();
        let mut n_sks = certs.len();
        for cert in certs.iter().step_by(2) {
            let subkey = cert.keys().subkeys().nth(0).unwrap().key()
                .role_as_unspecified();
            assert!(ks.remove_all(&subkey.fingerprint()));
            n_sks -= 1;
            ks_is_missing(&ks, subkey);
            ks_count(&ks, n_pks, n_sks, false);
        }
        assert!(n_sks > 0);

        // Remove the certificates, with and without subkey.
        for (i, (v, cert)) in
            rfc9980::VECTORS.iter().zip(certs.iter()).enumerate()
        {
            let primary = cert.primary_key().key().role_as_unspecified();
            let subkey = cert.keys().subkeys().nth(0).unwrap().key()
                .role_as_unspecified();
            assert!(ks.remove_all(&primary.fingerprint()));
            n_pks -= 1;
            if i % 2 == 1 {
                n_sks -= 1;
            }
            ks_is_missing(&ks, primary);
            ks_is_missing(&ks, subkey);
            ks_count(&ks, n_pks, n_sks, false);

            let grip: Keygrip = v.primary.grip.parse()?;
            assert_eq!(ks.by_primary_grip(&grip).count(), 0);
            let grip: Keygrip = v.subkey.grip.parse()?;
            assert_eq!(ks.by_subkey_grip(&grip).count(), 0);
        }
        ks_count(&ks, 0, 0, false);

        Ok(())
    }

    // Given a certificate with multiple subkeys, add the subkeys one
    // at a time.
    #[test]
    fn add() -> openpgp::Result<()> {
        let ks = Keystore::default();
        let mut ks = ks.write();
        ks_count(&ks, 0, 0, false);

        // Generate a key and insert it.
        let (alice, _) = openpgp::cert::CertBuilder::new()
            .add_userid("alice")
            .add_signing_subkey()
            .add_signing_subkey()
            .add_signing_subkey()
            .add_signing_subkey()
            .add_signing_subkey()
            .add_signing_subkey()
            .add_signing_subkey()
            .generate()?;

        for _ in 0..2 {
            let mut added: Vec<Fingerprint> = Vec::new();
            for i in 0..alice.keys().subkeys().count() {
                let subset = alice.clone().retain_subkeys(|sk| {
                    if added.iter().any(|fpr| fpr == &sk.key().fingerprint()) {
                        // Already present.  Ignore it.
                        false
                    } else if added.len() < i {
                        // Add it.
                        added.push(sk.key().fingerprint());
                        true
                    } else {
                        // We have enough.
                        false
                    }
                });

                // We should have just one subkey.
                if i > 0 {
                    assert!(subset.keys().subkeys().count() == 1);
                } else {
                    assert!(subset.keys().subkeys().count() == 0);
                }

                // Add it.
                ks.insert(subset.clone());

                // Make sure it was merged correctly.
                ks_count(&ks, 1, i, false);

                ks_contains(&ks, &[(&alice.primary_key().key().role_as_unspecified(), true, false)]);
                for sk in alice.keys().subkeys() {
                    if added.iter().any(|fpr| fpr == &sk.key().fingerprint()) {
                        // Should have been added.
                        ks_contains(&ks, &[(&sk.key().role_as_unspecified(), false, true)]);
                    } else {
                        // Hasn't been added yet.
                        ks_contains(&ks, &[(&sk.key().role_as_unspecified(), false, false)]);
                    }
                }
            }

            // Finally, remove the cert.
            let r = ks.remove_all(&alice.fingerprint());
            assert!(r);

            ks_count(&ks, 0, 0, false);
        }

        Ok(())
    }

    // Two certificates with the same subkey.
    #[test]
    fn same_subkey() -> openpgp::Result<()> {
        let p = &openpgp::policy::StandardPolicy::new();

        let ks = Keystore::default();
        let mut ks = ks.write();
        ks_count(&ks, 0, 0, false);
        ks_contains(&ks, &[]);

        // Generate the keys.
        let (alice, _) = openpgp::cert::CertBuilder::general_purpose(
            Some("alice")).generate()?;

        let (bob, _) = openpgp::cert::CertBuilder::new()
            .add_userid("bob")
            .add_signing_subkey()
            .generate()?;

        let alice_pk = alice.primary_key().key().role_as_unspecified();
        let alice_enc = alice.with_policy(p, None)?
            .keys().subkeys().for_transport_encryption().nth(0)
            .expect("encryption-capable subkey");
        let alice_signing = alice.with_policy(p, None)?
            .keys().subkeys().for_signing().nth(0)
            .expect("signing-capable subkey")
            .amalgamation()
            .key().role_as_unspecified();

        // Add Alice's encryption capable subkey to Bob's certificate.
        let key = alice_enc.key().clone();
        let bob = adopt(bob,
                        key.clone()
                            .parts_into_secret()
                            .expect("secret key material"),
                        alice_enc.binding_signature())?;
        let common: &Key<key::PublicParts, key::UnspecifiedRole>
            = alice_enc.key().role_as_unspecified();

        let bob_pk = bob.primary_key().key().role_as_unspecified();
        let bob_enc: &Key<key::PublicParts, key::UnspecifiedRole>
            = bob.with_policy(p, None)?
            .keys().subkeys().for_transport_encryption().nth(0)
            .expect("encryption-capable subkey")
            .amalgamation()
            .key().role_as_unspecified();
        assert_eq!(common.fingerprint(), bob_enc.fingerprint());
        let bob_signing = bob.with_policy(p, None)?
            .keys().subkeys().for_signing().nth(0)
            .expect("encryption-capable subkey")
            .amalgamation()
            .key().role_as_unspecified();

        ks.insert(alice.clone());
        assert_eq!(ks.by_subkey_fp(&common.fingerprint()).count(), 1);
        ks.insert(bob.clone());
        assert_eq!(ks.by_subkey_fp(&common.fingerprint()).count(), 2);

        // We have 3 subkeys, not 4.
        ks_count(&ks, 2, 3, false);
        // The common subkey appears twice.
        assert_eq!(ks.by_subkey_fp(&common.fingerprint()).count(), 2);
        ks_contains(&ks, &[
            (&alice_pk, true, false),
            (&alice_signing, false, true),
            (&bob_pk, true, false),
            (&bob_signing, false, true),
            (&common, false, true),
        ]);

        // Remove Bob's signing subkey.
        let r = ks.remove_all(&bob_signing.fingerprint());
        assert!(r);

        ks_count(&ks, 2, 2, false);
        assert_eq!(ks.by_subkey_fp(&common.fingerprint()).count(), 2);
        ks_contains(&ks, &[
            (&alice_pk, true, false),
            (&alice_signing, false, true),
            (&bob_pk, true, false),
            (&bob_signing, false, false),
            (&common, false, true),
        ]);

        let r = ks.remove_all(&common.fingerprint());
        assert!(r);

        ks_count(&ks, 2, 1, false);
        assert_eq!(ks.by_subkey_fp(&common.fingerprint()).count(), 0);
        ks_contains(&ks, &[
            (&alice_pk, true, false),
            (&alice_signing, false, true),
            (&bob_pk, true, false),
            (&bob_signing, false, false),
            (&common, false, false),
        ]);

        assert!(! ks.by_primary_fp(&alice.fingerprint()).unwrap()
            .keys().any(|ka| ka.key().fingerprint() == common.fingerprint()));
        assert!(! ks.by_primary_fp(&bob.fingerprint()).unwrap()
            .keys().any(|ka| ka.key().fingerprint() == common.fingerprint()));

        // Finally, remove the cert.
        let r = ks.remove_all(&alice.fingerprint());
        assert!(r);

        ks_is_missing(&ks, &common);

        let r = ks.remove_all(&bob.fingerprint());
        assert!(r);

        ks_count(&ks, 0, 0, false);


        // Add alice and bob.  Remove bob.  Make sure everything is
        // still sane.

        ks.insert(alice.clone());
        assert_eq!(ks.by_subkey_fp(&common.fingerprint()).count(), 1);
        ks.insert(bob.clone());
        assert_eq!(ks.by_subkey_fp(&common.fingerprint()).count(), 2);

        // We have 3 subkeys, not 4.
        ks_count(&ks, 2, 3, false);
        // The common subkey appears twice.
        assert_eq!(ks.by_subkey_fp(&common.fingerprint()).count(), 2);
        ks_contains(&ks, &[
            (&alice_pk, true, false),
            (&alice_signing, false, true),
            (&bob_pk, true, false),
            (&bob_signing, false, true),
            (&common, false, true),
        ]);

        eprintln!("{:?}", ks);

        // Remove Bob's key.
        let r = ks.remove_all(&bob.fingerprint());
        assert!(r);

        ks_count(&ks, 1, 2, false);
        assert_eq!(ks.by_subkey_fp(&common.fingerprint()).count(), 1);
        ks_contains(&ks, &[
            (&alice_pk, true, false),
            (&alice_signing, false, true),
            (&bob_pk, false, false),
            (&bob_signing, false, false),
            (&common, false, true),
        ]);

        Ok(())
    }

    // The same MPIs appear on two certificates (but the keys are
    // different!).
    #[test]
    fn same_grip() -> openpgp::Result<()> {
        let p = &openpgp::policy::StandardPolicy::new();

        let ks = Keystore::default();
        let mut ks = ks.write();
        ks_count(&ks, 0, 0, false);
        ks_contains(&ks, &[]);

        // Generate the keys.
        let t = std::time::SystemTime::now() - std::time::Duration::new(10, 0);
        let (alice, _) = openpgp::cert::CertBuilder::general_purpose(
            Some("alice"))
            .set_creation_time(t)
            .generate()?;

        let (bob, _) = openpgp::cert::CertBuilder::new()
            .add_userid("bob")
            .add_signing_subkey()
            .set_creation_time(t)
            .generate()?;

        let alice_pk = alice.primary_key().key().role_as_unspecified();
        let alice_enc = alice.with_policy(p, None)?
            .keys().subkeys().for_transport_encryption().nth(0)
            .expect("encryption-capable subkey");
        let alice_signing = alice.with_policy(p, None)?
            .keys().subkeys().for_signing().nth(0)
            .expect("signing-capable subkey")
            .amalgamation()
            .key().role_as_unspecified();

        // Add the encryption subkey to Bob's key.  Change the
        // creation time so that it has the same grip, but a different
        // fingerprint.
        let mut key = alice_enc.key().clone();
        let ct = key.creation_time() + std::time::Duration::new(1, 0);
        key.set_creation_time(ct)?;

        let bob = adopt(bob,
                        key.clone()
                            .parts_into_secret()
                            .expect("secret key material"),
                        alice_enc.binding_signature())?;
        let alice_enc: &Key<key::PublicParts, key::UnspecifiedRole>
            = alice_enc.amalgamation().key().role_as_unspecified();

        let bob_pk = bob.primary_key().key().role_as_unspecified();
        let bob_enc: &Key<key::PublicParts, key::UnspecifiedRole>
            = bob.with_policy(p, None)?
            .keys().subkeys().for_transport_encryption().nth(0)
            .expect("encryption-capable subkey")
            .amalgamation()
            .key().role_as_unspecified();
        let bob_signing = bob.with_policy(p, None)?
            .keys().subkeys().for_signing().nth(0)
            .expect("encryption-capable subkey")
            .amalgamation()
            .key().role_as_unspecified();

        let common_grip = Keygrip::of(alice_enc.mpis()).unwrap();
        assert_eq!(common_grip,
                   Keygrip::of(bob_enc.mpis()).unwrap());

        ks.insert(alice.clone());
        assert_eq!(ks.by_subkey_grip(&common_grip).count(), 1);
        ks.insert(bob.clone());
        assert_eq!(ks.by_subkey_grip(&common_grip).count(), 2);

        // We have 4 subkeys: the two subkeys with the same grip have
        // different fingerprints.
        ks_count(&ks, 2, 4, true);
        // The common grip appears twice.
        assert_eq!(ks.by_subkey_grip(&common_grip).count(), 2);
        ks_contains(&ks, &[
            (&alice_pk, true, false),
            (&alice_signing, false, true),
            (&alice_enc, false, true),
            (&bob_pk, true, false),
            (&bob_signing, false, true),
            (&bob_enc, false, true),
        ]);

        // Remove Bob's encryption subkey, which is the one with the
        // shared grip.
        let r = ks.remove_all(&bob_enc.fingerprint());
        assert!(r);

        ks_count(&ks, 2, 3, true);
        assert_eq!(ks.by_subkey_grip(&common_grip).count(), 1);
        ks_contains(&ks, &[
            (&alice_pk, true, false),
            (&alice_signing, false, true),
            (&alice_enc, false, true),
            (&bob_pk, true, false),
            (&bob_signing, false, true),
            (&bob_enc, false, false),
        ]);

        let r = ks.remove_all(&alice_enc.fingerprint());
        assert!(r);

        ks_count(&ks, 2, 2, true);
        assert_eq!(ks.by_subkey_grip(&common_grip).count(), 0);
        ks_contains(&ks, &[
            (&alice_pk, true, false),
            (&alice_signing, false, true),
            (&alice_enc, false, false),
            (&bob_pk, true, false),
            (&bob_signing, false, true),
            (&bob_enc, false, false),
        ]);

        assert!(! ks.by_primary_fp(&alice.fingerprint()).unwrap()
            .keys().any(|ka| Keygrip::of(ka.key().mpis()).unwrap() == common_grip));
        assert!(! ks.by_primary_fp(&bob.fingerprint()).unwrap()
            .keys().any(|ka| Keygrip::of(ka.key().mpis()).unwrap() == common_grip));

        // Finally, remove the cert.
        let r = ks.remove_all(&alice.fingerprint());
        assert!(r);

        let r = ks.remove_all(&bob.fingerprint());
        assert!(r);

        ks_count(&ks, 0, 0, false);


        // Add alice and bob.  Remove bob.  Make sure everything is
        // still sane.

        ks.insert(alice.clone());
        assert_eq!(ks.by_subkey_grip(&common_grip).count(), 1);
        ks.insert(bob.clone());
        assert_eq!(ks.by_subkey_grip(&common_grip).count(), 2);

        // We have 4 subkeys.
        ks_count(&ks, 2, 4, true);
        // The common grip appears twice.
        assert_eq!(ks.by_subkey_grip(&common_grip).count(), 2);
        ks_contains(&ks, &[
            (&alice_pk, true, false),
            (&alice_signing, false, true),
            (&alice_enc, false, true),
            (&bob_pk, true, false),
            (&bob_signing, false, true),
            (&bob_enc, false, true),
        ]);

        eprintln!("{:?}", ks);

        // Remove Bob's key.
        let r = ks.remove_all(&bob.fingerprint());
        assert!(r);

        ks_count(&ks, 1, 2, false);
        assert_eq!(ks.by_subkey_grip(&common_grip).count(), 1);
        ks_contains(&ks, &[
            (&alice_pk, true, false),
            (&alice_signing, false, true),
            (&alice_enc, false, true),
            (&bob_pk, false, false),
            (&bob_signing, false, false),
            (&bob_enc, false, false),
        ]);

        Ok(())
    }

    // The same MPIs appear on same certificate as two different
    // subkeys.
    #[test]
    fn same_grip_same_cert() -> openpgp::Result<()> {
        let p = &openpgp::policy::StandardPolicy::new();

        let ks = Keystore::default();
        let mut ks = ks.write();
        ks_count(&ks, 0, 0, false);
        ks_contains(&ks, &[]);

        // Generate the keys.
        let t = std::time::SystemTime::now() - std::time::Duration::new(10, 0);
        let (alice, _) = openpgp::cert::CertBuilder::new()
            .add_userid("alice")
            .add_signing_subkey()
            .set_creation_time(t)
            .generate()?;

        let alice_pk = alice.primary_key().key().role_as_unspecified();
        let alice_signing = alice.with_policy(p, None)?
            .keys().subkeys().for_signing().nth(0)
            .expect("signing-capable subkey");

        ks.insert(alice.clone());

        // We have 1 key with 1 subkey.
        ks_count(&ks, 1, 1, false);
        ks_contains(&ks, &[
            (&alice_pk, true, false),
            (&alice_signing.clone().amalgamation().key().role_as_unspecified(), false, true),
        ]);

        // Create a second subkey with the same grip.
        let mut key = alice_signing.key().clone();
        let ct = key.creation_time() + std::time::Duration::new(1, 0);
        key.set_creation_time(ct)?;
        let template = alice_signing.binding_signature().clone();

        let alice = adopt(alice,
                          key.clone()
                              .parts_into_secret()
                              .expect("secret key material"),
                          &template)?;
        let alice_pk = alice.primary_key().key().role_as_unspecified();
        let alice_signing: &Key<key::PublicParts, key::UnspecifiedRole>
            = alice.keys().subkeys().nth(0).unwrap().key().role_as_unspecified();
        let alice_signing2: &Key<key::PublicParts, key::UnspecifiedRole>
            = alice.keys().subkeys().nth(1).unwrap().key().role_as_unspecified();

        let common_grip = Keygrip::of(alice_signing.mpis()).unwrap();
        assert_eq!(common_grip,
                   Keygrip::of(alice_signing2.mpis()).unwrap());

        ks.insert(alice.clone());

        // We have 2 subkeys with the same grip.
        ks_count(&ks, 1, 2, true);
        // The common grip appears twice.
        assert_eq!(ks.by_subkey_grip(&common_grip).count(), 2,
                   "{:?}", ks);
        ks_contains(&ks, &[
            (&alice_pk, true, false),
            (&alice_signing, false, true),
            (&alice_signing2, false, true),
        ]);

        // Remove one of the signing keys with the shared grip.
        let r = ks.remove_all(&alice_signing2.fingerprint());
        assert!(r);

        ks_count(&ks, 1, 1, false);
        assert_eq!(ks.by_subkey_grip(&common_grip).count(), 1);
        ks_contains(&ks, &[
            (&alice_pk, true, false),
            (&alice_signing, false, true),
            (&alice_signing2, false, false),
        ]);

        let r = ks.remove_all(&alice_signing.fingerprint());
        assert!(r);

        ks_count(&ks, 1, 0, false);
        assert_eq!(ks.by_subkey_grip(&common_grip).count(), 0);
        ks_contains(&ks, &[
            (&alice_pk, true, false),
            (&alice_signing, false, false),
            (&alice_signing2, false, false),
        ]);

        // Finally, remove the cert.
        let r = ks.remove_all(&alice.fingerprint());
        assert!(r);

        ks_count(&ks, 0, 0, false);


        // Add alice and bob.  Remove bob.  Make sure everything is
        // still sane.

        ks.insert(alice.clone());
        assert_eq!(ks.by_subkey_grip(&common_grip).count(), 2);

        // The common grip appears twice.
        ks_count(&ks, 1, 2, true);
        assert_eq!(ks.by_subkey_grip(&common_grip).count(), 2);
        ks_contains(&ks, &[
            (&alice_pk, true, false),
            (&alice_signing, false, true),
            (&alice_signing2, false, true),
        ]);

        eprintln!("{:?}", ks);

        Ok(())
    }

    // Inserting the public key must not remove secrets.
    #[test]
    fn key_cert_secrets_preserved() -> openpgp::Result<()> {
        let (key, _) =
            openpgp::cert::CertBuilder::general_purpose(Some("Hanna")).generate()?;
        let fp = key.fingerprint();
        let a = key.clone();
        let b = key.strip_secret_key_material();

        // Test both ways.
        for (first, second) in vec![(&a, &b), (&b, &a)] {
            eprintln!("First has {}secret, second has {}secret.",
                      if first.is_tsk() { "" } else { "no " },
                      if second.is_tsk() { "" } else { "no " });
            let ks = Keystore::default();
            let mut ks = ks.write();
            ks.insert(first.clone());
            ks.insert(second.clone());

            let k = ks.by_primary_fp(&fp).unwrap();
            assert!(k.is_tsk());
            assert!(k.primary_key().key().has_unencrypted_secret());
            assert_eq!(k.keys().unencrypted_secret().count(),
                       k.keys().count());
        }
        Ok(())
    }
}
