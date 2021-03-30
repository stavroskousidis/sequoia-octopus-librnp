use std::collections::HashSet;
use std::ops::DerefMut;
use std::sync::Arc;
use std::sync::mpsc;
use std::sync::Mutex;
use std::sync::MutexGuard;
use std::thread;
use std::time::Duration;
use std::time::SystemTime;

use rusqlite::{
    Connection,
    types::ToSql,
    OptionalExtension,
    params,
};

use sequoia_openpgp as openpgp;
use openpgp::Fingerprint;
use openpgp::packet::UserID;

use crate::gpg;
use crate::gpg::Validity;
use crate::tbprofile::TBProfile;

pub struct WoT {
    data: Arc<Mutex<Option<WoTData>>>,
    sender: Arc<Mutex<Option<mpsc::Sender<()>>>>,
}

struct WoTData {
    gpg_ctx: gpg::Ctx,
    conn: rusqlite::Connection,
    output_hash: Option<gpg::OutputHash>,
    last_update: SystemTime,
}

// A singleton.
lazy_static! {
    static ref WOT: Arc<WoT>
        = Arc::new(WoT {
            data: Arc::new(Mutex::new(None)),
            sender: Arc::new(Mutex::new(None)),
        });
}

impl WoT {
    // Return a locked WoTData.
    //
    // If WoT hasn't been initialized, do it now.
    fn lock() -> openpgp::Result<MutexGuard<'static, Option<WoTData>>> {
        let mut data = WOT.data.lock().unwrap();
        if data.is_some() {
            // The singleton is already initialized.
            return Ok(data);
        }

        let gpg_ctx = gpg::Ctx::new()?;

        let path = TBProfile::path()
            .ok_or(anyhow::anyhow!("TB Profile directory not found"))?;

        // The tables that TB creates:
        //
        // Note the unfortunate lack of a version number :/.
        //
        //   CREATE TABLE acceptance_email
        //     (fpr text not null, email text not null, unique(fpr, email));
        //   CREATE TABLE acceptance_decision
        //     (fpr text not null, decision text not null, unique(fpr));
        //
        // Make sure the DB meets our expectations DB before continuing.
        let mut conn = Connection::open(path.join("openpgp.sqlite"))?;
        conn.query_row("SELECT fpr, email FROM acceptance_email LIMIT 1",
                       params![], |_| Ok(()))
            .optional()
            .map_err(|err| {
                let err: anyhow::Error = err.into();
                let err = err.context(
                    "openpgp.sqlite: \
                     Unexpected schema (querying acceptance_email)");
                warn!("openpgp.sqlite: {}", err);
                err
            })?;
        conn.query_row("SELECT fpr, decision FROM acceptance_decision LIMIT 1",
                       params![], |_| Ok(()))
            .optional()
            .map_err(|err| {
                let err: anyhow::Error = err.into();
                let err = err.context(
                    "openpgp.sqlite:\
                     Unexpected schema (querying acceptance_decision)");
                warn!("openpgp.sqlite: {}", err);
                err
            })?;

        let tx = conn.transaction()?;

        // Be extra careful to not override user decisions.
        //
        // A given certificate can be in one of three states:
        //
        //   1. Not in acceptance_decision and thus not managed by the user
        //      or us.
        //
        //   2. In acceptance_decision and not in managed_by_sequoia and
        //      thus managed by the user.
        //
        //   3. In acceptance_decision and in managed_by_sequoia and
        //      thus managed by us.
        //
        // Using triggers, we cause the managed_by_sequoia entry to be
        // deleted when the user (via TB) sets the acceptance.
        //
        // When updating the acceptance criteria, we don't touch
        // certificates that fall into category 2.  Everything else is
        // fair game.
        tx.execute("CREATE TABLE IF NOT EXISTS managed_by_sequoia \
                    (fpr text not NULL, unique(fpr))",
                   params![])?;
        tx.execute("CREATE INDEX IF NOT EXISTS managed_by_sequoia_i \
                    ON managed_by_sequoia (fpr)",
                   params![])?;
        tx.execute("CREATE TRIGGER IF NOT EXISTS user_update \
                    UPDATE on acceptance_decision \
                    FOR EACH ROW \
                    BEGIN \
                    DELETE FROM managed_by_sequoia \
                    WHERE managed_by_sequoia.fpr = NEW.fpr; \
                    END",
                   params![])?;
        tx.execute("CREATE TRIGGER IF NOT EXISTS user_insert \
                    INSERT on acceptance_decision \
                    FOR EACH ROW \
                    BEGIN \
                    DELETE FROM managed_by_sequoia \
                    WHERE managed_by_sequoia.fpr = NEW.fpr; \
                    END",
                   params![])?;

        tx.commit()?;

        *data = Some(WoTData {
            gpg_ctx,
            conn,
            output_hash: None,
            last_update: std::time::UNIX_EPOCH,
        });

        Ok(data)
    }

    // Create a thread to start monitoring gpg's trust db for updates.
    pub fn monitor() -> openpgp::Result<()> {
        let data_ref = WoT::lock()?;
        assert!(data_ref.is_some());

        let mut sender_ref = WOT.sender.lock().unwrap();
        if sender_ref.is_some() {
            // Already started the thread.
            return Ok(());
        }

        // Start the thread.
        let (sender, receiver) = mpsc::channel();
        *sender_ref = Some(sender);
        drop(sender_ref);

        thread::spawn(move || {
            WoTData::monitor(receiver);
        });

        Ok(())
    }
}

impl WoTData {
    fn worker(receiver: &mut mpsc::Receiver<()>)
        -> openpgp::Result<()>
    {
        rnp_function!(WoTData::worker, super::TRACE);
        let mut first_time = true;
        loop {
            // Check for updates about once an hour (but not quite to
            // avoid possible resonance), or when we are asked.
            if first_time {
                first_time = false;
            } else {
                let r = receiver.recv_timeout(Duration::new(67 * 60, 0));
                match r {
                    // Check now.
                    Ok(()) => {
                        // Drain the queue.
                        while let Ok(_) = receiver.recv_timeout(
                            Duration::new(0, 0)) {
                        }
                    },
                    // Poll now.
                    Err(mpsc::RecvTimeoutError::Timeout) => (),
                    // wot was destroyed.
                    Err(_err) => {
                        t!("Monitor disconnected (1).  Time to shutdown.");
                        return Ok(());
                    }
                }
            }

            let mut data_ref = WOT.data.lock().unwrap();
            let data = if let Some(data) = data_ref.deref_mut() {
                data
            } else {
                t!("Monitor disconnected (2).  Time to shutdown.");
                return Ok(());
            };

            let now = SystemTime::now();
            let elapsed = now.duration_since(data.last_update);
            match elapsed {
                Err(err) => {
                    t!("Error computing time since last update: {}", err);
                    continue;
                },
                Ok(elapsed) => {
                    if elapsed < Duration::new(10, 0) {
                        t!("Throttling updates.");
                        continue;
                    }
                }
            }

            t!("Checking for WoT updates...");

            if let Err(err) = Self::update(&mut data_ref) {
                warn!("Updating web of trust: {}", err);
            }

            data_ref.as_mut().unwrap().last_update = SystemTime::now();

            drop(data_ref);
        }
    }

    // Monitor the worker thread.
    //
    // If it returns an error, then it is restarted (after a short
    // timeout).
    fn monitor(mut receiver: mpsc::Receiver<()>)
    {
        rnp_function!(WoTData::monitor, super::TRACE);
        while let Err(err) = Self::worker(&mut receiver) {
            t!("WoT thread returned unexpectedly ({:?}), restarting", err);
            thread::sleep(Duration::new(5 * 60, 0));
        }
    }

    // Carefully update TB's acceptance DB with GPG's validity.
    fn update(data: &mut MutexGuard<Option<WoTData>>) -> openpgp::Result<()>
    {
        rnp_function!(WoT::update, super::TRACE);

        let data = data.as_mut().expect("init succeeded");

        let (validity, output_hash)
            = match gpg::list_validity(&data.gpg_ctx, None,
                                       data.output_hash.as_ref())
        {
            Ok(validity) => validity,
            Err(err) => {
                match err.downcast_ref::<gpg::Error>() {
                    Some(gpg::Error::Unchanged) =>
                        // Unchanged.  Short-circuit.
                        return Ok(()),
                    _ => (),
                }

                let err = err.context("openpgp.sqlite: \
                                       Running  gpg --list-keys");
                warn!("{}", err);
                return Err(err);
            }
        };

        let mut tx = data.conn.transaction()?;

        // See comment in `WoT::new` regarding what exactly is
        // considered managed by sequoia.
        let managed_by_tb: HashSet<String> = {
            let mut stmt =
                tx.prepare("SELECT fpr from acceptance_decision \
                            WHERE fpr NOT IN \
                            (SELECT fpr from managed_by_sequoia)")?;
            let rows = stmt
                .query_map(params![], |row| row.get::<_, String>(0).map(|fpr| {
                    fpr.to_ascii_lowercase()
                }));
            match rows {
                Ok(iter) => iter.filter_map(|fpr| fpr.ok()).collect(),
                Err(err) => {
                    warn!("Querying managed_by_sequoia: {}", err);
                    Default::default()
                }
            }
        };

        WoTData::import_validity(&mut tx, Some(managed_by_tb), validity)?;

        tx.commit()?;

        data.output_hash = Some(output_hash);

        Ok(())
    }

    // If managed_by_tb is None, then validity has already been
    // filtered to only contain keys managed by us.
    fn import_validity(tx: &mut rusqlite::Transaction,
                       managed_by_tb: Option<HashSet<String>>,
                       validity: Vec<(Fingerprint, Vec<(String, gpg::Validity)>)>)
                       -> openpgp::Result<()>
    {
        rnp_function!(import_validity, super::TRACE);

        for (fpr, key_validity) in validity {
            let key_validity: Vec<_> = key_validity
                .into_iter()
                .filter_map(|(uid, validity)| {
                    match UserID::from(uid.clone()).email() {
                        Ok(Some(email)) => {
                            Some((email.to_ascii_lowercase(), validity))
                        },
                        Ok(None) => None,
                        Err(err) => {
                            warn!("Extracting email address from UserID: {:?}: {}",
                                  uid, err);
                            None
                        }
                    }
                })
                .collect();
            if key_validity.is_empty() {
                continue;
            }

            // We can only have two judgements per certificate: "none" or
            // "something else".  Unfortunately, the format isn't more
            // expressive.  If any are maginal, then we treat all verified
            // User IDs as maginal.
            let validity = if key_validity.iter().any(|(_uid, validity)| {
                *validity == Validity::Marginal
            }) {
                "unverified"
            } else {
                "verified"
            };

            let fpr = fpr.to_string().to_ascii_lowercase();
            if managed_by_tb.as_ref().map(|h| h.contains(&fpr)).unwrap_or(true) {
                t!("Not updating validity for {} to {:?}: \
                    validity managed by user",
                   fpr, validity);
            } else {
                t!("Setting {} to {}", fpr, validity);

                tx.execute(
                    "INSERT OR REPLACE INTO acceptance_decision \
                     (fpr, decision) VALUES (?1, ?2)",
                    &[&fpr as &dyn ToSql, &validity])?;

                tx.execute(
                    "INSERT OR REPLACE INTO managed_by_sequoia \
                     (fpr) VALUES (?1)",
                    &[&fpr as &dyn ToSql])?;

                for (email, _validity) in key_validity {
                    t!("Setting {}, {} to {}", fpr, email, validity);
                    tx.execute(
                        "INSERT OR REPLACE INTO acceptance_email \
                         (fpr, email) VALUES (?1, ?2)",
                        &[&fpr as &dyn ToSql, &email])?;
                }
            }
        }

        Ok(())
    }
}
