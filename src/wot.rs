use std::collections::HashSet;

use rusqlite::{
    Connection,
    types::ToSql,
    OptionalExtension,
    params,
};

use sequoia_openpgp as openpgp;
use openpgp::packet::UserID;

use crate::gpg;
use crate::gpg::Validity;
use crate::tbprofile::TBProfile;

// Carefully update TB's acceptance DB with GPG's validity.
pub fn update_acceptance(gpg_ctx: &gpg::Ctx, output_hash: Option<&gpg::OutputHash>)
    -> openpgp::Result<gpg::OutputHash>
{
    rnp_function!(update_acceptance, super::TRACE);

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

    let (validity, output_hash) = match gpg::list_validity(&gpg_ctx, output_hash) {
        Ok(validity) => validity,
        Err(err) => {
            match err.downcast_ref::<gpg::Error>() {
                Some(gpg::Error::Unchanged) =>
                    return Ok(output_hash.unwrap().clone()),
                _ => (),
            }

            let err = err.context("openpgp.sqlite: \
                                   Running  gpg --list-keys");
            warn!("{}", err);
            return Err(err);
        }
    };

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
        if managed_by_tb.contains(&fpr) {
            t!("Not updating validity for {} to {:?}: \
                validity managed by user",
               fpr, validity);
        } else {
            tx.execute(
                "INSERT OR REPLACE INTO acceptance_decision \
                 (fpr, decision) VALUES (?1, ?2)",
                &[&fpr as &dyn ToSql, &validity])?;

            tx.execute(
                "INSERT OR REPLACE INTO managed_by_sequoia \
                 (fpr) VALUES (?1)",
                &[&fpr as &dyn ToSql])?;

            for (email, _validity) in key_validity {
                tx.execute(
                    "INSERT OR REPLACE INTO acceptance_email \
                     (fpr, email) VALUES (?1, ?2)",
                    &[&fpr as &dyn ToSql, &email])?;
            }
        }
    }

    tx.commit()?;

    Ok(output_hash)
}

