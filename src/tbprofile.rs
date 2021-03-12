use std::path::Path;
use std::path::PathBuf;
use std::fs::File;
use std::io::Read;
use std::ops::Deref;
use std::time::{SystemTime, Duration, UNIX_EPOCH};

use sequoia_openpgp as openpgp;

// https://docs.rs/app_dirs/1.2.1/app_dirs/

const PROFILES_INI: &[&'static str] = &[
    // Linux, BSD, etc.: prefix with $HOME.
    #[cfg(not(any(windows, target_os = "macos")))]
    ".thunderbird",
    #[cfg(not(any(windows, target_os = "macos")))]
    ".mozilla-thunderbird",

    // macOS: prefix with $HOME.
    #[cfg(target_os = "macos")]
    "Library/Thunderbird/Profiles",
    #[cfg(target_os = "macos")]
    "Library/Application Support/Thunderbird/Profiles",

    // Windows: prefix with %APPDATA%.
    #[cfg(windows)]
    "Thunderbird\\Profiles",
];

#[cfg(windows)]
const LOCK_FILE: &'static str = "parent.lock";
#[cfg(not(windows))]
const LOCK_FILE: &'static str = "lock";


pub struct TBProfile {
    path: Option<PathBuf>,
}

// Some information about profiles.ini:
//
//   https://www.thunderbird-mail.de/lexicon/entry/123-profiles-ini/
impl TBProfile {
    pub fn load() -> openpgp::Result<Self> {
        rnp_function!(TBProfile::load, super::TRACE);

        #[allow(deprecated)]
        let prefix = std::env::home_dir()
            .ok_or(anyhow::anyhow!("Failed to find home directory"))?;

        let mut base: PathBuf = PathBuf::new();
        base.push(&prefix);

        let dirs: Vec<_> = PROFILES_INI.iter().flat_map(|suffix| {
            let mut profiles_ini = base.clone();
            profiles_ini.push(&suffix);
            profiles_ini.push("profiles.ini");
            t!("Considering {:?}", profiles_ini);

            let mut f = match File::open(&profiles_ini) {
                Ok(f) => f,
                Err(err) => {
                    warn!("Opening {:?}: {}", profiles_ini, err);
                    return vec![];
                }
            };

            let mut content = String::new();
            if let Err(err) = f.read_to_string(&mut content) {
                warn!("Reading {:?}: {}", profiles_ini, err);
                return vec![];
            }

            // Use Ini::new, all sections are keys are lowercased.
            let mut parsed = configparser::ini::Ini::new();
            if let Err(err) = parsed.read(content) {
                warn!("Parsing {:?}: {}", profiles_ini, err);
                return vec![];
            }

            parsed.sections()
                .into_iter()
                .filter_map(|section| {
                    if section.starts_with("profile") {
                        parsed.get(&section, "path")
                    } else {
                        None
                    }
                })
                .map(|path| {
                    let mut dir = PathBuf::new();
                    dir.push(&path);

                    t!("Profile directory (raw): {:?}", dir);

                    if dir.is_relative() {
                        let mut abs = prefix.clone();
                        abs.push(&base);
                        abs.push(&suffix);
                        abs.push(dir);
                        dir = abs;
                    }

                    t!("Profile directory (absolute path): {:?}", dir);

                    dir
                })
                .filter(|dir| {
                    // Make sure it exists.
                    if ! dir.is_dir() {
                        t!("{:?} does not exist", dir);
                        false
                    } else {
                        true
                    }
                })
                .filter_map(|dir| {
                    // And the lock file.
                    let mut lock = dir.clone();
                    lock.push(LOCK_FILE);

                    // On Linux, it is created as a symlink whose
                    // value is of the form: 127.0.1.1:+12184.  We
                    // want the pid.  We grab all of the digits at the
                    // end and parse that as a number.
                    #[cfg(not(windows))]
                    let pid: Option<isize> = {
                        let lock_value = lock
                            .read_link()
                            .map_err(|err| {
                                t!("Opening lock file: {}", err);
                                err
                            })
                            .ok()?;

                        t!("lock file: {:?} -> {:?}",
                           lock, lock_value);

                        let pid: String = lock_value
                            .to_string_lossy()
                            .chars()
                            .rev()
                            .take_while(|c| c.is_digit(10))
                            .collect();
                        let pid: String = pid.chars().rev().collect();
                        // Don't fail if we can't extract a pid.  I wasn't
                        // able to find documentation on the actual
                        // format.
                        let pid = pid.parse::<isize>().ok();
                        t!("pid: {:?}", pid);
                        pid
                    };
                    #[cfg(windows)]
                    let pid: Option<isize> = None;

                    // On Linux, a symlink is created.
                    #[cfg(not(windows))]
                    let ts: Option<SystemTime> = {
                        lock.symlink_metadata()
                            .map_err(|err| {
                                t!("Opening lock file: {}", err);
                                err
                            })
                            .ok()?
                            .modified().ok()
                    };
                    // On Windows, the lockfile is touched.
                    #[cfg(windows)]
                    let ts: Option<SystemTime> = {
                        lock.metadata().ok()?.modified().ok()
                    };

                    Some((dir, pid, ts))
                })
                .collect::<Vec<(PathBuf,
                                Option<isize>,
                                Option<SystemTime>)>>()
        }).collect::<Vec<_>>();

        // We have zero or more candidate directories.
        Ok(TBProfile::select_profile(dirs))
    }

    // This is a separate function to make it easier to test.
    fn select_profile(mut dirs: Vec<(PathBuf,
                                     Option<isize>,
                                     Option<SystemTime>)>)
        -> Self
    {
        rnp_function!(TBProfile::select_profile, super::TRACE);

        // XXX: What's the format of the lock file on windows?
        #[cfg(windows)]
        let pid = isize::MAX;
        #[cfg(not(windows))]
        let pid = unsafe { libc::getpid() as isize };

        t!("my pid is: {:?}", pid);

        let now = SystemTime::now();
        let long_ago = Duration::new(10 * 365 * 24 * 60 * 60, 0);

        dirs.sort_by_key(|a| {
            // Prefer the lock file that has a matching pid.  Then
            // fallback to the time since the lock file's creation
            // time.  Finally, break ties using a lexographical sort.
            //
            // Recall None < Some(_).

            let lock_pid = a.1;
            let creation_time = a.2.unwrap_or(UNIX_EPOCH);
            let path = a.0.clone();

            (
                // PID.
                if lock_pid.is_some() && lock_pid.unwrap() == pid {
                    0
                } else if lock_pid.is_some() {
                    // Could extract a pid.
                    1
                } else {
                    // Got nothing.
                    2
                },
                // Absolute time from now.
                if creation_time > now {
                    // If the timestamp is in the future, penalize it.
                    (creation_time.duration_since(now))
                        .unwrap_or(long_ago.clone())
                        + Duration::new(60 * 60, 0)
                } else {
                    now.duration_since(creation_time)
                        .unwrap_or(long_ago.clone())
                },
                // Path.
                path)
        });

        t!("candidate profile directories: {:?}", dirs);

        TBProfile {
            path: if dirs.is_empty() { None } else { Some(dirs[0].0.clone()) },
        }
    }

    /// Return the profile's path.
    ///
    /// If we culd find the profile, returns None.
    pub fn path(&self) -> Option<&Path> {
        self.path.as_ref().map(|p| p.deref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::time::SystemTime;
    use std::time::Duration;

    #[test]
    fn sort() {
        let now = SystemTime::now();
        let tminus1 = now - Duration::new(1, 0);
        let tminus2 = now - Duration::new(2, 0);

        #[cfg(windows)]
        let pid = isize::MAX;
        #[cfg(not(windows))]
        let pid = unsafe { libc::getpid() as isize };

        let other_pid = pid - 1;

        // Even though a's lock file is old, we prefer it, because the
        // pid matches ours.
        assert_eq!(
            TBProfile::select_profile(vec![
                ("a".into(), Some(pid), Some(tminus2)),
                ("b".into(), Some(other_pid), Some(tminus1)),
            ]).path().map(|p| p.to_string_lossy().into_owned()),
            Some("a".into()));

        // Neither pid matches.  But "b"'s lock file is more recent.
        assert_eq!(
            TBProfile::select_profile(vec![
                ("a".into(), Some(other_pid), Some(tminus2)),
                ("b".into(), Some(other_pid), Some(tminus1)),
            ]).path().map(|p| p.to_string_lossy().into_owned()),
            Some("b".into()));

        // No pids.  "b"'s lock file is more recent.
        assert_eq!(
            TBProfile::select_profile(vec![
                ("a".into(), None, Some(tminus2)),
                ("b".into(), None, Some(tminus1)),
            ]).path().map(|p| p.to_string_lossy().into_owned()),
            Some("b".into()));

        // We prefer a valid formed lock file (with a pid) to one
        // where we can't extract a pid.
        assert_eq!(
            TBProfile::select_profile(vec![
                ("a".into(), Some(other_pid), Some(tminus2)),
                ("b".into(), None, Some(tminus1)),
            ]).path().map(|p| p.to_string_lossy().into_owned()),
            Some("a".into()));
    }
}
