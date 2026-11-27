use std::sync::OnceLock;

use libc::{
    c_char
};

const CLAIMED_RNP_VERSION: [u32; 3] = [0, 18, 1];

const RNP_VERSION_COMPONENT_MASK: u32 = 0x3ff;

const RNP_VERSION_MAJOR_SHIFT: u8 = 20;
const RNP_VERSION_MINOR_SHIFT: u8 = 10;
const RNP_VERSION_PATCH_SHIFT: u8 = 0;

// An RNP version number is a 32bit number. 10 bit per version component, the
// lowest 10 bit for the patch number, the middle 10 for the minor version, the highest
// for the major version number. The most significant 2 bits are undefined.
#[no_mangle]
pub unsafe extern "C" fn rnp_version_for(
    major: u32,
    minor: u32,
    patch: u32,
) -> u32 {
    let r = rnp_version_for_internal(major, minor, patch);

    // Thunderbird invokes this function with the minimal supported
    // version, then compares the result with the result of
    // `rnp_version`.  If it is lower, an error message is emitted to
    // the error console, and OpenPGP support is disabled.
    //
    // This error message can be hard to discover.  Do the same
    // comparison, and emit an error message to stderr.
    if rnp_version() < r {
        log!("sequoia-octopus: Thunderbird requires a newer version of the Octopus.");
        log!("sequoia-octopus: We support the API {}.{}.{}, but {}.{}.{} is required.",
             CLAIMED_RNP_VERSION[0], CLAIMED_RNP_VERSION[1],
             CLAIMED_RNP_VERSION[2],
             major, minor, patch);
        log!("sequoia-octopus: Please update, or report this issue to your distribution.");
    }

    r
}

fn rnp_version_for_internal(
    major: u32,
    minor: u32,
    patch: u32,
) -> u32 {
    (major & RNP_VERSION_COMPONENT_MASK) << RNP_VERSION_MAJOR_SHIFT
        | (minor & RNP_VERSION_COMPONENT_MASK) << RNP_VERSION_MINOR_SHIFT
        | ((patch & RNP_VERSION_COMPONENT_MASK) << RNP_VERSION_PATCH_SHIFT)
}

#[no_mangle]
pub unsafe extern "C" fn rnp_version(
) -> u32 {
    rnp_version_for_internal(
        CLAIMED_RNP_VERSION[0],
        CLAIMED_RNP_VERSION[1],
        CLAIMED_RNP_VERSION[2],
    )
}

#[no_mangle]
pub unsafe extern "C" fn rnp_version_string_full() -> *const c_char {
    static VERSION: OnceLock<Vec<u8>> = OnceLock::new();
    VERSION.get_or_init(
        || {
            let mut b = match option_env!("VERGEN_GIT_SHA") {
                Some(git_sha) => {
                    format!(
                        "{}-{}+sequoia-openpgp-{}",
                        env!("CARGO_PKG_VERSION"),
                        git_sha,
                        sequoia_openpgp::VERSION
                    ).into_bytes()
                }
                None => {
                    format!(
                        "{}+sequoia-openpgp-{}",
                        env!("CARGO_PKG_VERSION"),
                        sequoia_openpgp::VERSION
                    ).into_bytes()
                }
            };
            b.push(0); // Sentinel.
            b
        })
        .as_ptr() as *const _
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claimed_version() {
        // Thunderbird compares rnp_version() with the result of
        // rnp_version_for() for the version it requires, and does
        // not use the library if it is older.
        unsafe {
            assert_eq!(rnp_version(), rnp_version_for(0, 18, 1));
            assert_eq!(rnp_version(), 18 << 10 | 1);
            assert!(rnp_version() > rnp_version_for(0, 17, 1));
            assert!(rnp_version() < rnp_version_for(0, 18, 2));
        }
    }
}
