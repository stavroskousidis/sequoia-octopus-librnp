use libc::{
    c_char
};

const CLAIMED_RNP_VERSION: [u32; 3] = [0, 15, 2];

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
    (major & RNP_VERSION_COMPONENT_MASK) << RNP_VERSION_MAJOR_SHIFT
        | (minor & RNP_VERSION_COMPONENT_MASK) << RNP_VERSION_MINOR_SHIFT
        | ((patch & RNP_VERSION_COMPONENT_MASK) << RNP_VERSION_PATCH_SHIFT)
}

#[no_mangle]
pub unsafe extern "C" fn rnp_version(
) -> u32 {
    rnp_version_for(
        CLAIMED_RNP_VERSION[0],
        CLAIMED_RNP_VERSION[1],
        CLAIMED_RNP_VERSION[2],
    )
}


#[no_mangle]
pub unsafe extern "C" fn rnp_version_string_full() -> *const c_char {
    lazy_static::lazy_static! {
        static ref VERSION: Vec<u8> = {
            let mut b = format!("{}-{}+sequoia-openpgp-{}",
                                env!("CARGO_PKG_VERSION"),
                                env!("VERGEN_GIT_SHA_SHORT"),
                                sequoia_openpgp::VERSION)
                .into_bytes();
            b.push(0); // Sentinel.
            b
        };
    };

    VERSION.as_ptr() as *const _
}
