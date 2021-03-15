use libc::{
    c_char,
};

#[no_mangle] pub unsafe extern "C"
fn rnp_version_string_full() -> *const c_char {
    lazy_static::lazy_static! {
        static ref VERSION: Vec<u8> = {
            let mut b = format!("{}+sequoia-openpgp-{}",
                                env!("CARGO_PKG_VERSION"),
                                sequoia_openpgp::VERSION)
                .into_bytes();
            b.push(0); // Sentinel.
            b
        };
    };

    VERSION.as_ptr() as *const _
}
