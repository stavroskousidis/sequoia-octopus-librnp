//! Contains stubbed out functions.
//!
//! This module contains functions that are bound in RNPlib.jsm but
//! are not actually used.

// These are bound in RNPlib.jsm but not actually used.
macro_rules! unused {
    ($s: ident) => {
        /// This function is a stub.
        ///
        /// This function is bound in RNPlib.jsm but is not actually used.
        #[no_mangle] pub extern "C"
        fn $s() -> crate::RnpResult {
            warn!("previously unused function is used: {}", stringify!($s));
            crate::error::RNP_ERROR_NOT_IMPLEMENTED
        }
    };
}

unused!(rnp_guess_contents);
unused!(rnp_decrypt);
unused!(rnp_symenc_get_aead_alg);
unused!(rnp_symenc_get_cipher);
unused!(rnp_symenc_get_hash_alg);
unused!(rnp_symenc_get_s2k_iterations);
unused!(rnp_symenc_get_s2k_type);
