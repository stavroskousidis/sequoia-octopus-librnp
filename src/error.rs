//! Error handling.

/// Native RNP result type.
pub type RnpResult = u32;
pub const RNP_SUCCESS: RnpResult = 0x00000000;

// Common error codes
pub const RNP_ERROR_GENERIC: RnpResult = 0x10000000;
pub const RNP_ERROR_BAD_FORMAT: RnpResult = 0x10000001;
pub const RNP_ERROR_BAD_PARAMETERS: RnpResult = 0x10000002;
pub const RNP_ERROR_NOT_IMPLEMENTED: RnpResult = 0x10000003;
pub const RNP_ERROR_NOT_SUPPORTED: RnpResult = 0x10000004;
pub const RNP_ERROR_OUT_OF_MEMORY: RnpResult = 0x10000005;
pub const RNP_ERROR_SHORT_BUFFER: RnpResult = 0x10000006;
pub const RNP_ERROR_NULL_POINTER: RnpResult = 0x10000007;

// Storage
pub const RNP_ERROR_ACCESS: RnpResult = 0x11000000;
pub const RNP_ERROR_READ: RnpResult = 0x11000001;
pub const RNP_ERROR_WRITE: RnpResult = 0x11000002;

// Crypto
pub const RNP_ERROR_BAD_STATE: RnpResult = 0x12000000;
pub const RNP_ERROR_MAC_INVALID: RnpResult = 0x12000001;
pub const RNP_ERROR_SIGNATURE_INVALID: RnpResult = 0x12000002;
pub const RNP_ERROR_KEY_GENERATION: RnpResult = 0x12000003;
pub const RNP_ERROR_BAD_PASSWORD: RnpResult = 0x12000004;
pub const RNP_ERROR_KEY_NOT_FOUND: RnpResult = 0x12000005;
pub const RNP_ERROR_NO_SUITABLE_KEY: RnpResult = 0x12000006;
pub const RNP_ERROR_DECRYPT_FAILED: RnpResult = 0x12000007;
pub const RNP_ERROR_RNG: RnpResult = 0x12000008;
pub const RNP_ERROR_SIGNING_FAILED: RnpResult = 0x12000009;
pub const RNP_ERROR_NO_SIGNATURES_FOUND: RnpResult = 0x1200000a;

pub const RNP_ERROR_SIGNATURE_EXPIRED: RnpResult = 0x1200000b;

// Parsing
pub const RNP_ERROR_NOT_ENOUGH_DATA: RnpResult = 0x13000000;
pub const RNP_ERROR_UNKNOWN_TAG: RnpResult = 0x13000001;
pub const RNP_ERROR_PACKET_NOT_CONSUMED: RnpResult = 0x13000002;
pub const RNP_ERROR_NO_USERID: RnpResult = 0x13000003;
pub const RNP_ERROR_EOF: RnpResult = 0x13000004;

/// Rustic-errors resembling the native RNP errors.
///
/// These errors can be used in functions returning standard errors to
/// return a specific native RNP error.
///
/// # Examples
///
/// ```rust,no-compile
/// #[no_mangle] pub unsafe extern "C"
/// fn rnp_something(rnp_key: *mut RnpKey) -> RnpResult {
///     rnp_function!(rnp_key_protect, crate::TRACE);
///
///     let f = || -> openpgp::Result<()> {
///         Err(Error::NotImplemented)
///     };
///
///     rnp_return!(f())
/// }
/// ```
#[derive(thiserror::Error, Debug, Clone)]
pub enum Error {
    #[error("Generic")]
    Generic,
    #[error("BadFormat")]
    BadFormat,
    #[error("BadParameters")]
    BadParameters,
    #[error("NotImplemented")]
    NotImplemented,
    #[error("NotSupported")]
    NotSupported,
    #[error("OutOfMemory")]
    OutOfMemory,
    #[error("ShortBuffer")]
    ShortBuffer,
    #[error("NullPointer")]
    NullPointer,
    #[error("Access")]
    Access,
    #[error("Read")]
    Read,
    #[error("Write")]
    Write,
    #[error("BadState")]
    BadState,
    #[error("MacInvalid")]
    MacInvalid,
    #[error("SignatureInvalid")]
    SignatureInvalid,
    #[error("KeyGeneration")]
    KeyGeneration,
    #[error("BadPassword")]
    BadPassword,
    #[error("KeyNotFound")]
    KeyNotFound,
    #[error("NoSuitableKey")]
    NoSuitableKey,
    #[error("DecryptFailed")]
    DecryptFailed,
    #[error("RNG")]
    RNG,
    #[error("SigningFailed")]
    SigningFailed,
    #[error("NoSignaturesFound")]
    NoSignaturesFound,
    #[error("SignatureExpired")]
    SignatureExpired,
    #[error("NotEnoughData")]
    NotEnoughData,
    #[error("UnknownTag")]
    UnknownTag,
    #[error("PacketNotConsumed")]
    PacketNotConsumed,
    #[error("NoUserID")]
    NoUserID,
    #[error("EOF")]
    EOF,
}

impl From<Error> for RnpResult {
    fn from(e: Error) -> RnpResult {
        use Error::*;
        match e {
            Generic => RNP_ERROR_GENERIC,
            BadFormat => RNP_ERROR_BAD_FORMAT,
            BadParameters => RNP_ERROR_BAD_PARAMETERS,
            NotImplemented => RNP_ERROR_NOT_IMPLEMENTED,
            NotSupported => RNP_ERROR_NOT_SUPPORTED,
            OutOfMemory => RNP_ERROR_OUT_OF_MEMORY,
            ShortBuffer => RNP_ERROR_SHORT_BUFFER,
            NullPointer => RNP_ERROR_NULL_POINTER,
            Access => RNP_ERROR_ACCESS,
            Read => RNP_ERROR_READ,
            Write => RNP_ERROR_WRITE,
            BadState => RNP_ERROR_BAD_STATE,
            MacInvalid => RNP_ERROR_MAC_INVALID,
            SignatureInvalid => RNP_ERROR_SIGNATURE_INVALID,
            KeyGeneration => RNP_ERROR_KEY_GENERATION,
            BadPassword => RNP_ERROR_BAD_PASSWORD,
            KeyNotFound => RNP_ERROR_KEY_NOT_FOUND,
            NoSuitableKey => RNP_ERROR_NO_SUITABLE_KEY,
            DecryptFailed => RNP_ERROR_DECRYPT_FAILED,
            RNG => RNP_ERROR_RNG,
            SigningFailed => RNP_ERROR_SIGNING_FAILED,
            NoSignaturesFound => RNP_ERROR_NO_SIGNATURES_FOUND,
            SignatureExpired => RNP_ERROR_SIGNATURE_EXPIRED,
            NotEnoughData => RNP_ERROR_NOT_ENOUGH_DATA,
            UnknownTag => RNP_ERROR_UNKNOWN_TAG,
            PacketNotConsumed => RNP_ERROR_PACKET_NOT_CONSUMED,
            NoUserID => RNP_ERROR_NO_USERID,
            EOF => RNP_ERROR_EOF,
        }
    }
}


// Used by helper functions.
pub type Result<T> = std::result::Result<T, RnpResult>;

macro_rules! rnp_function {
    ( $fn_name: path, $TRACE: expr ) => {
        #[allow(unused_macros)]
        macro_rules! _trace {
            ( $msg: expr ) => {
                if $TRACE {
                    eprintln!("sequoia-octopus: TRACE: {}: {}",
                              stringify!($fn_name), $msg);
                }
            };
        }

        // Currently, Rust doesn't support $( ... ) in a nested
        // macro's definition.  See:
        // https://users.rust-lang.org/t/nested-macros-issue/8348/2
        #[allow(unused_macros)]
        macro_rules! t {
            ( $fmt:expr ) =>
            { _trace!( $fmt) };
            ( $fmt:expr, $a:expr ) =>
            { _trace!( format!($fmt, $a)) };
            ( $fmt:expr, $a:expr, $b:expr ) =>
            { _trace!( format!($fmt, $a, $b)) };
            ( $fmt:expr, $a:expr, $b:expr, $c:expr ) =>
            { _trace!( format!($fmt, $a, $b, $c)) };
            ( $fmt:expr, $a:expr, $b:expr, $c:expr, $d:expr ) =>
            { _trace!( format!($fmt, $a, $b, $c, $d)) };
            ( $fmt:expr, $a:expr, $b:expr, $c:expr, $d:expr, $e:expr ) =>
            { _trace!( format!($fmt, $a, $b, $c, $d, $e)) };
            ( $fmt:expr, $a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:expr ) =>
            { _trace!( format!($fmt, $a, $b, $c, $d, $e, $f)) };
            ( $fmt:expr, $a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:expr, $g:expr ) =>
            { _trace!( format!($fmt, $a, $b, $c, $d, $e, $f, $g)) };
            ( $fmt:expr, $a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:expr, $g:expr, $h:expr ) =>
            { _trace!( format!($fmt, $a, $b, $c, $d, $e, $f, $g, $h)) };
            ( $fmt:expr, $a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:expr, $g:expr, $h:expr, $i:expr ) =>
            { _trace!( format!($fmt, $a, $b, $c, $d, $e, $f, $g, $h, $i)) };
            ( $fmt:expr, $a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:expr, $g:expr, $h:expr, $i:expr, $j:expr ) =>
            { _trace!( format!($fmt, $a, $b, $c, $d, $e, $f, $g, $h, $i, $j)) };
            ( $fmt:expr, $a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:expr, $g:expr, $h:expr, $i:expr, $j:expr, $k:expr ) =>
            { _trace!( format!($fmt, $a, $b, $c, $d, $e, $f, $g, $h, $i, $j, $k)) };
        }

        #[allow(unused_macros)]
        macro_rules! _warn {
            // Currently, Rust doesn't support $( ... ) in a nested
            // macro's definition.  See:
            // https://users.rust-lang.org/t/nested-macros-issue/8348/2
            //
            //( $fmt: expr $(, $a: expr )* ) => {
            //    eprintln!(concat!("sequoia-octopus: ",
            //                      stringify!($fn_name),
            //                      ": ", $fmt)
            //              $(, $a )*);
            //};
            ( $fmt: expr ) => {
                eprintln!(concat!("sequoia-octopus: ",
                                  stringify!($fn_name),
                                  ": ", $fmt));
            };
            ( $fmt: expr, $a: expr ) => {
                eprintln!(concat!("sequoia-octopus: ",
                                  stringify!($fn_name),
                                  ": ", $fmt),
                          $a);
            };
            ( $fmt: expr, $a: expr, $b: expr ) => {
                eprintln!(concat!("sequoia-octopus: ",
                                  stringify!($fn_name),
                                  ": ", $fmt),
                          $a, $b);
            };
        }

        #[allow(unused_macros)]
        macro_rules! _assert_ptr {
            ( $param: expr ) => {
                if $param.is_null() {
                    _warn!("parameter {:?} is null", stringify!($param));
                    return RNP_ERROR_NULL_POINTER;
                }
            };
        }

        #[allow(unused_macros)]
        macro_rules! assert_ptr_ref {
            ( $param: expr ) => {{
                _assert_ptr!($param);
                &*$param
            }};
        }

        #[allow(unused_macros)]
        macro_rules! assert_ptr_mut {
            ( $param: expr ) => {{
                _assert_ptr!($param);
                &mut *$param
            }};
        }

        #[allow(unused_macros)]
        macro_rules! rnp_return {
            ( $expr: expr ) => {
                if let Err(e) = $expr {
                    _warn!("{}", e);
                    if let Ok(e) = e.downcast::<crate::error::Error>() {
                        e.into()
                    } else {
                        RNP_ERROR_GENERIC
                    }
                } else {
                    t!("Leaving function: success");
                    RNP_SUCCESS
                }
            };
        }

        t!("Entering function");
    };
}

macro_rules! warn {
    ( $fmt: expr $(, $a: expr )* ) => {
        eprintln!(concat!("sequoia-octopus: ", $fmt)
                  $(, $a )*);
    };
}

macro_rules! assert_ptr {
    ( $param: expr ) => {
        if $param.is_null() {
            warn!("{}:{}: parameter {:?} is null",
                  file!(), line!(), stringify!($param));
            return RNP_ERROR_NULL_POINTER;
        }
    };
}

macro_rules! rnp_try {
    ( $result: expr ) => {
        match $result {
            Ok(v) => v,
            Err(e) => return e,
        }
    };
}

macro_rules! rnp_try_or {
    ( $result: expr, $fail_with: expr ) => {
        match $result {
            Ok(v) => v,
            Err(e) => {
                warn!("{}", e);
                return $fail_with;
            },
        }
    };
}
