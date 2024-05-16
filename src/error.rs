//! Error handling.

use std::{
    fmt,
    sync::OnceLock,
};

// Like eprintln!
macro_rules! log {
    ($dst:expr $(,)?) => (
        $crate::error::log_internal($dst)
    );
    ($dst:expr, $($arg:tt)*) => (
        $crate::error::log_internal(std::format!($dst, $($arg)*))
    );
}

/// Native RNP result type.
///
/// This is what the RNP functions return.
pub type RnpResult = u32;

/// A wrapped RnpResult.
///
/// This is the type of our status code constants.  By using a type
/// distinct from [`RnpResult`], we force a conversion through
/// [`RnpStatus::epilogue`] (or [`RnpStatus::quiet_epilogue`]).
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct RnpStatus(RnpResult);

impl fmt::UpperHex for RnpStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::UpperHex::fmt(&self.0, f) // Forward.
    }
}

impl fmt::Display for RnpStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            RNP_SUCCESS => f.write_str("RNP_SUCCESS"),
            RNP_ERROR_GENERIC => f.write_str("RNP_ERROR_GENERIC"),
            RNP_ERROR_BAD_FORMAT => f.write_str("RNP_ERROR_BAD_FORMAT"),
            RNP_ERROR_BAD_PARAMETERS => f.write_str("RNP_ERROR_BAD_PARAMETERS"),
            RNP_ERROR_NOT_IMPLEMENTED => f.write_str("RNP_ERROR_NOT_IMPLEMENTED"),
            RNP_ERROR_NOT_SUPPORTED => f.write_str("RNP_ERROR_NOT_SUPPORTED"),
            RNP_ERROR_OUT_OF_MEMORY => f.write_str("RNP_ERROR_OUT_OF_MEMORY"),
            RNP_ERROR_SHORT_BUFFER => f.write_str("RNP_ERROR_SHORT_BUFFER"),
            RNP_ERROR_NULL_POINTER => f.write_str("RNP_ERROR_NULL_POINTER"),
            RNP_ERROR_ACCESS => f.write_str("RNP_ERROR_ACCESS"),
            RNP_ERROR_READ => f.write_str("RNP_ERROR_READ"),
            RNP_ERROR_WRITE => f.write_str("RNP_ERROR_WRITE"),
            RNP_ERROR_BAD_STATE => f.write_str("RNP_ERROR_BAD_STATE"),
            RNP_ERROR_MAC_INVALID => f.write_str("RNP_ERROR_MAC_INVALID"),
            RNP_ERROR_SIGNATURE_INVALID => f.write_str("RNP_ERROR_SIGNATURE_INVALID"),
            RNP_ERROR_KEY_GENERATION => f.write_str("RNP_ERROR_KEY_GENERATION"),
            RNP_ERROR_BAD_PASSWORD => f.write_str("RNP_ERROR_BAD_PASSWORD"),
            RNP_ERROR_KEY_NOT_FOUND => f.write_str("RNP_ERROR_KEY_NOT_FOUND"),
            RNP_ERROR_NO_SUITABLE_KEY => f.write_str("RNP_ERROR_NO_SUITABLE_KEY"),
            RNP_ERROR_DECRYPT_FAILED => f.write_str("RNP_ERROR_DECRYPT_FAILED"),
            RNP_ERROR_RNG => f.write_str("RNP_ERROR_RNG"),
            RNP_ERROR_SIGNING_FAILED => f.write_str("RNP_ERROR_SIGNING_FAILED"),
            RNP_ERROR_NO_SIGNATURES_FOUND => f.write_str("RNP_ERROR_NO_SIGNATURES_FOUND"),
            RNP_ERROR_SIGNATURE_EXPIRED => f.write_str("RNP_ERROR_SIGNATURE_EXPIRED"),
            RNP_ERROR_NOT_ENOUGH_DATA => f.write_str("RNP_ERROR_NOT_ENOUGH_DATA"),
            RNP_ERROR_UNKNOWN_TAG => f.write_str("RNP_ERROR_UNKNOWN_TAG"),
            RNP_ERROR_PACKET_NOT_CONSUMED => f.write_str("RNP_ERROR_PACKET_NOT_CONSUMED"),
            RNP_ERROR_NO_USERID => f.write_str("RNP_ERROR_NO_USERID"),
            RNP_ERROR_EOF => f.write_str("RNP_ERROR_EOF"),
            n => write!(f, "RNP_ERROR_{:08X}", n),
        }
    }
}

impl RnpStatus {
    /// Does this status denote success?
    pub fn success(&self) -> bool {
        self == &RNP_SUCCESS
    }

    /// On failure, prints a trace message in debug builds.
    ///
    /// Returns the [`RnpResult`] suitable as return value for RNP
    /// functions.
    pub fn epilogue(&self, name: &str, args: Vec<String>) -> RnpResult {
        if ! self.success() || call_tracing() {
            if cfg!(debug_assertions) {
                log!("sequoia-octopus: TRACE: {}({}) => {}",
                     name, args.join(", "), self)
            }
        }
        self.quiet_epilogue()
    }

    /// Does not print a trace message.
    ///
    /// Returns the [`RnpResult`] suitable as return value for RNP
    /// functions.
    pub fn quiet_epilogue(&self) -> RnpResult {
        self.0
    }

    #[cfg(test)]
    pub const fn as_u32(&self) -> u32 {
        self.0
    }
}

pub const RNP_SUCCESS: RnpStatus = RnpStatus(0x00000000);

// Common error codes
pub const RNP_ERROR_GENERIC: RnpStatus = RnpStatus(0x10000000);
pub const RNP_ERROR_BAD_FORMAT: RnpStatus = RnpStatus(0x10000001);
pub const RNP_ERROR_BAD_PARAMETERS: RnpStatus = RnpStatus(0x10000002);
pub const RNP_ERROR_NOT_IMPLEMENTED: RnpStatus = RnpStatus(0x10000003);
pub const RNP_ERROR_NOT_SUPPORTED: RnpStatus = RnpStatus(0x10000004);
pub const RNP_ERROR_OUT_OF_MEMORY: RnpStatus = RnpStatus(0x10000005);
pub const RNP_ERROR_SHORT_BUFFER: RnpStatus = RnpStatus(0x10000006);
pub const RNP_ERROR_NULL_POINTER: RnpStatus = RnpStatus(0x10000007);

// Storage
pub const RNP_ERROR_ACCESS: RnpStatus = RnpStatus(0x11000000);
pub const RNP_ERROR_READ: RnpStatus = RnpStatus(0x11000001);
pub const RNP_ERROR_WRITE: RnpStatus = RnpStatus(0x11000002);

// Crypto
pub const RNP_ERROR_BAD_STATE: RnpStatus = RnpStatus(0x12000000);
pub const RNP_ERROR_MAC_INVALID: RnpStatus = RnpStatus(0x12000001);
pub const RNP_ERROR_SIGNATURE_INVALID: RnpStatus = RnpStatus(0x12000002);
pub const RNP_ERROR_KEY_GENERATION: RnpStatus = RnpStatus(0x12000003);
pub const RNP_ERROR_BAD_PASSWORD: RnpStatus = RnpStatus(0x12000004);
pub const RNP_ERROR_KEY_NOT_FOUND: RnpStatus = RnpStatus(0x12000005);
pub const RNP_ERROR_NO_SUITABLE_KEY: RnpStatus = RnpStatus(0x12000006);
pub const RNP_ERROR_DECRYPT_FAILED: RnpStatus = RnpStatus(0x12000007);
pub const RNP_ERROR_RNG: RnpStatus = RnpStatus(0x12000008);
pub const RNP_ERROR_SIGNING_FAILED: RnpStatus = RnpStatus(0x12000009);
pub const RNP_ERROR_NO_SIGNATURES_FOUND: RnpStatus = RnpStatus(0x1200000a);

pub const RNP_ERROR_SIGNATURE_EXPIRED: RnpStatus = RnpStatus(0x1200000b);

// Parsing
pub const RNP_ERROR_NOT_ENOUGH_DATA: RnpStatus = RnpStatus(0x13000000);
pub const RNP_ERROR_UNKNOWN_TAG: RnpStatus = RnpStatus(0x13000001);
pub const RNP_ERROR_PACKET_NOT_CONSUMED: RnpStatus = RnpStatus(0x13000002);
pub const RNP_ERROR_NO_USERID: RnpStatus = RnpStatus(0x13000003);
pub const RNP_ERROR_EOF: RnpStatus = RnpStatus(0x13000004);

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

impl From<Error> for RnpStatus {
    fn from(e: Error) -> RnpStatus {
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
pub type Result<T> = std::result::Result<T, RnpStatus>;

//#[cfg(windows)]
pub fn log_internal<T: AsRef<str>>(text: T) {
    let text = format!("{}: {}", chrono::offset::Utc::now(), text.as_ref());

    if cfg!(windows) {
        // Save messages to a log file in the current profile's
        // directory (.../.thunderbird/$PROFILE/octopus.log).
        //
        // This is a bit hairy, because the code needs to be
        // reentrant: to initialize the logger's file description, we
        // need the location of the current profile, but finding that
        // location also uses the logging functionality.
        //
        // To break this cycle, if the logger is locked, rather than
        // wait for the lock, we simply enqueue the message in a
        // channel.  Then when we actually have the lock, we first
        // print any messages queued in the channel and then print out
        // our own message.

        use std::fs::File;
        use std::io::Write;
        use std::ops::DerefMut;
        use std::sync::Mutex;
        use std::sync::mpsc::channel;
        use std::sync::mpsc::Sender;
        use std::sync::mpsc::Receiver;

        use crate::tbprofile::TBProfile;

        struct State {
            sender: Mutex<Sender<String>>,
            // If None, the file has not yet been opened.
            output: Mutex<Option<(Receiver<String>, Option<File>)>>,
        }

        static LOGGER: OnceLock<State> = OnceLock::new();
        let logger = LOGGER.get_or_init(
            || {
                let (sender, receiver) = channel();

                State {
                    sender: Mutex::new(sender),
                    output: Mutex::new(Some((receiver, None))),
                }
            });

        let mut logged = false;
        if let Ok(mut guard) = logger.output.try_lock() {
            // We got the lock.

            // If initialization fails, we set output to None.  But
            // since it is borrowed, we need to delay it.
            let mut kill = false;
            if let Some((receiver, ref mut ofd)) = guard.deref_mut() {
                if ofd.is_none() {
                    // We need to initialize the file descriptor.

                    if let Some(tbpath) = TBProfile::path() {
                        // We found a TB profile.  Let's try to open the
                        // log file.
                        let path = tbpath.join("octopus.log");
                        if let Ok(fd) = File::create(&path) {
                            *ofd = Some(fd);
                            eprintln!("Logging to {:?}", path);
                        } else {
                            // We failed to open the file :/
                            kill = true;
                        }
                    } else {
                        // We failed to find the TBProfile :/
                        kill = true;
                    }
                }

                if let Some(fd) = ofd {
                    // First, drain the message queue.
                    while let Ok(text) = receiver.try_recv() {
                        let _ = writeln!(fd, "{}", text);
                    }
                    // Then print our own message.
                    let _ = writeln!(fd, "{}", text);
                    let _ = fd.flush();
                    logged = true;
                }
            }

            if kill {
                *guard = None;
            }
        } else {
            // Locked.  Enqueue the message for later.  If we can't
            // send, it means initialization failed so just ignore.
            if let Ok(_) = logger.sender.lock().unwrap().send(text.clone()) {
                logged = true;
            }
        }

        if ! logged {
            // Something went wrong.  Just send it to stderr, which
            // probably won't do anything on Windows, but if we are
            // debugging on another platform, that will be useful.
            eprintln!("{}", text);
        }
    } else {
        // Just write to stderr.
        eprintln!("{}", text);
    }
}

pub fn full_tracing() -> bool {
    static FULL_TRACING: OnceLock<bool> = OnceLock::new();
    *FULL_TRACING.get_or_init(
        || std::env::var("SEQUOIA_OCTOPUS_TRACING")
            .map(|t| t == "full")
            .unwrap_or(false))
}

pub fn call_tracing() -> bool {
    static FULL_TRACING: OnceLock<bool> = OnceLock::new();
    *FULL_TRACING.get_or_init(
        || std::env::var("SEQUOIA_OCTOPUS_TRACING")
            .map(|t| t == "call")
            .unwrap_or(false))
}

macro_rules! rnp_function {
    ( $fn_name: path, $TRACE: expr ) => {
        #[allow(dead_code, unused_mut, unused_variables)]
        let mut args: Vec<String> = Vec::new();

        #[allow(unused_macros)]
        macro_rules! arg {
            ($arg: expr) => {
                args.push(format!("{:?}", $arg))
            };
        }

        #[allow(unused_macros)]
        macro_rules! rnp_return_status {
            ($status: expr) => {
                return $status.epilogue(stringify!($fn_name), args)
            };
        }

        #[allow(unused_macros)]
        macro_rules! rnp_success {
            () => {
                rnp_return_status!(RNP_SUCCESS)
            };
        }

        #[allow(unused_macros)]
        macro_rules! _trace {
            ( $msg: expr ) => {
                if $TRACE && crate::error::full_tracing() {
                    log!("sequoia-octopus: TRACE: {}: {}",
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
        macro_rules! warn {
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
                log!(concat!("sequoia-octopus: ",
                                  stringify!($fn_name),
                                  ": ", $fmt));
            };
            ( $fmt: expr, $a: expr ) => {
                log!(concat!("sequoia-octopus: ",
                             stringify!($fn_name),
                             ": ", $fmt),
                     $a);
            };
            ( $fmt: expr, $a: expr, $b: expr ) => {
                log!(concat!("sequoia-octopus: ",
                             stringify!($fn_name),
                             ": ", $fmt),
                     $a, $b);
            };
            ( $fmt: expr, $a: expr, $b: expr, $c: expr ) => {
                log!(concat!("sequoia-octopus: ",
                             stringify!($fn_name),
                             ": ", $fmt),
                     $a, $b, $c);
            };
        }

        #[allow(unused_macros)]
        macro_rules! assert_ptr_int {
            ( $param: expr ) => {
                if $param.is_null() {
                    warn!("parameter {:?} is null", stringify!($param));
                    rnp_return_status!(RNP_ERROR_NULL_POINTER);
                }
            };
        }

        #[allow(unused_macros)]
        macro_rules! assert_ptr {
            ( $param: expr ) => {
                arg!($param);
                assert_ptr_int!($param);
            };
        }

        #[allow(unused_macros)]
        macro_rules! assert_ptr_ref {
            ( $param: expr ) => {{
                assert_ptr!($param);
                &*$param
            }};
        }

        #[allow(unused_macros)]
        macro_rules! assert_ptr_mut {
            ( $param: expr ) => {{
                assert_ptr!($param);
                &mut *$param
            }};
        }

        #[allow(unused_macros)]
        macro_rules! assert_str {
            ( $param: expr ) => {
                assert_str!($param, false)
            };
            ( confidential => $param: expr ) => {
                assert_str!($param, true)
            };
            ( $param: expr, $confidential: expr ) => {{
                assert_ptr_int!($param);
                match std::ffi::CStr::from_ptr($param).to_str() {
                    Ok(s) => {
                        if $confidential {
                            arg!("<REDACTED>")
                        } else {
                            arg!(s);
                        }
                        s
                    },
                    Err(e) => {
                        warn!("parameter {:?} is not UTF8: {}",
                              stringify!($param), e);
                        rnp_return_status!(RNP_ERROR_BAD_PARAMETERS);
                    }
                }
            }};
        }

        #[allow(unused_macros)]
        macro_rules! rnp_try {
            ( $result: expr ) => {
                match $result {
                    Ok(v) => v,
                    Err(e) => rnp_return_status!(e),
                }
            };
        }

        #[allow(unused_macros)]
        macro_rules! rnp_try_or {
            ( $result: expr, $fail_with: expr ) => {
                match $result {
                    Ok(v) => v,
                    Err(_) => {
                        let s: RnpStatus = $fail_with;
                        rnp_return_status!(s);
                    },
                }
            };
        }

        #[allow(unused_macros)]
        macro_rules! rnp_return {
            ( $expr: expr ) => {
                rnp_return_status!(if let Err(e) = $expr {
                    warn!("{}", e);
                    if let Ok(e) = e.downcast::<crate::error::Error>() {
                        e.into()
                    } else {
                        RNP_ERROR_GENERIC
                    }
                } else {
                    t!("Leaving function: success");
                    RNP_SUCCESS
                })
            };
        }

        #[allow(unused_macros)]
        macro_rules! thunderbird_workaround {
            () => {{
                if crate::THUNDERBIRD_WORKAROUND {
                    t!("Thunderbird-specific workaround in {}:{}",
                       file!(), line!());
                }
                crate::THUNDERBIRD_WORKAROUND
            }};
        }
    };
}

macro_rules! global_warn {
    ( $fmt: expr $(, $a: expr )* ) => {
        log!(concat!("sequoia-octopus: ", $fmt)
             $(, $a )*)
    };
}

macro_rules! global_rnp_try_or {
    ( $result: expr, $fail_with: expr ) => {
        match $result {
            Ok(v) => v,
            Err(e) => {
                global_warn!("{}", e);
                return $fail_with;
            },
        }
    };
}
