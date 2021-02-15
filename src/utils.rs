use std::{
    path::PathBuf,
    ffi::CStr,
};

use libc::{
    c_char,
};

use crate::{
    error::*,
};

/// Converts a C string to a &str.
///
/// If the given string is not encoded using UTF-8, this will fail
/// with RNP_ERROR_BAD_PARAMETERS.
pub fn cstr_to_str<'a>(path: *const c_char)
                       -> Result<&'a str> {
    if let Ok(s) = unsafe { CStr::from_ptr(path) }.to_str() {
        Ok(s)
    } else {
        Err(RNP_ERROR_BAD_PARAMETERS)
    }
}

/// Converts a C string to a PathBuf.
///
/// XXX: Currently, if the given string is not encoded using UTF-8,
/// this will fail with RNP_ERROR_BAD_PARAMETERS.
pub fn cstr_to_pathbuf(path: *const c_char)
                       -> Result<PathBuf> {
    if let Ok(p) = unsafe { CStr::from_ptr(path) }.to_str() {
        Ok(p.into())
    } else {
        Err(RNP_ERROR_BAD_PARAMETERS)
    }
}
