//! Buffer management.
//!
//! RNP hands out buffers to both zero-terminated strings and binary
//! data, and we need to be able to deallocate both with
//! `rnp_buffer_destroy`.
//!
//! Our strategy is to use libc's allocator and let it keep track of
//! the size of the allocations.

use std::{
    ptr::{
        copy_nonoverlapping,
    },
};

use libc::{
    malloc,
    free,
    c_char,
    c_void,
};

/// Copies a Rust string to a buffer, adding a terminating zero.
pub fn str_to_rnp_buffer<S: AsRef<str>>(s: S) -> *mut c_char {
    let s = s.as_ref();
    let bytes = s.as_bytes();
    unsafe {
        let buf = malloc(bytes.len() + 1);
        copy_nonoverlapping(bytes.as_ptr(), buf as *mut _, bytes.len());
        *((buf as *mut u8).add(bytes.len())) = 0; // Terminate.
        buf as *mut c_char
    }
}

/// Copies a C string to a buffer, adding a terminating zero.
///
/// Fails on embedded zeros.
pub fn c_str_to_rnp_buffer<S: AsRef<[u8]>>(s: S) -> Option<*mut c_char> {
    let bytes = s.as_ref();
    if bytes.iter().any(|b| *b == 0) {
        return None;
    }

    unsafe {
        let buf = malloc(bytes.len() + 1);
        copy_nonoverlapping(bytes.as_ptr(), buf as *mut _, bytes.len());
        *((buf as *mut u8).add(bytes.len())) = 0; // Terminate.
        Some(buf as *mut c_char)
    }
}

/// Copies a C string to a buffer, adding a terminating zero.
///
/// Replaces embedded zeros with '_'.
pub fn c_str_to_rnp_buffer_lossy<S: AsRef<[u8]>>(s: S) -> *mut c_char {
    let bytes = s.as_ref();
    unsafe {
        let buf = malloc(bytes.len() + 1);
        copy_nonoverlapping(bytes.as_ptr(), buf as *mut _, bytes.len());

        // Replace embedded zeros.
        let bytes_mut = std::slice::from_raw_parts_mut(buf as *mut u8,
                                                       bytes.len());
        bytes_mut.iter_mut().for_each(|b| if *b == 0 { *b = b'_' });

        *((buf as *mut u8).add(bytes.len())) = 0; // Terminate.
        buf as *mut c_char
    }
}

/// Copies a byte slice to a buffer.
pub fn bytes_to_rnp_buffer<B: AsRef<[u8]>>(b: B) -> *mut u8 {
    let bytes = b.as_ref();
    unsafe {
        let buf = malloc(bytes.len());
        copy_nonoverlapping(bytes.as_ptr(), buf as *mut _, bytes.len());
        buf as *mut _
    }
}

#[no_mangle] pub unsafe extern "C"
fn rnp_buffer_destroy(ptr: *mut c_void) {
    free(ptr);
}
