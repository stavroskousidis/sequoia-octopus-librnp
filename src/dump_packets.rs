//! Implements rnp_dump_packets_to_output.

use crate::{
    RnpInput,
    RnpOutput,
    RnpResult,
    error::*,
};

// XXX: Copied from sequoia-sq.
pub mod dump;

const RNP_DUMP_MPI: u32 =  1 << 0;
const RNP_DUMP_RAW: u32 =  1 << 1;
const RNP_DUMP_GRIP: u32 = 1 << 2;

#[no_mangle] pub unsafe extern "C"
fn rnp_dump_packets_to_output(input: *mut RnpInput,
                              output: *mut RnpOutput,
                              flags: u32)
                             -> RnpResult
{
    rnp_function!(rnp_dump_packets_to_output, crate::TRACE);
    let input = assert_ptr_mut!(input);
    let output = assert_ptr_mut!(output);
    let dump_mpis = flags & RNP_DUMP_MPI > 0;
    let dump_hex = flags & RNP_DUMP_RAW > 0;
    // Key grips are a proprietary GnuPG extension.  No.
    let _dump_grip = flags & RNP_DUMP_GRIP > 0;

    rnp_try_or!(dump::dump(input, output, dump_mpis, dump_hex, None, None),
                RNP_ERROR_GENERIC);
    rnp_success!()
}
