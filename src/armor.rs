use sequoia_openpgp as openpgp;
use openpgp::{
    armor::{Reader, ReaderMode},
};

use crate::{
    RnpResult,
    RnpInput,
    RnpOutput,
    error::*,
};

#[no_mangle] pub unsafe extern "C"
fn rnp_dearmor<'a>(input: *mut RnpInput,
                   output: *mut RnpOutput<'a>)
                   -> RnpResult
{
    rnp_function!(rnp_dearmor, crate::TRACE);
    let input = assert_ptr_mut!(input);
    let output = assert_ptr_mut!(output);

    let mut reader =
        Reader::from_reader(input, ReaderMode::Tolerant(None));
    rnp_try_or!(std::io::copy(&mut reader, output), RNP_ERROR_BAD_FORMAT);

    rnp_success!()
}
