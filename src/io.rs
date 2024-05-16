use std::{
    io,
    fmt,
    fs::File,
    path::PathBuf,
};

use sequoia_openpgp as openpgp;
use openpgp::{
    armor,
};

use super::*;

pub enum RnpInput {
    Ref(io::Cursor<&'static [u8]>),
    Buf(io::Cursor<Vec<u8>>),
    File(PathBuf, File),
}

impl fmt::Debug for RnpInput {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            RnpInput::Ref(c) => {
                f.debug_struct("RnpInput")
                    .field("Ref", &c.get_ref().len())
                    .finish()
            }
            RnpInput::Buf(c) => {
                f.debug_struct("RnpInput")
                    .field("Vec", &c.get_ref().len())
                    .finish()
            }
            RnpInput::File(p, _) => {
                f.debug_struct("RnpInput")
                    .field("File", p)
                    .finish()
            }
        }
    }
}

pub enum RnpOutput<'a> {
    Buf((Vec<u8>, Option<usize>)),
    File(File),
    Armorer(Option<armor::Writer<&'a mut RnpOutput<'a>>>)
}

impl RnpInput {
    /// Returns the input's file size, if it can be determined.
    pub fn size(&self) -> openpgp::Result<u64> {
        match self {
            RnpInput::Ref(c) => Ok(c.get_ref().len() as u64),
            RnpInput::Buf(c) => Ok(c.get_ref().len() as u64),
            RnpInput::File(_, fp) => {
                Ok(fp.metadata()?.len())
            }
        }
    }

    /// Tries to clone this input.
    ///
    /// This may fail if the input refers to a file and reopening the
    /// file fails.
    ///
    /// The input stream is rewound for consistency with the reopened
    /// file.
    pub fn try_clone(&self) -> io::Result<Self> {
        use io::Seek;
        match self {
            RnpInput::Ref(c) => {
                let mut c = c.clone();
                c.seek(io::SeekFrom::Start(0))?;
                Ok(RnpInput::Ref(c))
            },
            RnpInput::Buf(c) => {
                let mut c = c.clone();
                c.seek(io::SeekFrom::Start(0))?;
                Ok(RnpInput::Buf(c))
            },
            RnpInput::File(p, _) =>
                Ok(RnpInput::File(p.clone(), File::open(p)?)),
        }
    }

    /// Copies referenced data, if necessary.
    pub fn to_owned(self) -> Self {
        if let RnpInput::Ref(c) = self {
            let p = c.position();
            let mut owned = io::Cursor::new(c.into_inner().to_vec());
            owned.set_position(p);
            RnpInput::Buf(owned)
        } else {
            self
        }
    }
}

#[no_mangle] pub unsafe extern "C"
fn rnp_input_from_path(input: *mut *mut RnpInput,
                       path: *const c_char)
                       -> RnpResult {
    rnp_function!(rnp_input_from_path, crate::TRACE);
    assert_ptr!(input);
    let path = assert_str!(path).into();

    rnp_return_status!(if let Ok(f) = File::open(&path) {
        *input = Box::into_raw(Box::new(
            RnpInput::File(path, f)
        ));
        RNP_SUCCESS
    } else {
        RNP_ERROR_ACCESS
    })
}

#[no_mangle] pub unsafe extern "C"
fn rnp_input_from_memory(input: *mut *mut RnpInput,
                         buf: *const u8,
                         len: size_t,
                         do_copy: bool)
                         -> RnpResult {
    rnp_function!(rnp_input_from_memory, crate::TRACE);
    assert_ptr!(input);
    assert_ptr!(buf);
    arg!(len);
    arg!(do_copy);

    let data = std::slice::from_raw_parts(buf, len);
    *input = Box::into_raw(Box::new(if do_copy {
        RnpInput::Buf(io::Cursor::new(data.to_vec()))
    } else {
        RnpInput::Ref(io::Cursor::new(data))
    }));
    rnp_success!()
}

#[no_mangle] pub unsafe extern "C"
fn rnp_input_destroy(input: *mut RnpInput) -> RnpResult {
    rnp_function!(rnp_input_destroy, crate::TRACE);
    arg!(input);

    if ! input.is_null() {
        drop(Box::from_raw(input));
    }
    rnp_success!()
}

impl io::Read for RnpInput {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            RnpInput::Ref(c) => c.read(buf),
            RnpInput::Buf(c) => c.read(buf),
            RnpInput::File(_, f) => f.read(buf),
        }
    }
}

#[no_mangle] pub unsafe extern "C"
fn rnp_output_to_path(output: *mut *mut RnpOutput,
                      path: *const c_char)
                      -> RnpResult {
    rnp_function!(rnp_output_to_path, crate::TRACE);
    let path = rnp_try!(cstr_to_pathbuf(path));

    let f = match File::create(&path) {
        Ok(f) => f,
        Err(e) => {
            log!("sequoia-octopus: failed to create {:?}: {}",
                 path, e);
            rnp_return_status!(RNP_ERROR_ACCESS);
        },
    };

    *output = Box::into_raw(Box::new(
        RnpOutput::File(f)
    ));
    rnp_success!()
}

#[no_mangle] pub unsafe extern "C"
fn rnp_output_to_memory(output: *mut *mut RnpOutput,
                        max_alloc: size_t)
                        -> RnpResult {
    rnp_function!(rnp_output_to_memory, crate::TRACE);
    assert_ptr!(output);
    arg!(max_alloc);

    *output = Box::into_raw(Box::new(
        RnpOutput::Buf((Vec::new(),
                        if max_alloc == 0 { None } else { Some(max_alloc) }))
    ));
    rnp_success!()
}

#[no_mangle] pub unsafe extern "C"
fn rnp_output_memory_get_buf(output: *const RnpOutput,
                             buf: *mut *mut u8,
                             len: *mut size_t,
                             do_copy: bool)
                             -> RnpResult {
    rnp_function!(rnp_output_memory_get_buf, crate::TRACE);
    let output = assert_ptr_ref!(output);
    let buf = assert_ptr_mut!(buf);
    let len = assert_ptr_mut!(len);
    arg!(do_copy);

    rnp_return_status!(if let RnpOutput::Buf((bytes, _)) = output {
        if do_copy {
            *buf = bytes_to_rnp_buffer(bytes);
            *len = bytes.len();
        } else {
            *buf = bytes.as_ptr() as *mut _;
            *len = bytes.len();
        }
        RNP_SUCCESS
    } else {
        RNP_ERROR_GENERIC
    })
}


#[no_mangle] pub unsafe extern "C"
fn rnp_output_to_armor<'a>(sink: *mut RnpOutput<'a>,
                           output: *mut *mut RnpOutput<'a>,
                           kind: *const c_char)
                           -> RnpResult {
    rnp_function!(rnp_output_to_armor, crate::TRACE);
    let sink = assert_ptr_mut!(sink);
    let output = assert_ptr_mut!(output);

    if kind.is_null() {
        arg!(kind);
        warn!("rnp_output_to_armor: type detection not implemented");
        rnp_return_status!(RNP_ERROR_NOT_IMPLEMENTED); // XXX
    }
    assert_str!(kind); // XXX
    let kind = rnp_try!(armor::Kind::from_rnp_id(kind));

    *output = match armor::Writer::new(&mut *sink, kind) {
        Ok(v) => Box::into_raw(Box::new(RnpOutput::Armorer(Some(v)))),
        Err(e) => {
            warn!("rnp_output_to_armor: {}", e);
            rnp_return_status!(RNP_ERROR_WRITE);
        },
    };

    rnp_success!()
}

#[no_mangle] pub unsafe extern "C"
fn rnp_output_armor_set_line_length<'a>(output: *mut RnpOutput<'a>,
                                        llen: size_t)
                                        -> RnpResult {
    rnp_function!(rnp_output_armor_set_line_length, crate::TRACE);
    assert_ptr!(output);
    arg!(llen);

    if llen == 64 {
        // This is Sequoia's default line length, there is nothing to
        // do.  Another job well done.
    } else {
        // Currently, there is no API to change the line length, nor
        // do I think there is a use case for changing the line
        // length.  Emit a warning and move on.
        warn!("rnp_output_armor_set_line_length: setting length to {} ignored",
              llen);
    }
    rnp_success!()
}

#[no_mangle] pub unsafe extern "C"
fn rnp_output_destroy(output: *mut RnpOutput) -> RnpResult {
    rnp_function!(rnp_output_destroy, crate::TRACE);
    arg!(output);

    if ! output.is_null() {
        drop(Box::from_raw(output));
    }
    rnp_success!()
}

#[no_mangle] pub unsafe extern "C"
fn rnp_output_finish(output: *mut RnpOutput) -> RnpResult {
    rnp_function!(rnp_output_finish, crate::TRACE);
    let output = assert_ptr_mut!(output);

    match output {
        RnpOutput::Buf(_) => (),
        RnpOutput::File(_) => (),
        RnpOutput::Armorer(w) =>
            if let Some(w) = w.take() {
                if let Err(e) = w.finalize() {
                    warn!("rnp_output_finish: {}", e);
                    rnp_return_status!(RNP_ERROR_WRITE);
                }
            } else {
                rnp_return_status!(RNP_ERROR_WRITE);
            },
        // XXX: If we ever implement RNP_OUTPUT_FILE_RANDOM, do the
        // rename here.
    }

    rnp_success!()
}

impl<'a> io::Write for RnpOutput<'a> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            RnpOutput::Buf((c, max_alloc)) => {
                if let Some(max) = max_alloc {
                    let left = *max - c.len();
                    c.write(&buf[..buf.len().min(left)])
                } else {
                    c.write(buf)
                }
            },
            RnpOutput::File(f) => f.write(buf),
            RnpOutput::Armorer(w) =>
                if let Some(w) = w {
                    w.write(buf)
                } else {
                    Err(io::Error::new(io::ErrorKind::BrokenPipe,
                                       "rnp_output_finished called"))
                },
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            RnpOutput::Buf(_) => Ok(()),
            RnpOutput::File(f) => f.flush(),
            RnpOutput::Armorer(w) =>
                if let Some(w) = w {
                    w.flush()
                } else {
                    Err(io::Error::new(io::ErrorKind::BrokenPipe,
                                       "rnp_output_finished called"))
                },
        }
    }
}

#[no_mangle] pub unsafe extern "C"
fn rnp_enarmor(input: *mut RnpInput,
               output: *mut RnpOutput,
               kind: *const c_char)
               -> RnpResult {
    rnp_function!(rnp_enarmor, crate::TRACE);
    assert_ptr!(input);
    assert_ptr!(output);

    if kind.is_null() {
        arg!(kind);
        warn!("rnp_enarmor: type detection not implemented");
        rnp_return_status!(RNP_ERROR_NOT_IMPLEMENTED); // XXX
    }
    assert_str!(kind); // XXX
    let kind = rnp_try!(armor::Kind::from_rnp_id(kind));

    fn f(input: &mut RnpInput, output: &mut RnpOutput, kind: armor::Kind)
         -> openpgp::Result<()>
    {
        let mut w = armor::Writer::new(output, kind)?;
        io::copy(input, &mut w)?;
        w.finalize()?;
        Ok(())
    }

    rnp_return_status!(if let Err(e) = f(&mut *input, &mut *output, kind) {
        warn!("rnp_enarmor failed: {}", e);
        RNP_ERROR_GENERIC
    } else {
        RNP_SUCCESS
    })
}
