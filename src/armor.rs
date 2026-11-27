use std::io;

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

/// Ends the lines of ASCII Armor with CRLF.
///
/// RNP ends every line of the ASCII Armor it writes with CRLF, and
/// Thunderbird relies on that.  Sequoia's armor writer ends lines
/// with LF, and has no way to change that.  This writer sits between
/// Sequoia's armor writer and the sink, and inserts a CR before every
/// LF that isn't preceded by one.
///
/// This must only be used for ASCII Armor, never for binary data.
pub struct CrLfWriter<W: io::Write> {
    inner: W,
    /// Whether the last byte written to `inner` was a CR.
    last_was_cr: bool,
}

impl<W: io::Write> CrLfWriter<W> {
    /// Returns a writer that converts line endings to CRLF, and
    /// writes the result to `inner`.
    pub fn new(inner: W) -> Self {
        CrLfWriter {
            inner,
            last_was_cr: false,
        }
    }
}

impl<W: io::Write> io::Write for CrLfWriter<W> {
    /// Writes a prefix of `buf`, up to the next LF that needs a CR.
    ///
    /// Like any writer, this may consume less than `buf`.  We keep
    /// track of what was written to the sink, not of what we were
    /// given.  This way, if the sink fails or writes only a part of
    /// the data, and the caller tries again, no CR is lost and none
    /// is written twice.
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        if buf[0] == b'\n' && ! self.last_was_cr {
            if self.inner.write(b"\r")? == 0 {
                return Ok(0);
            }
            self.last_was_cr = true;
        }

        // Now, buf[0] can be written as it is.  Stop before the next
        // LF that isn't preceded by a CR.
        let end = (1..buf.len())
            .find(|&i| buf[i] == b'\n' && buf[i - 1] != b'\r')
            .unwrap_or(buf.len());

        let n = self.inner.write(&buf[..end])?;
        if n > 0 {
            self.last_was_cr = buf[n - 1] == b'\r';
        }
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

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

#[cfg(test)]
mod tests {
    use std::ffi::CString;
    use std::io::Write;
    use std::ptr::null_mut;

    use super::*;
    use libc::{
        c_char,
        size_t,
    };

    use openpgp::{
        Cert,
        Packet,
        cert::CertBuilder,
        parse::Parse,
        policy::StandardPolicy,
        serialize::MarshalInto,
    };

    use crate::RnpContext;
    use crate::flags::*;
    use crate::import::rnp_import_keys;
    use crate::key::*;
    use crate::op_encrypt::*;
    use crate::op_sign::*;
    use crate::op_verify::*;
    use crate::rnp_enarmor;
    use crate::rnp_ffi_create;
    use crate::rnp_ffi_destroy;
    use crate::rnp_input_destroy;
    use crate::rnp_input_from_memory;
    use crate::rnp_output_armor_set_line_length;
    use crate::rnp_output_destroy;
    use crate::rnp_output_finish;
    use crate::rnp_output_memory_get_buf;
    use crate::rnp_output_to_armor;
    use crate::rnp_output_to_memory;

    /// Text with all kinds of line endings.  The functions that armor
    /// data must not change it.
    const MESSAGE: &[u8] = b"line one\nline two\r\nline three\rline four\n";

    macro_rules! rnp_try {
        ($e: expr) => {{
            let r = unsafe { $e };
            assert_eq!(r, RNP_SUCCESS.as_u32());
        }}
    }

    /// Generates a certificate.
    ///
    /// The user ID contains a line feed, so the binary certificate
    /// contains a line feed that is not preceded by a carriage
    /// return.
    fn generate() -> Cert {
        let (cert, _) =
            CertBuilder::general_purpose(Some("line one\nline two"))
            .generate().unwrap();
        assert!(cert.to_vec().unwrap().contains(&b'\n'));
        cert
    }

    /// Creates a context and imports the certificate, including the
    /// secret key material.
    fn ctx_with_cert(cert: &Cert) -> *mut RnpContext {
        let mut ctx: *mut RnpContext = null_mut();
        rnp_try!(rnp_ffi_create(
            &mut ctx as *mut *mut _,
            b"GPG\x00".as_ptr() as *const c_char,
            b"GPG\x00".as_ptr() as *const c_char));

        let buffer = cert.as_tsk().to_vec().unwrap();
        let input = input_from(&buffer);
        rnp_try!(rnp_import_keys(
            ctx, input,
            RNP_LOAD_SAVE_PUBLIC_KEYS | RNP_LOAD_SAVE_SECRET_KEYS,
            null_mut() as *mut *mut _));
        rnp_try!(rnp_input_destroy(input));

        ctx
    }

    /// Returns a handle for the key with the given fingerprint.
    fn locate(ctx: *mut RnpContext, fp: openpgp::Fingerprint) -> *mut RnpKey {
        let fp = CString::new(fp.to_hex()).unwrap();
        let mut key: *mut RnpKey = null_mut();
        rnp_try!(rnp_locate_key(ctx, b"fingerprint\0".as_ptr() as *const _,
                                fp.as_ptr(), &mut key as *mut _));
        assert!(! key.is_null());
        key
    }

    /// Returns an input that reads from `data`.
    fn input_from(data: &[u8]) -> *mut RnpInput {
        let mut input: *mut RnpInput = null_mut();
        rnp_try!(rnp_input_from_memory(
            &mut input as *mut *mut _, data.as_ptr(), data.len(), true));
        input
    }

    /// Returns an output that writes to memory.
    fn output_to_memory<'a>() -> *mut RnpOutput<'a> {
        let mut output: *mut RnpOutput = null_mut();
        rnp_try!(rnp_output_to_memory(&mut output as *mut *mut _, 0));
        output
    }

    /// Returns an output that writes to memory, and fails when more
    /// than `max` bytes are written to it.
    fn output_to_limited_memory<'a>(max: usize) -> *mut RnpOutput<'a> {
        assert!(max > 0);
        let mut output: *mut RnpOutput = null_mut();
        rnp_try!(rnp_output_to_memory(&mut output as *mut *mut _, max));
        output
    }

    /// Returns what was written to the output, and destroys it.
    fn finish(output: *mut RnpOutput) -> Vec<u8> {
        let mut buf: *mut u8 = null_mut();
        let mut len: size_t = 0;
        rnp_try!(rnp_output_memory_get_buf(
            output, &mut buf as *mut *mut _, &mut len as *mut _, false));
        let data = if len > 0 {
            unsafe { std::slice::from_raw_parts(buf, len) }.to_vec()
        } else {
            Vec::new()
        };
        rnp_try!(rnp_output_destroy(output));
        data
    }

    /// Asserts that `armor` is one armored block with the given
    /// label, and that each of its lines ends with CRLF.
    fn assert_crlf(armor: &[u8], label: &str) {
        let armor = std::str::from_utf8(armor).expect("armor is ASCII");
        let begin = format!("-----BEGIN PGP {}-----\r\n", label);
        let end = format!("-----END PGP {}-----\r\n", label);
        assert!(armor.starts_with(&begin), "{:?}", armor);
        assert!(armor.ends_with(&end), "{:?}", armor);

        // Header, empty line, at least one line of data, checksum,
        // and footer.
        let lines = armor.split_inclusive('\n').collect::<Vec<_>>();
        assert!(lines.len() >= 5, "{:?}", armor);
        for line in lines {
            assert!(line.ends_with("\r\n"), "{:?}", line);
            // Exactly one CR, and exactly one LF.
            let line = &line[..line.len() - 2];
            assert!(! line.contains('\r'), "{:?}", line);
            assert!(! line.contains('\n'), "{:?}", line);
            assert!(line.len() <= 64, "{:?}", line);
        }
    }

    /// Dearmors `armor` using rnp_dearmor.
    fn dearmor(armor: &[u8]) -> Vec<u8> {
        let input = input_from(armor);
        let output = output_to_memory();
        rnp_try!(rnp_dearmor(input, output));
        rnp_try!(rnp_input_destroy(input));
        finish(output)
    }

    /// Verifies or decrypts `message` using rnp_op_verify_execute.
    ///
    /// If `detached` is given, `message` is the signed data and
    /// `detached` the signature.  Returns the content of the output,
    /// and the number of valid signatures.  Fails if the operation
    /// fails or a signature is not valid.
    fn verify(ctx: *mut RnpContext, message: &[u8], detached: Option<&[u8]>)
              -> (Vec<u8>, usize)
    {
        let input = input_from(message);
        let output = output_to_memory();
        let mut signature: *mut RnpInput = null_mut();
        let mut op: *mut RnpOpVerify = null_mut();
        if let Some(detached) = detached {
            signature = input_from(detached);
            rnp_try!(rnp_op_verify_detached_create(
                &mut op as *mut *mut _, ctx, input, signature));
        } else {
            rnp_try!(rnp_op_verify_create(
                &mut op as *mut *mut _, ctx, input, output));
        }
        rnp_try!(rnp_op_verify_execute(op));

        let mut count = 0;
        rnp_try!(rnp_op_verify_get_signature_count(op, &mut count as *mut _));
        for i in 0..count {
            let mut sig: *const RnpOpVerifySignature = std::ptr::null();
            rnp_try!(rnp_op_verify_get_signature_at(
                op, i, &mut sig as *mut *const _));
            rnp_try!(rnp_op_verify_signature_get_status(sig));
        }

        rnp_try!(rnp_op_verify_destroy(op));
        if ! signature.is_null() {
            rnp_try!(rnp_input_destroy(signature));
        }
        rnp_try!(rnp_input_destroy(input));
        (finish(output), count)
    }

    /// Creates a detached signature over `data` using the
    /// certificate's signing subkey.
    fn sign_detached(ctx: *mut RnpContext, cert: &Cert, data: &[u8],
                     armor: bool)
                     -> Vec<u8>
    {
        let p = &StandardPolicy::new();
        let signer = locate(
            ctx,
            cert.keys().with_policy(p, None).for_signing().next().unwrap()
                .key().fingerprint());

        let input = input_from(data);
        let output = output_to_memory();
        let mut op: *mut RnpOpSign = null_mut();
        rnp_try!(rnp_op_sign_detached_create(
            &mut op as *mut *mut _, ctx, input, output));
        rnp_try!(rnp_op_sign_add_signature(op, signer, null_mut()));
        rnp_try!(rnp_op_sign_set_armor(op, armor));
        rnp_try!(rnp_op_sign_set_hash(
            op, b"SHA256\0".as_ptr() as *const c_char));
        rnp_try!(rnp_op_sign_execute(op));
        rnp_try!(rnp_op_sign_destroy(op));
        rnp_try!(rnp_input_destroy(input));
        rnp_try!(rnp_key_handle_destroy(signer));
        finish(output)
    }

    /// Encrypts `data` for the certificate.
    fn encrypt(ctx: *mut RnpContext, cert: &Cert, data: &[u8], armor: bool)
               -> Vec<u8>
    {
        let recipient = locate(ctx, cert.fingerprint());

        let input = input_from(data);
        let output = output_to_memory();
        let mut op: *mut RnpOpEncrypt = null_mut();
        rnp_try!(rnp_op_encrypt_create(
            &mut op as *mut *mut _, ctx, input, output));
        rnp_try!(rnp_op_encrypt_add_recipient(op, recipient));
        rnp_try!(rnp_op_encrypt_set_armor(op, armor));
        rnp_try!(rnp_op_encrypt_execute(op));
        rnp_try!(rnp_op_encrypt_destroy(op));
        rnp_try!(rnp_input_destroy(input));
        rnp_try!(rnp_key_handle_destroy(recipient));
        finish(output)
    }

    /// A sink that fails or writes only a part of the data.
    #[derive(Default)]
    struct Sink {
        data: Vec<u8>,
        /// The sink does not grow beyond this size.  A write that
        /// doesn't fit is cut short, and when the sink is full, a
        /// write fails.
        limit: Option<usize>,
        /// The sink fails once when it has this size.
        fail_once_at: Option<usize>,
        /// The sink writes nothing once when it has this size.
        zero_once_at: Option<usize>,
        /// The sink writes at most this many bytes at a time.
        at_most: Option<usize>,
    }

    impl io::Write for Sink {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if self.fail_once_at == Some(self.data.len()) {
                self.fail_once_at = None;
                return Err(io::Error::new(io::ErrorKind::Other, "failed"));
            }
            if self.zero_once_at == Some(self.data.len()) {
                self.zero_once_at = None;
                return Ok(0);
            }

            let mut n = buf.len().min(self.at_most.unwrap_or(usize::MAX));
            if let Some(limit) = self.limit {
                if self.data.len() == limit && ! buf.is_empty() {
                    return Err(io::Error::new(io::ErrorKind::Other, "full"));
                }
                n = n.min(limit - self.data.len());
            }
            self.data.extend_from_slice(&buf[..n]);
            Ok(n)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn crlf_writer() {
        /// Writes the chunks one after the other.
        fn convert(chunks: &[&[u8]]) -> Vec<u8> {
            let mut sink = Vec::new();
            let mut w = CrLfWriter::new(&mut sink);
            for chunk in chunks {
                w.write_all(chunk).unwrap();
            }
            w.flush().unwrap();
            sink
        }

        // A CR is added before a LF.
        assert_eq!(convert(&[b"a\nb\n"]), b"a\r\nb\r\n");
        assert_eq!(convert(&[b"\n\n"]), b"\r\n\r\n");
        assert_eq!(convert(&[b"\n"]), b"\r\n");

        // Unless there already is one.
        assert_eq!(convert(&[b"a\r\nb\r\n"]), b"a\r\nb\r\n");
        assert_eq!(convert(&[b"\r\n\n\r\n"]), b"\r\n\r\n\r\n");

        // Everything else is left alone.
        assert_eq!(convert(&[b""]), b"");
        assert_eq!(convert(&[b"ab"]), b"ab");
        assert_eq!(convert(&[b"a\rb\n"]), b"a\rb\r\n");
        assert_eq!(convert(&[b"\r\r\n"]), b"\r\r\n");
        assert_eq!(convert(&[b"a\r"]), b"a\r");

        // Line endings at the boundaries of writes.
        assert_eq!(convert(&[b"a", b"\nb"]), b"a\r\nb");
        assert_eq!(convert(&[b"a\n", b"b\n"]), b"a\r\nb\r\n");
        assert_eq!(convert(&[b"a\n", b"\n"]), b"a\r\n\r\n");
        assert_eq!(convert(&[b"a\r", b"\nb"]), b"a\r\nb");
        assert_eq!(convert(&[b"a\r", b"", b"\nb"]), b"a\r\nb");
        assert_eq!(convert(&[b"a\r", b"b", b"\n"]), b"a\rb\r\n");

        // Writing byte by byte gives the same result.
        let bytes = DATA.chunks(1).collect::<Vec<_>>();
        assert_eq!(convert(&bytes), CONVERTED);
        assert_eq!(convert(&[DATA]), CONVERTED);

        // A single write consumes some of the data, never more than
        // it was given, and nothing if there is nothing to write.
        let mut sink = Vec::new();
        let mut w = CrLfWriter::new(&mut sink);
        assert_eq!(w.write(b"").unwrap(), 0);
        let mut rest = DATA;
        while ! rest.is_empty() {
            let n = w.write(rest).unwrap();
            assert!(n > 0 && n <= rest.len());
            rest = &rest[n..];
        }
        assert_eq!(sink, CONVERTED);
    }

    /// Data with all kinds of line endings, and what CrLfWriter makes
    /// of it.
    const DATA: &[u8] = b"\na\n\nb\r\nc\rd\r\r\n\nef";
    const CONVERTED: &[u8] = b"\r\na\r\n\r\nb\r\nc\rd\r\r\n\r\nef";

    /// If the sink fails, CrLfWriter fails, and what was written up
    /// to then is correct.
    #[test]
    fn crlf_writer_sink_fails() {
        // The sink is full after `limit` bytes: before, between, and
        // after any CR and LF.
        for limit in 0..=CONVERTED.len() {
            for at_most in [None, Some(1), Some(2)] {
                let mut sink = Sink {
                    limit: Some(limit),
                    at_most,
                    ..Default::default()
                };
                let r = CrLfWriter::new(&mut sink).write_all(DATA);
                assert_eq!(r.is_ok(), limit == CONVERTED.len(),
                           "limit {}: {:?}", limit, r);
                assert_eq!(sink.data, &CONVERTED[..limit], "limit {}", limit);
            }
        }

        // A sink that returns zero is reported as such.
        let mut sink = Sink { at_most: Some(0), ..Default::default() };
        assert_eq!(CrLfWriter::new(&mut sink).write(b"\n").unwrap(), 0);
        assert_eq!(CrLfWriter::new(&mut sink).write(b"a").unwrap(), 0);
        assert_eq!(CrLfWriter::new(&mut sink).write_all(DATA)
                   .unwrap_err().kind(),
                   io::ErrorKind::WriteZero);
        assert!(sink.data.is_empty());
    }

    /// If the sink fails once, or writes nothing once, and the caller
    /// tries again, no byte is lost, and none is written twice.
    #[test]
    fn crlf_writer_sink_fails_once() {
        for position in 0..CONVERTED.len() {
            for at_most in [None, Some(1), Some(2)] {
                for fail in [true, false] {
                    let mut sink = Sink {
                        fail_once_at: Some(position).filter(|_| fail),
                        zero_once_at: Some(position).filter(|_| ! fail),
                        at_most,
                        ..Default::default()
                    };
                    let mut w = CrLfWriter::new(&mut sink);
                    let mut rest = DATA;
                    let mut errors = 0;
                    let mut zeros = 0;
                    while ! rest.is_empty() {
                        match w.write(rest) {
                            Ok(0) => zeros += 1,
                            Ok(n) => rest = &rest[n..],
                            Err(_) => errors += 1,
                        }
                    }
                    // A sink that writes byte by byte gets to every
                    // position.  Another sink may skip the position.
                    let expected = if fail { (1, 0) } else { (0, 1) };
                    if at_most == Some(1) {
                        assert_eq!((errors, zeros), expected,
                                   "position {}", position);
                    } else {
                        assert!((errors, zeros) == expected
                                || (errors, zeros) == (0, 0),
                                "position {}", position);
                    }
                    assert_eq!(sink.data, CONVERTED, "position {}", position);
                }
            }
        }
    }

    /// The lines of an exported key end with CRLF, whether the armor
    /// is requested using rnp_output_to_armor or using the flag.
    #[test]
    fn key_export() -> openpgp::Result<()> {
        let cert = generate();
        let ctx = ctx_with_cert(&cert);
        let key = locate(ctx, cert.fingerprint());

        // Not armored.  This must not be changed.
        let output = output_to_memory();
        rnp_try!(rnp_key_export(
            key, output, RNP_KEY_EXPORT_PUBLIC | RNP_KEY_EXPORT_SUBKEYS));
        let binary = finish(output);
        assert_eq!(binary, cert.to_vec()?);

        // What Thunderbird does to export a public key.
        let sink = output_to_memory();
        let mut output: *mut RnpOutput = null_mut();
        rnp_try!(rnp_output_to_armor(
            sink, &mut output as *mut *mut _,
            b"public key\0".as_ptr() as *const c_char));
        rnp_try!(rnp_output_armor_set_line_length(output, 64));
        rnp_try!(rnp_key_export(
            key, output, RNP_KEY_EXPORT_PUBLIC | RNP_KEY_EXPORT_SUBKEYS));
        rnp_try!(rnp_output_finish(output));
        rnp_try!(rnp_output_destroy(output));
        let armored = finish(sink);
        assert_crlf(&armored, "PUBLIC KEY BLOCK");
        assert_eq!(dearmor(&armored), binary);
        assert_eq!(Cert::from_bytes(&armored)?,
                   cert.clone().strip_secret_key_material());

        // Using the flag.
        let output = output_to_memory();
        rnp_try!(rnp_key_export(
            key, output,
            RNP_KEY_EXPORT_ARMORED
                | RNP_KEY_EXPORT_PUBLIC | RNP_KEY_EXPORT_SUBKEYS));
        let armored = finish(output);
        assert_crlf(&armored, "PUBLIC KEY BLOCK");
        assert_eq!(dearmor(&armored), binary);

        // The secret key.
        let output = output_to_memory();
        rnp_try!(rnp_key_export(
            key, output,
            RNP_KEY_EXPORT_ARMORED
                | RNP_KEY_EXPORT_SECRET | RNP_KEY_EXPORT_SUBKEYS));
        let armored = finish(output);
        assert_crlf(&armored, "PRIVATE KEY BLOCK");
        assert_eq!(dearmor(&armored), cert.as_tsk().to_vec()?);
        assert!(Cert::from_bytes(&armored)?.is_tsk());

        rnp_try!(rnp_key_handle_destroy(key));
        rnp_try!(rnp_ffi_destroy(ctx));
        Ok(())
    }

    /// The lines that rnp_enarmor writes end with CRLF, and the data
    /// is not changed.
    #[test]
    fn enarmor() -> openpgp::Result<()> {
        let cert = generate();
        let binary = cert.to_vec()?;

        for (kind, label, data) in [
            (&b"public key\0"[..], "PUBLIC KEY BLOCK", &binary[..]),
            (&b"message\0"[..], "MESSAGE", MESSAGE),
        ] {
            let input = input_from(data);
            let output = output_to_memory();
            rnp_try!(rnp_enarmor(input, output,
                                 kind.as_ptr() as *const c_char));
            rnp_try!(rnp_input_destroy(input));
            let armored = finish(output);
            assert_crlf(&armored, label);
            assert_eq!(dearmor(&armored), data);
        }

        Ok(())
    }

    /// The lines of an armored encrypted message end with CRLF, and
    /// the message can be decrypted.
    #[test]
    fn encrypted_message() -> openpgp::Result<()> {
        let cert = generate();
        let ctx = ctx_with_cert(&cert);

        let ciphertext = encrypt(ctx, &cert, MESSAGE, true);
        assert_crlf(&ciphertext, "MESSAGE");
        assert_eq!(verify(ctx, &ciphertext, None), (MESSAGE.to_vec(), 0));

        // Not armored.  This must not be changed: if a CR was added
        // before a LF, the message could not be decrypted.  To make
        // sure that the ciphertext contains a LF, encrypt data that
        // cannot be compressed.
        let mut state: u32 = 1;
        let data = std::iter::repeat_with(|| {
            state = state.wrapping_mul(1103515245).wrapping_add(12345);
            (state >> 16) as u8
        }).take(64 * 1024).collect::<Vec<u8>>();
        let ciphertext = encrypt(ctx, &cert, &data, false);
        assert!(ciphertext.len() >= data.len());
        assert!(ciphertext.contains(&b'\n'));
        assert!(! ciphertext.starts_with(b"-----"));
        assert_eq!(verify(ctx, &ciphertext, None), (data, 0));

        rnp_try!(rnp_ffi_destroy(ctx));
        Ok(())
    }

    /// The lines of an armored detached signature end with CRLF, and
    /// the signature can be verified.
    #[test]
    fn detached_signature() -> openpgp::Result<()> {
        let cert = generate();
        let ctx = ctx_with_cert(&cert);

        let signature = sign_detached(ctx, &cert, MESSAGE, true);
        assert_crlf(&signature, "SIGNATURE");
        assert_eq!(verify(ctx, MESSAGE, Some(&signature)), (Vec::new(), 1));
        let binary = dearmor(&signature);
        assert!(matches!(Packet::from_bytes(&binary)?, Packet::Signature(_)));

        // Not armored.  This must not be changed: if a CR was added
        // before a LF, the signature would not be valid.  Not every
        // signature contains a LF, so sign different data until one
        // does.
        let mut with_lf = 0;
        for i in 0..1000 {
            let mut data = MESSAGE.to_vec();
            write!(&mut data, "{}", i)?;
            let signature = sign_detached(ctx, &cert, &data, false);
            assert!(matches!(Packet::from_bytes(&signature)?,
                             Packet::Signature(_)));
            assert_eq!(verify(ctx, &data, Some(&signature)), (Vec::new(), 1));
            if signature.contains(&b'\n') {
                with_lf += 1;
                if with_lf == 3 {
                    break;
                }
            }
        }
        assert_eq!(with_lf, 3);

        rnp_try!(rnp_ffi_destroy(ctx));
        Ok(())
    }

    /// If the output cannot take all of the armor, the functions
    /// fail, and what was written up to then is correct.  This cuts
    /// the armor at every position: before, between, and after any
    /// CR and LF.
    #[test]
    fn output_too_small() -> openpgp::Result<()> {
        const SUCCESS: u32 = RNP_SUCCESS.as_u32();
        let cert = generate();
        let ctx = ctx_with_cert(&cert);
        let key = locate(ctx, cert.fingerprint());
        let flags = RNP_KEY_EXPORT_PUBLIC | RNP_KEY_EXPORT_SUBKEYS;

        // rnp_key_export with the flag.
        let output = output_to_memory();
        rnp_try!(rnp_key_export(key, output, RNP_KEY_EXPORT_ARMORED | flags));
        let armored = finish(output);
        assert_crlf(&armored, "PUBLIC KEY BLOCK");
        for max in 1..=armored.len() {
            let output = output_to_limited_memory(max);
            let r = unsafe {
                rnp_key_export(key, output, RNP_KEY_EXPORT_ARMORED | flags)
            };
            if max < armored.len() {
                assert_eq!(r, RNP_ERROR_WRITE.as_u32(), "max {}", max);
            } else {
                assert_eq!(r, SUCCESS);
            }
            assert_eq!(finish(output), &armored[..max], "max {}", max);
        }

        // What Thunderbird does to export a public key.
        let export = |sink: *mut RnpOutput| -> (u32, u32) {
            let mut output: *mut RnpOutput = null_mut();
            rnp_try!(rnp_output_to_armor(
                sink, &mut output as *mut *mut _,
                b"public key\0".as_ptr() as *const c_char));
            rnp_try!(rnp_output_armor_set_line_length(output, 64));
            let exported = unsafe { rnp_key_export(key, output, flags) };
            let finished = unsafe { rnp_output_finish(output) };
            rnp_try!(rnp_output_destroy(output));
            (exported, finished)
        };
        let sink = output_to_memory();
        assert_eq!(export(sink), (SUCCESS, SUCCESS));
        let armored = finish(sink);
        assert_crlf(&armored, "PUBLIC KEY BLOCK");
        for max in 1..=armored.len() {
            let sink = output_to_limited_memory(max);
            let (exported, finished) = export(sink);
            if max < armored.len() {
                // The armor is complete only when the output is
                // finished, so that fails in any case.
                assert_eq!(finished, RNP_ERROR_WRITE.as_u32(), "max {}", max);
                assert!(exported == SUCCESS
                        || exported == RNP_ERROR_WRITE.as_u32(),
                        "max {}", max);
            } else {
                assert_eq!((exported, finished), (SUCCESS, SUCCESS));
            }
            assert_eq!(finish(sink), &armored[..max], "max {}", max);
        }

        // rnp_enarmor.
        let binary = cert.to_vec()?;
        let enarmor = |output: *mut RnpOutput| -> u32 {
            let input = input_from(&binary);
            let r = unsafe {
                rnp_enarmor(input, output,
                            b"public key\0".as_ptr() as *const c_char)
            };
            rnp_try!(rnp_input_destroy(input));
            r
        };
        let output = output_to_memory();
        assert_eq!(enarmor(output), SUCCESS);
        assert_eq!(finish(output), armored);
        for max in 1..=armored.len() {
            let output = output_to_limited_memory(max);
            let r = enarmor(output);
            if max < armored.len() {
                assert_eq!(r, RNP_ERROR_GENERIC.as_u32(), "max {}", max);
            } else {
                assert_eq!(r, SUCCESS);
            }
            assert_eq!(finish(output), &armored[..max], "max {}", max);
        }

        // rnp_op_encrypt_execute.  The message is different each
        // time, but it always starts the same way.
        let start = b"-----BEGIN PGP MESSAGE-----\r\n\r\n";
        for max in 1..=start.len() + 8 {
            let recipient = locate(ctx, cert.fingerprint());
            let input = input_from(MESSAGE);
            let output = output_to_limited_memory(max);
            let mut op: *mut RnpOpEncrypt = null_mut();
            rnp_try!(rnp_op_encrypt_create(
                &mut op as *mut *mut _, ctx, input, output));
            rnp_try!(rnp_op_encrypt_add_recipient(op, recipient));
            rnp_try!(rnp_op_encrypt_set_armor(op, true));
            let r = unsafe { rnp_op_encrypt_execute(op) };
            assert_ne!(r, SUCCESS, "max {}", max);
            rnp_try!(rnp_op_encrypt_destroy(op));
            rnp_try!(rnp_input_destroy(input));
            rnp_try!(rnp_key_handle_destroy(recipient));
            let data = finish(output);
            assert_eq!(data.len(), max);
            let n = max.min(start.len());
            assert_eq!(&data[..n], &start[..n], "max {}", max);
        }

        rnp_try!(rnp_key_handle_destroy(key));
        rnp_try!(rnp_ffi_destroy(ctx));
        Ok(())
    }

    /// When Thunderbird signs and encrypts a message, it first
    /// creates a detached signature, and then encrypts the
    /// multipart/signed message.  The Octopus recognizes the
    /// signature in the data to encrypt, and signs and encrypts the
    /// original data instead.  Make sure that it recognizes a
    /// signature whose lines end with CRLF.
    #[test]
    fn recombination() -> openpgp::Result<()> {
        let cert = generate();
        let ctx = ctx_with_cert(&cert);

        let signature = sign_detached(ctx, &cert, MESSAGE, true);
        assert_crlf(&signature, "SIGNATURE");

        let mut signed = Vec::new();
        write!(&mut signed,
               "Content-Type: multipart/signed; micalg=pgp-sha256;\r\n \
                protocol=\"application/pgp-signature\"; boundary=\"b\"\r\n\
                \r\n\
                --b\r\n")?;
        signed.write_all(MESSAGE)?;
        write!(&mut signed,
               "\r\n\
                --b\r\n\
                Content-Type: application/pgp-signature\r\n\
                \r\n")?;
        signed.write_all(&signature)?;
        write!(&mut signed, "\r\n--b--\r\n")?;

        // If the signature is recognized, decrypting the message
        // yields the data that was signed and the signature.
        // Otherwise, it yields the multipart/signed message and no
        // signature.
        let ciphertext = encrypt(ctx, &cert, &signed, true);
        assert_crlf(&ciphertext, "MESSAGE");
        assert_eq!(verify(ctx, &ciphertext, None), (MESSAGE.to_vec(), 1));

        rnp_try!(rnp_ffi_destroy(ctx));
        Ok(())
    }
}
