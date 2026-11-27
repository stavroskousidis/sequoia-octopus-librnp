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
    /// Whether the last byte written was a CR.
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
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // The start of the data that we still need to write.
        let mut start = 0;
        for (i, &b) in buf.iter().enumerate() {
            let preceded_by_cr = if i == 0 {
                self.last_was_cr
            } else {
                buf[i - 1] == b'\r'
            };

            if b == b'\n' && ! preceded_by_cr {
                // Write everything up to the LF, then the CR.  The LF
                // is written with the data that follows.
                self.inner.write_all(&buf[start..i])?;
                self.inner.write_all(b"\r")?;
                start = i;
            }
        }
        self.inner.write_all(&buf[start..])?;

        if let Some(&last) = buf.last() {
            self.last_was_cr = last == b'\r';
        }

        Ok(buf.len())
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

    #[test]
    fn crlf_writer() {
        /// Writes the chunks one after the other.
        fn convert(chunks: &[&[u8]]) -> Vec<u8> {
            let mut sink = Vec::new();
            let mut w = CrLfWriter::new(&mut sink);
            for chunk in chunks {
                // All of the data is consumed.
                assert_eq!(w.write(chunk).unwrap(), chunk.len());
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
        let data = b"\na\n\nb\r\nc\rd\r\r\n\n";
        let bytes = data.chunks(1).collect::<Vec<_>>();
        assert_eq!(convert(&bytes), convert(&[data]));
        assert_eq!(convert(&[data]), b"\r\na\r\n\r\nb\r\nc\rd\r\r\n\r\n");
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
