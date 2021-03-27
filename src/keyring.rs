use std::convert::TryFrom;
use std::fmt::Debug;
use std::io::Read;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::mpsc::channel;
use std::thread;

use anyhow::Context;

use buffered_reader::BufferedReader;

use sequoia_openpgp as openpgp;
use openpgp::{
    cert::prelude::*,
    packet::prelude::*,
    parse::PacketParser,
    parse::Parse,
    packet::header::CTB,
    packet::header::BodyLength,
    packet::header::PacketLengthType,
};

/// Parses a keyring.
///
/// Returns a vector of `Result<Cert>`.  The reason we return
/// `Result`s and not bare `Cert`s is that we are able to recover from
/// certain errors.  These show up as `Err`s.
///
/// If R is empty or contains junk at the start of the file, then this
/// immediately returns an error.
///
/// If R starts with a valid certificate and then we encounter junk,
/// we attempt to recover.  If we are able to find a valid packet,
/// then the iterator returns an error for the junk, and keeps
/// parsing.  If we are unable to recover, then we return an error and
/// stop parsing.
pub(crate) fn parse_keyring<R>(input: R)
    -> openpgp::Result<Vec<openpgp::Result<Cert>>>
    where R: std::io::Read + Send + Sync
{
    return parse_keyring_internal(input, None, None, None);
}

pub(crate) fn parse_keyring_internal<R>(mut input: R,
                                        threads: Option<usize>,
                                        chunk_size: Option<usize>,
                                        inline_last_chunk: Option<bool>)
    -> openpgp::Result<Vec<openpgp::Result<Cert>>>
    where R: std::io::Read + Send + Sync
{
    // Enabling tracing on this function is very noisy.
    rnp_function!(parse_keyring, false);

    // We want to parse the keyring in parallel.  One strategy would
    // be to parse a certificate and then queue it to be canonicalized
    // in another threat.  My measurements suggest that it takes about
    // 3 times as long to parse a certificate as it does to
    // canonicalize it.  So, this will only result in a 30% speed up
    // or so.
    //
    // Instead, we read the whole keyring into memory and split it
    // into certificates.  Then, we then use a thread pool to do the
    // parsing and canonicalization.
    //
    // Future improvements:
    //
    //     - Don't buffer the whole keyring in memory.

    // XXX: These functions are more or less copied from
    // sequoia/openpgp/src/parse.rs.  When sequoia-openpgp makes them
    // public, we drop this copy.
    fn body_length_parse_new_format<T, C>(bio: &mut T)
        -> openpgp::Result<BodyLength>
        where T: BufferedReader<C>, C: Debug + Send + Sync
    {
        let octet1 : u8 = bio.data_consume_hard(1)?[0];
        match octet1 {
            0..=191 => // One octet.
                Ok(BodyLength::Full(octet1 as u32)),
            192..=223 => { // Two octets length.
                let octet2 = bio.data_consume_hard(1)?[0];
                Ok(BodyLength::Full(((octet1 as u32 - 192) << 8)
                                    + octet2 as u32 + 192))
            },
            224..=254 => // Partial body length.
                Ok(BodyLength::Partial(1 << (octet1 & 0x1F))),
            255 => // Five octets.
                Ok(BodyLength::Full(bio.read_be_u32()?)),
        }
    }

    /// Decodes an old format body length as described in [Section
    /// 4.2.1 of RFC 4880].
    ///
    ///   [Section 4.2.1 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-4.2.1
    fn body_length_parse_old_format<T, C>(bio: &mut T,
                                          length_type: PacketLengthType)
         -> openpgp::Result<BodyLength>
        where T: BufferedReader<C>, C: Debug + Send + Sync
    {
        match length_type {
            PacketLengthType::OneOctet =>
                Ok(BodyLength::Full(bio.data_consume_hard(1)?[0] as u32)),
            PacketLengthType::TwoOctets =>
                Ok(BodyLength::Full(bio.read_be_u16()? as u32)),
            PacketLengthType::FourOctets =>
                Ok(BodyLength::Full(bio.read_be_u32()? as u32)),
            PacketLengthType::Indeterminate =>
                Ok(BodyLength::Indeterminate),
        }
    }

    fn parse_header<T, C>(bio: &mut T)
        -> openpgp::Result<Header>
        where T: BufferedReader<C>, C: Debug + Send + Sync
    {
        let ctb = CTB::try_from(bio.data_consume_hard(1)?[0])?;
        let length = match ctb {
            CTB::New(_) => body_length_parse_new_format(bio)?,
            CTB::Old(ref ctb) =>
                body_length_parse_old_format(bio, ctb.length_type())?,
        };
        return Ok(Header::new(ctb, length));
    }

    let buffer: Vec<u8> = {
        let mut buffer = Vec::new();
        input.read_to_end(&mut buffer)?;

        if buffer.len() == 0 {
            // Empty keyring.
            return Ok(Vec::new());
        }

        let mut br = buffered_reader::Memory::new(&buffer);
        if let Err(_) = parse_header(&mut br) {
            // It's not a binary keyring.  Try dearmoring.
            let mut input = openpgp::armor::Reader::from_bytes(
                &buffer, openpgp::armor::ReaderMode::Tolerant(None));
            let mut buffer2: Vec<u8> = Vec::new();
            input.read_to_end(&mut buffer2)?;

            if buffer2.len() == 0 {
                // Empty keyring.
                return Ok(Vec::new());
            }

            buffer2
        } else {
            buffer
        }
    };

    let buffer = Arc::new(buffer);
    let mut br = buffered_reader::Memory::new(&buffer);

    let parse_region = |data: &[u8]| -> openpgp::Result<Vec<openpgp::Result<Cert>>>
    {
        let ppr = PacketParser::from_bytes(&data)
            .context("Reading keyring")?;
        Ok(openpgp::cert::CertParser::from(ppr)
           .enumerate()
           .map(|(i, r)| {
               t!(" {}. {:?}",
                  i,
                  r.as_ref().map(|cert| cert.fingerprint()));
               r
           })
           .collect())
    };

    // Benchmark on a 4 core, 8 thread CPU parsing a 264 MB keyring
    // containing 10836 certificates, passing one certificate at a
    // time to the worker:
    //
    // last chunk processed by the main thread:
    //
    //                        Chunksize
    //               1          4          16
    // 1 threads   20.2 s     19.8 s     19.7 s
    // 2 threads   10.3 s     10.4 s     10.3 s
    // 4 threads    5.57 s     5.51 s     5.56 s
    // 6 threads    5.24 s     5.21 s     5.31 s
    // 8 threads    4.99 s     5.00 s     5.02 s
    //
    // last chunk not processed by the main thread:
    //
    // 1 threads   20.2 s     19.7 s     19.7 s
    // 2 threads   10.4 s     10.3 s     10.3 s
    // 4 threads    5.55 s     5.56 s     5.56 s
    // 6 threads    5.26 s     5.31 s     5.31 s
    // 8 threads    5.00 s     5.02 s     5.02 s
    //
    // Note: splitting the keyring into chunks and starting the
    // threads took 64.5ms.
    //
    // The results suggest that the processing scales with the number
    // of physical cores.  And for large keyrings, the chunk size and
    // whether the last chunk is processed by the main thread only
    // have negligible impact.
    //
    // We run the same benchmark, but using a 419 KB keyring
    // containing 10 certificates:
    //
    // last chunk processed by the main thread:
    //
    //                        Chunk size
    //                 1            4           16
    // 1 threads    12.72ms     14.30m        14.30m
    // 2 threads    10.03ms      7.83ms        7.83ms
    // 4 threads    10.21ms      7.47ms        7.47ms
    // 6 threads     9.70ms      7.66ms        7.66ms
    // 8 threads     9.28ms      8.35ms        8.35ms
    //
    // last chunk not processed by the main thread:
    //
    // 1 threads    11.95ms     14.30m        14.30m
    // 2 threads     8.88ms      7.83ms        7.83ms
    // 4 threads     7.73ms      7.47ms        7.47ms
    // 6 threads    10.72ms      7.66ms        7.66ms
    // 8 threads    10.65ms      8.35ms        8.35ms
    //
    // Not processing the last chunk in the main thread helps a tiny
    // bit.  This is probably because the main thread can already
    // start to gather the results.
    //
    // Second, 2 worker threads seem to be optimal.  More threads
    // don't seem to help for small keyrings.
    let chunk_size = chunk_size.unwrap_or(1);
    let inline_last_chunk = inline_last_chunk.unwrap_or(true);

    // The threads.  We start them on demand.
    let threads = if let Some(threads) = threads {
        threads
    } else {
        if buffer.len() < 1024 * 1024 {
            // The keyring is small, limit the number of threads.
            2
        } else {
            num_cpus::get()
        }
    };
    // Use at least one and not more than we have cores.
    let threads = std::cmp::min(std::cmp::max(1, threads), num_cpus::get());


    // We have two communication channels: one for sending work to the
    // workers and one for getting the results back.
    let (work_tx, work_rx) = channel();
    let work_rx = Arc::new(Mutex::new(work_rx));
    let (result_tx, result_rx) = channel();

    let mut thread_handles = Vec::with_capacity(threads);

    let mut enqueue_work = |i, start, end, inline| {
        if inline {
            t!("Main thread dequeuing region {}!", i);
            let results = parse_region(&buffer[start..end]);
            result_tx.send((i, results)).unwrap();
            return;
        }

        // Start a thread if we don't have one or there are no idle
        // threads.
        if thread_handles.len() < threads {
            t!("Starting thread {} of {}, seeding region {}",
               1 + thread_handles.len(), threads, i);

            // The thread's state.
            let work_rx = Arc::clone(&work_rx.clone());
            let result_tx = result_tx.clone();
            let buffer = Arc::clone(&buffer);
            let tid = thread_handles.len();

            thread_handles.push(thread::spawn(move || {
                // We move the first work item to avoid taking the
                // lock.
                let mut work = Some(Ok((i, start, end)));

                loop {
                    let work = match work.take() {
                        Some(work) => work,
                        None => {
                            // We are extra careful to drop the mutex
                            // as quickly as possible.
                            let work_rx = work_rx.lock().unwrap();
                            let work = work_rx.recv();
                            drop(work_rx);
                            work
                        }
                    };
                    match work {
                        Err(_) => break,
                        Ok((i, start, end)) => {
                            t!("Thread {} dequeuing region {} ({}-{})!",
                               tid, i, start, end);
                            let results = parse_region(&buffer[start..end]);
                            result_tx.send((i, results)).unwrap();
                        }
                    }
                }

                t!("Thread {} exiting", tid);
            }));
        } else {
            // When we start a thread, we seed it with the initial
            // region.
            t!("Enqueuing region {}!", i);
            work_tx.send((i, start, end)).unwrap();
        }
    };

    // The total number of regions.
    let mut region_count = 0;
    // The start of this region as a byte offset into buffer.
    let mut start_of_region: usize = 0;
    // The number of certs in this region.
    let mut certs_in_region = 0;

    // let split_start = std::time::SystemTime::now();

    // If we ever have an issue, we simply turn the rest of the file
    // into a single region.  We can't parallelize that region, but
    // are able to process it correctly.
    loop {
        // The start of this packet as a byte offset into buffer.
        let start_of_packet = br.total_out();

        if start_of_packet == buffer.len() {
            // We're done.
            break;
        }

        let header = match parse_header(&mut br) {
            Ok(header) => header,
            Err(err) => {
                t!("Error splitting keyring at offset {}: {}",
                   start_of_packet, err);
                break;
            }
        };

        use Tag::*;
        let t = header.ctb().tag();
        t!("Found a {:?} at offset {}, length: {:?}",
           t, start_of_packet, header.length());
        match t {
            // Start of a new certificate.
            PublicKey | SecretKey => {
                if start_of_packet > 0 {
                    certs_in_region += 1;
                }
                if certs_in_region >= chunk_size {
                    enqueue_work(region_count,
                                 start_of_region, start_of_packet,
                                 false);
                    start_of_region = start_of_packet;
                    region_count += 1;
                    certs_in_region = 0;
                }
            }

            // The body of a certificate.
            PublicSubkey
            | SecretSubkey
            | UserID
            | UserAttribute
            | Signature
            | Marker
            | Trust
            | Unknown(_)
            | Private(_) => {
                if start_of_packet == 0 {
                    t!("Encountered a ({:?}) at offset {}, \
                        which is not a valid start of a certificate",
                       t, start_of_packet);
                    break;
                }
            }

            Reserved
            | PKESK
            | SKESK
            | OnePassSig
            | CompressedData
            | SED
            | Literal
            | SEIP
            | MDC
            | AED =>
            {
                t!("Encountered a ({:?}) at offset {}, \
                    which does not belong in a certificate",
                   t, start_of_packet);
                break;
            }
        }

        // Advance to the next packet.
        match header.length() {
            BodyLength::Full(l) => {
                let l = *l as usize;
                if let Err(err) = br.data_consume_hard(l) {
                    t!("Error while reading packet: {}", err);
                    break;
                }
            }
            BodyLength::Partial(_) => {
                t!("Packet {} has partial body length, \
                    which is unsupported by keyring splitter",
                   t);
                break;
            }
            BodyLength::Indeterminate => {
                t!("Packet {} has intedeterminite length, \
                    which is unsupported by keyring splitter",
                   t);
                break;
            }
        }
    }
    if let Ok(_) = br.drop_eof() {
        if br.total_out() > start_of_region {
            enqueue_work(region_count, start_of_region, br.total_out(),
                         inline_last_chunk);
            region_count += 1;
        }
    }

    // log!("Splitting {} byte keyring took {:?}",
    //      buffer.len(), split_start.elapsed().unwrap());

    // Collect the results.

    // When the threads see this drop, they will exit.
    drop(work_tx);

    let mut results = Vec::with_capacity(region_count);
    if region_count > 0 {
        while let Ok((i, result)) = result_rx.recv() {
            results.push((i, result));
            if results.len() == region_count {
                break;
            }
        }
        // Because threading, the results could be out of order.
        results.sort_by_key(|a| a.0);
    }
    let results: Vec<_> = results.into_iter().map(|r| r.1).collect();

    // We've collected all of the results so this should be
    // instantaneous.
    for (i, th) in thread_handles.into_iter().enumerate() {
        t!("Joining thread #{}", i);
        th.join().unwrap();
    }


    // Massage the results.

    // If we only have a single region, and that region has a single
    // error, return that error as is.
    if results.len() == 1 {
        if let Ok(ref first_region) = results[0] {
            if first_region.len() == 1 {
                if let Err(ref _err) = first_region[0] {
                    let first_region = results.into_iter().next().unwrap();
                    let v = first_region.into_iter().next().unwrap();
                    match v.into_iter().next().unwrap() {
                        Err(err) => {
                            t!("Converting sole error into a parse error: {}",
                               err);
                            return Err(err);
                        }
                        Ok(_) => unreachable!(),
                    }
                }
            }
        }
    }

    // Recombine.
    let certs: Vec<openpgp::Result<Cert>> = results.into_iter()
        .flat_map(|result| {
            match result {
                Ok(result) => result,
                Err(err) => vec![ Err(err) ],
            }
        })
        .collect();

    for (i, cert) in certs.iter().enumerate() {
        t!("  {}. {:?}",
           i,
           cert.as_ref().map(|cert| cert.fingerprint()));
    }

    Ok(certs)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::HashSet;
    use std::iter::FromIterator;

    use openpgp::serialize::Serialize;
    use openpgp::types::DataFormat;
    use openpgp::Fingerprint;

    // How much junk the packet parser is willing to skip when
    // recovering (as of 1.1).  This is an internal implementation
    // detail.
    const RECOVERY_THRESHOLD: usize = 32 * 1024;

    fn t(n: usize, literal: bool, bad: usize) -> openpgp::Result<()> {
        // XXX: Remove this once we start using the next released
        // version of sequoia.  See this issue for details:
        //
        //   https://gitlab.com/sequoia-pgp/sequoia/-/issues/699
        if bad > 0 {
            return Ok(());
        }

        // Parses keyrings with different numbers of keys and
        // different errors.

        // n: number of keys
        // literal: whether to interleave literal packets.
        // bad: whether to insert invalid data (NUL bytes where
        //      the start of a certificate is expected).

        // PacketParser is pretty good at recovering from junk in the
        // middle: it will (as of 1.1) search the next 32kb for a
        // valid packet.  If it finds it, it will turn the junk into a
        // reserved packet and resume.  Insert a lot of nuls to
        // prevent the recovery mechanism from working.
        let nulls = vec![ 0; bad ];

        log!("n: {}, literals: {}, bad data: {}",
             n, literal, bad);

        let mut data = Vec::new();

        let mut certs_orig = vec![];
        for i in 0..n {
            let (cert, _) =
                CertBuilder::general_purpose(
                    None, Some(format!("{}@example.org", i)))
                .generate()?;

            cert.as_tsk().serialize(&mut data)?;
            certs_orig.push(cert);

            if literal {
                let mut lit = Literal::new(DataFormat::Text);
                lit.set_body(b"data".to_vec());

                Packet::from(lit).serialize(&mut data)?;
            }
            // Push some NUL bytes.
            data.extend(&nulls[..bad]);
        }
        if n == 0 {
            // Push some NUL bytes even if we didn't add any packets.
            data.extend(&nulls[..bad]);
        }
        assert_eq!(certs_orig.len(), n);

        log!("Start of data: {} {}",
             if let Some(x) = data.get(0) {
                 format!("{:02X}", x)
             } else {
                 "XX".into()
             },
             if let Some(x) = data.get(1) {
                 format!("{:02X}", x)
             } else {
                 "XX".into()
             });

        let certs_parsed = parse_keyring(std::io::Cursor::new(data));

        let certs_parsed = if n == 0 && bad > 0 {
            // Junk at the beginning of the file results in an
            // immediate parse error.
            assert!(certs_parsed.is_err());
            return Ok(());
        } else {
            certs_parsed.expect("Valid init")
        };

        certs_parsed.iter().enumerate().for_each(|(i, r)| {
            log!("{}. {}",
                 i,
                 match r {
                     Ok(c) => c.fingerprint().to_string(),
                     Err(err) => err.to_string(),
                 });
        });

        let n = if bad > RECOVERY_THRESHOLD {
            // We stop once we see the junk.
            certs_orig.drain(1..);
            std::cmp::min(n, 1)
        } else {
            n
        };

        let modulus = if literal && bad > 0 {
            3
        } else {
            2
        };
        let certs_parsed: Vec<Cert> = certs_parsed.into_iter()
            .enumerate()
            .filter_map(|(i, c)| {
                if literal && i % modulus == 1 {
                    // Literals should be errors.
                    assert!(c.is_err());
                    None
                } else if bad > 0 && n == 0 && i == 0 {
                    // The first byte in the input is the NUL
                    // byte.
                    assert!(c.is_err());
                    None
                } else if bad > 0 && i % modulus == modulus - 1 {
                    // NUL bytes are inserted after the
                    // certificate / literal data packet.  So the
                    // second element will be the parse error.
                    assert!(c.is_err());
                    None
                } else {
                    Some(c.unwrap())
                }
            })
            .collect();

        assert_eq!(certs_orig.len(), certs_parsed.len(),
                   "number of parsed certificates: expected vs. got");

        let fpr_orig = certs_orig.iter()
            .map(|c| {
                c.fingerprint()
            })
            .collect::<Vec<_>>();
        let fpr_parsed = certs_parsed.iter()
            .map(|c| {
                c.fingerprint()
            })
            .collect::<Vec<_>>();
        if fpr_orig != fpr_parsed {
            log!("{} certificates in orig; {} is parsed",
                 fpr_orig.len(), fpr_parsed.len());

            let fpr_set_orig: HashSet<&Fingerprint>
                = HashSet::from_iter(fpr_orig.iter());
            let fpr_set_parsed = HashSet::from_iter(fpr_parsed.iter());
            log!("Only in orig:\n  {}",
                 fpr_set_orig.difference(&fpr_set_parsed)
                 .map(|f| f.to_string())
                 .collect::<Vec<_>>()
                 .join(",\n  "));
            log!("Only in parsed:\n  {}",
                 fpr_set_parsed.difference(&fpr_set_orig)
                 .map(|f| f.to_string())
                 .collect::<Vec<_>>()
                 .join(",\n  "));

            assert_eq!(fpr_orig, fpr_parsed);
        }

        // Go packet by packet.  (This makes finding an error a
        // lot easier.)
        for (i, (c_orig, c_parsed)) in
            certs_orig
            .into_iter()
            .zip(certs_parsed.into_iter())
            .enumerate()
        {
            let ps_orig: Vec<Packet> = c_orig.into_packets().collect();
            let ps_parsed: Vec<Packet> = c_parsed.into_packets().collect();
            if bad > 0 && ! literal && i == n - 1 {
                // On a parse error, we lose the last successfully
                // parsed packet.  This is annoying.  But, the
                // file is corrupted anyway, so...
                assert_eq!(ps_orig.len() - 1, ps_parsed.len(),
                           "number of packets: expected vs. got");
            } else {
                assert_eq!(ps_orig.len(), ps_parsed.len(),
                           "number of packets: expected vs. got");
            }

            for (j, (p_orig, p_parsed)) in
                ps_orig
                .into_iter()
                .zip(ps_parsed.into_iter())
                .enumerate()
            {
                assert_eq!(p_orig, p_parsed,
                           "Cert {}, packet: {}", i, j);
            }
        }

        Ok(())
    }

    #[test]
    fn parse_keyring_simple() -> openpgp::Result<()> {
        for n in [1, 100, 0].iter() {
            t(*n, false, 0)?;
        }

        Ok(())
    }

    #[test]
    fn parse_keyring_interleaved_literals() -> openpgp::Result<()> {
        for n in [1, 100, 0].iter() {
            t(*n, true, 0)?;
        }

        Ok(())
    }

    #[test]
    fn parse_keyring_interleaved_small_junk() -> openpgp::Result<()> {
        for n in [1, 100, 0].iter() {
            t(*n, false, 1)?;
        }

        Ok(())
    }

    #[test]
    fn parse_keyring_interleaved_unrecoverable_junk() -> openpgp::Result<()> {
        for n in [1, 100, 0].iter() {
            t(*n, false, 2 * RECOVERY_THRESHOLD)?;
        }

        Ok(())
    }

    #[test]
    fn parse_keyring_interleaved_literal_and_small_junk() -> openpgp::Result<()> {
        for n in [1, 100, 0].iter() {
            t(*n, true, 1)?;
        }

        Ok(())
    }

    #[test]
    fn parse_keyring_interleaved_literal_and_unrecoverable_junk() -> openpgp::Result<()> {
        for n in [1, 100, 0].iter() {
            t(*n, true, 2 * RECOVERY_THRESHOLD)?;
        }

        Ok(())
    }

    #[test]
    fn parse_keyring_no_public_key() -> openpgp::Result<()> {
        // The first few packets are not the valid start of a
        // certificate.  Each of those should return in an Error.
        // But, that shouldn't stop us from parsing the rest of the
        // keyring.

        let (cert_1, _) =
            CertBuilder::general_purpose(
                None, Some("a@example.org"))
            .generate()?;
        let cert_1_packets: Vec<Packet>
            = cert_1.into_packets().collect();

        let (cert_2, _) =
            CertBuilder::general_purpose(
                None, Some("b@example.org"))
            .generate()?;

        for n in 1..cert_1_packets.len() {
            log!("n: {}", n);

            let mut data = Vec::new();

            for i in n..cert_1_packets.len() {
                cert_1_packets[i].serialize(&mut data)?;
            }

            cert_2.as_tsk().serialize(&mut data)?;


            let certs_parsed = parse_keyring(std::io::Cursor::new(data))
                .expect("Valid parse");

            let mut iter = certs_parsed.iter();
            for _ in n..cert_1_packets.len() {
                assert!(iter.next().unwrap().is_err());
            }
            assert_eq!(iter.next().unwrap().as_ref().unwrap(), &cert_2);
            assert!(iter.next().is_none());
            assert!(iter.next().is_none());
        }

        Ok(())
    }

    // A trivial way to benchmark the keyring parser.
    // #[test]
    #[allow(dead_code)]
    fn parse_a_keyring() -> openpgp::Result<()> {
        // The first few packets are not the valid start of a
        // certificate.  Each of those should return in an Error.
        // But, that shouldn't stop us from parsing the rest of the
        // keyring.

        let mut file = std::fs::File::open("/tmp/keyring.pgp")?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer).unwrap();

        for inline in [ true, false ].iter() {
            for chunk_size in [ 1usize, 4, 16 ].iter() {
                for threads in [ 1usize, 2, 4, 6, 8 ].iter() {
                    let start = std::time::SystemTime::now();
                    let _ = parse_keyring_internal(std::io::Cursor::new(&buffer),
                                                   Some(*threads),
                                                   Some(*chunk_size),
                                                   Some(*inline))
                        .expect("Valid parse");
                    let elapsed = start.elapsed().unwrap();
                    log!("{} threads, chunk size: {:2}, inline: {}: {:.2?}",
                         threads, chunk_size, inline, elapsed);
                }
            }
        }

        Ok(())
    }
}
