use anyhow::Context;

use sequoia_openpgp as openpgp;
use openpgp::{
    cert::prelude::*,
    packet::prelude::*,
    parse::PacketParser,
    parse::PacketParserResult,
    parse::Parse,
};

enum CertParserState {
    // The initial state (nothing queued).
    Start,
    // If we have a queued error.
    QueuedError(anyhow::Error),
    // If we have a queued PublicKey or SecretKey packet.
    QueuedHead(Packet),
    // If we encountered a parser error.
    ParserError(Option<anyhow::Error>),
}

struct CertParser<'a> {
    ppr: PacketParserResult<'a>,
    state: CertParserState,
}

impl<'a> Iterator for CertParser<'a> {
    type Item = openpgp::Result<Vec<Packet>>;

    fn next(&mut self) -> Option<Self::Item> {
        use Tag::*;

        let mut packets = Vec::with_capacity(32);

        match std::mem::replace(&mut self.state, CertParserState::Start) {
            CertParserState::Start => (),
            CertParserState::QueuedError(err) => {
                return Some(Err(err))
            }
            CertParserState::QueuedHead(pk) => {
                match pk.tag() {
                    PublicKey | SecretKey => {
                    }
                    tag => {
                        panic!("Impossible head of certificate: {:?}",
                               tag);
                    }
                }

                packets.push(pk);
            }
            CertParserState::ParserError(oerr) => {
                // self.state was reset by the replace.  Restore the
                // error.
                self.state = CertParserState::ParserError(None);
                if let Some(err) = oerr {
                    return Some(Err(err));
                } else {
                    return None;
                }
            }
        }

        while let PacketParserResult::Some(pp) = self.ppr.take() {
            // Get the packet out of the parser and start parsing the next
            // packet.
            let packet = match pp.next() {
                Err(err) => {
                    if packets.is_empty() {
                        self.state = CertParserState::ParserError(None);
                        return Some(Err(err));
                    } else {
                        self.state = CertParserState::ParserError(Some(err));
                        return Some(Ok(packets));
                    }
                },
                Ok((packet, next_ppr)) => {
                    self.ppr = next_ppr;
                    packet
                }
            };

            let tag = packet.tag();
            match tag {
                PublicKey | SecretKey => {
                    if ! packets.is_empty() {
                        // Start of a new certificate.
                        self.state = CertParserState::QueuedHead(packet);
                        return Some(Ok(packets));
                    } else {
                        // First time through.
                        packets.push(packet);
                    }
                }

                PublicSubkey
                | SecretSubkey
                | UserID
                | UserAttribute
                | Unknown(_)
                | Private(_)
                | Signature => {
                    if packets.is_empty() {
                        // These packets can't start a certificate.
                        return Some(Err(openpgp::Error::MalformedCert(
                            format!("A certificate does not start with a {}",
                                    tag).into()).into()));
                    } else {
                        packets.push(packet);
                    }
                }

                Marker | Trust => {
                    // Ignore them.
                }

                _ => {
                    // Packets that don't belong in a certificate.
                    let err = openpgp::Error::MalformedCert(
                        format!("A certificate cannot not include a {}",
                                tag).into()).into();

                    if packets.len() > 0 {
                        // Return the collected cert and queue the error
                        self.state = CertParserState::QueuedError(err);
                        return Some(Ok(packets));
                    } else {
                        // There is no certificate.  Return the error.
                        return Some(Err(err));
                    }
                }
            }
        }

        if ! packets.is_empty() {
            Some(Ok(packets))
        } else {
            None
        }
    }
}

// itertools::chunks doesn't work, because it is not Sized, Send and
// Sync.
//
//   rayon::join(|| certs.extend(p(c).into_iter()),
//   ^^^^^^^^^^^ `std::cell::RefCell<itertools::groupbylazy::GroupInner<usize, keyring::CertParser<'_>, itertools::groupbylazy::ChunkIndex>>` cannot be shared between threads safely
struct Chunked<I, E>
    where I: Iterator<Item=E>
{
    elements: usize,
    iter: I,
}

impl<I, E> Chunked<I, E>
    where I: Iterator<Item=E>
{
    fn new(n: usize, iter: I) -> Self {
        Self {
            elements: n,
            iter: iter,
        }
    }
}

impl<I, E> Iterator for Chunked<I, E>
    where I: Iterator<Item=E>
{
    type Item = Vec<E>;

    fn next(&mut self) -> Option<Self::Item> {
        let elements = std::cmp::max(1, self.elements);

        let mut v: Self::Item = Vec::with_capacity(self.elements);
        for _ in 0..elements {
            if let Some(e) = self.iter.next() {
                v.push(e);
            } else if v.is_empty() {
                return None;
            } else {
                return Some(v);
            }
        }

        Some(v)
    }
}

// The tuning parameters.
//
// The most important bit: it takes about 3 times as long to parse a
// certificate as it does to canonicalize it.  Since we can't easily
// parse a keyring in parallel (we don't know where the packet
// boundaries are), at most two threads are helpful: one to parse and
// the other to canonicalize.
//
// There are two main concerns.  First, we want to avoid communication
// overhead.  This means we should hand off multiple uncanonicalized
// certificates at a time.  Second, we want to start processing the
// parsed certificates as soon as possible.  This means a small batch
// size.
//
// Using the Debian Keyring (/usr/share/keyrings/debian-keyring.gpg,
// version 2020.12.24) with its 885 certificates I (Neal, 2021) did
// the following experiment on my desktop (4 core, 8 thread system): I
// parsed the whole keyring with different chunk sizes and measured
// the time both in the parse_keyring function and using 'time', which
// includes the overhead of starting the process.  The results follow:
//
// certs per chunk: 2
// Total time to process 885 certs: 846.243151ms
//
// real	0m0.886s
// user	0m1.025s
// sys	0m0.098s
//
// certs per chunk: 4
// Total time to process 885 certs: 817.505522ms
//
// real	0m0.858s
// user	0m0.958s
// sys	0m0.071s
//
// certs per chunk: 8
// Total time to process 885 certs: 813.635013ms
//
// real	0m0.852s
// user	0m0.903s
// sys	0m0.093s
//
// certs per chunk: 16
// Total time to process 885 certs: 816.149861ms
//
// real	0m0.855s
// user	0m0.936s
// sys	0m0.057s
//
// certs per chunk: 32
// Total time to process 885 certs: 828.848489ms
//
// real	0m0.872s
// user	0m0.959s
// sys	0m0.058s
//
// certs per chunk: 64
// Total time to process 885 certs: 826.119611ms
//
// real	0m0.867s
// user	0m0.948s
// sys	0m0.048s
//
// certs per chunk: 128
// Total time to process 885 certs: 829.17686ms
//
// real	0m0.874s
// user	0m0.915s
// sys	0m0.104s
//
// certs per chunk: 256
// Total time to process 885 certs: 851.942463ms
//
// real	0m0.898s
// user	0m0.921s
// sys	0m0.100s
//
// certs per chunk: 512
// Total time to process 885 certs: 890.484757ms
//
// real	0m0.939s
// user	0m0.927s
// sys	0m0.096s
//
// certs per chunk: 1024
// Total time to process 885 certs: 909.777735ms
//
// real	0m0.951s
// user	0m0.883s
// sys	0m0.068s
//
// The sweet spot on my system both in terms of wall clock and total
// computation time is handing off 8 certificates at a time.  Note:
// with a chunk size of 1024, we have just a single batch, which means
// we don't both to start an additional thread.  Thus, that is our
// baseline.
//
// Comparing, a batch size of 8 with the baseline, we see, it takes
// 90% as much wall clock time (1 - 0.852 / 0.951) while using 102% as
// much CPU time (0.903 / 0.883).
//
// I also generated 25,600 standard certificates (ECC, two subkeys and
// a User ID).  And ran the benchmark again just the first 100, 200,
// 400, ..., 25,600 of the certificates.  For smaller keyrings, a
// batch size of 8 remained optimal.  For enormous keyrings slightly
// larger batches were better (16), but only marginally so.
//
// Since we expect few users to have more than a few thousand
// certificates, we fix the chunk size to 8.
const CERTS_PER_CHUNK: usize = 8;

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
    let ppr: PacketParserResult = PacketParser::from_reader(input)
        .context("Reading keyring")?;

    let parser = CertParser {
        ppr: ppr,
        state: CertParserState::Start,
    };

    let p = |chunks: Vec<openpgp::Result<Vec<Packet>>>|
        -> Vec<openpgp::Result<Cert>>
    {
        chunks
            .into_iter()
            .map(|packets| {
                match packets {
                    Err(err) => {
                        Err(err)
                    }
                    Ok(packets) => {
                        match Cert::from_packets(packets.into_iter()) {
                            Err(err) => {
                                Err(err)
                            }
                            Ok(cert) => {
                                Ok(cert)
                            }
                        }
                    }
                }
            })
            .collect()
    };

    let mut parser = Chunked::new(CERTS_PER_CHUNK, parser);

    let mut chunk: Option<Vec<openpgp::Result<Vec<Packet>>>>
        = parser.next();
    let mut certs: Vec<openpgp::Result<Cert>> = Vec::new();
    if chunk.as_ref().map(|v| v.len()).unwrap_or(0) < CERTS_PER_CHUNK {
        // We have less than a chunk worth of certificates.  Avoid
        // spinning up a thread.
        if let Some(c) = chunk.take() {
            certs.extend(p(c));
        }
    } else {
        while let Some(c) = chunk.take() {
            rayon::join(|| certs.extend(p(c)),
                        || chunk = parser.next());
        }
    }

    Ok(certs)
}

#[cfg(test)]
mod tests {
    use super::*;

    use openpgp::serialize::Serialize;
    use openpgp::types::DataFormat;

    // How much junk the packet parser is willing to skip when
    // recovering (as of 1.1).  This is an internal implementation
    // detail.
    const RECOVERY_THRESHOLD: usize = 32 * 1024;

    fn t(n: usize, literal: bool, bad: usize) -> openpgp::Result<()> {
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

        eprintln!("n: {}, literals: {}, bad data: {}",
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

        eprintln!("Start of data: {} {}",
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
            eprintln!("{}. {}",
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

        assert_eq!(
            certs_orig.iter()
                .map(|c| {
                    c.fingerprint()
                })
                .collect::<Vec<_>>(),
            certs_parsed.iter()
                .map(|c| {
                    c.fingerprint()
                })
                .collect::<Vec<_>>());

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
            eprintln!("n: {}", n);

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
}
