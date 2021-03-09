use rayon::prelude::*;
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

    // par_bridge doesn't guarantee the order.
    let mut certs: Vec<(usize, openpgp::Result<Cert>)> = parser
        .enumerate()
        .par_bridge()
        .map(|(i, packets)| {
            (i, match packets {
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
            })
        })
        .collect();

    // Restore the order.
    certs.sort_by_key(|(i, _)| *i);

    let certs = certs
        .into_iter()
        .map(|(_, cert)| cert)
        .collect();

    Ok(certs)
}

#[cfg(test)]
mod tests {
    use super::*;

    use openpgp::serialize::Serialize;
    use openpgp::types::DataFormat;

    #[test]
    fn parse_keyring_simple() -> openpgp::Result<()> {
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
        let nulls = vec![ 0; 64 * 1024 ];

        for n in [1, 100, 0].iter() { for literal in [false, true].iter() { for bad in [ 0, 1, nulls.len() ].iter() {
            eprintln!("n: {}, literals: {}, bad data: {}",
                      n, literal, bad);

            let mut data = Vec::new();

            let mut certs_orig = vec![];
            for i in 0..*n {
                let (cert, _) =
                    CertBuilder::general_purpose(
                        None, Some(format!("{}@example.org", i)))
                    .generate()?;

                cert.as_tsk().serialize(&mut data)?;
                certs_orig.push(cert);

                if *literal {
                    let mut lit = Literal::new(DataFormat::Text);
                    lit.set_body(b"data".to_vec());

                    Packet::from(lit).serialize(&mut data)?;
                }
                // Push some NUL bytes.
                data.extend(&nulls[..*bad]);
            }
            if *n == 0 {
                // Push some NUL bytes even if we didn't add any packets.
                data.extend(&nulls[..*bad]);
            }
            assert_eq!(certs_orig.len(), *n);

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

            let certs_parsed = if *n == 0 && *bad > 0 {
                // Junk at the beginning of the file results in an
                // immediate parse error.
                assert!(certs_parsed.is_err());
                continue;
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

            let n = if *bad == nulls.len() {
                // We stop once we see the junk.
                certs_orig.drain(1..);
                std::cmp::min(*n, 1)
            } else {
                *n
            };

            let modulus = if *literal && *bad > 0 {
                3
            } else {
                2
            };
            let certs_parsed: Vec<Cert> = certs_parsed.into_iter()
                .enumerate()
                .filter_map(|(i, c)| {
                    if *literal && i % modulus == 1 {
                        // Literals should be errors.
                        assert!(c.is_err());
                        None
                    } else if *bad > 0 && n == 0 && i == 0 {
                        // The first byte in the input is the NUL
                        // byte.
                        assert!(c.is_err());
                        None
                    } else if *bad > 0 && i % modulus == modulus - 1 {
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
                if *bad > 0 && ! literal && i == n - 1 {
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
        }}}

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
