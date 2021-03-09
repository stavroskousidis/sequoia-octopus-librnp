use rayon::prelude::*;

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
    ParserError,
}

struct CertParser<'a> {
    ppr: PacketParserResult<'a>,
    state: CertParserState,
    parser_error: &'a mut Option<anyhow::Error>,
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
            CertParserState::ParserError => {
                // self.state was reset by the replace.  Restore the
                // error.
                self.state = CertParserState::ParserError;
                return None;
            }
        }

        while let PacketParserResult::Some(pp) = self.ppr.take() {
            // Get the packet out of the parser and start parsing the next
            // packet.
            let packet = match pp.next() {
                Err(err) => {
                    self.state = CertParserState::ParserError;
                    *self.parser_error = Some(err);
                    return None;
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
    let ppr: PacketParserResult =
        PacketParser::from_reader(input)?;

    let mut parser_error = None;
    let parser = CertParser {
        ppr: ppr,
        state: CertParserState::Start,
        parser_error: &mut parser_error,
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

    if let Some(err) = parser_error {
        return Err(err);
    }

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
        for n in [1, 100, 0].iter() { for literal in [false, true].iter() { for bad in [ false, true ].iter() {
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
                if *bad {
                    // Push a NUL byte.
                    data.push(0);
                }
            }
            if *n == 0 && *bad {
                // Push a NUL byte.
                data.push(0);
            }

            let certs_parsed = parse_keyring(std::io::Cursor::new(data));
            let certs_parsed = if *bad {
                // If the file includes invalid data, then we
                // shouldn't get any certificates back.
                assert!(certs_parsed.is_err());
                continue;
            } else {
                certs_parsed.expect("Valid parse")
            };

            certs_parsed.iter().enumerate().for_each(|(i, r)| {
                eprintln!("{}. {}",
                          i,
                          match r {
                              Ok(c) => c.fingerprint().to_string(),
                              Err(err) => err.to_string(),
                          });
            });

            let certs_parsed: Vec<Cert> = certs_parsed.into_iter()
                .enumerate()
                .filter_map(|(i, c)| {
                    if *literal && i % 2 == 1 {
                        // Literals should be errors.
                        assert!(c.is_err());
                        None
                    } else {
                        Some(c.unwrap())
                    }
                })
                .collect();

            assert_eq!(certs_orig.len(), *n);
            assert_eq!(certs_orig.len(), certs_parsed.len());

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
                assert_eq!(ps_orig.len(), ps_parsed.len());

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
