use std::io::{self, Read};

use sequoia_openpgp as openpgp;
use openpgp::armor::ReaderMode;
use self::openpgp::types::SymmetricAlgorithm;
use self::openpgp::fmt::hex;
use self::openpgp::crypto::mpi;
use self::openpgp::{Packet, Result};
use self::openpgp::packet;
use self::openpgp::packet::prelude::*;
use self::openpgp::packet::header::CTB;
use self::openpgp::packet::{Header, header::BodyLength, Signature};
use self::openpgp::packet::signature::subpacket::{Subpacket, SubpacketValue};
use self::openpgp::crypto::S2K;
use self::openpgp::parse::{
    Dearmor,
    Parse,
    PacketParserBuilder,
    PacketParserResult,
    map::Map,
};

/// Converts sequoia_openpgp types for rendering.
pub trait Convert<T> {
    /// Performs the conversion.
    fn convert(self) -> T;
}

impl Convert<humantime::FormattedDuration> for std::time::Duration {
    fn convert(self) -> humantime::FormattedDuration {
        humantime::format_duration(self)
    }
}

impl Convert<humantime::FormattedDuration> for openpgp::types::Duration {
    fn convert(self) -> humantime::FormattedDuration {
        humantime::format_duration(self.into())
    }
}

impl Convert<chrono::DateTime<chrono::offset::Utc>> for std::time::SystemTime {
    fn convert(self) -> chrono::DateTime<chrono::offset::Utc> {
        chrono::DateTime::<chrono::offset::Utc>::from(self)
    }
}

impl Convert<chrono::DateTime<chrono::offset::Utc>> for openpgp::types::Timestamp {
    fn convert(self) -> chrono::DateTime<chrono::offset::Utc> {
        std::time::SystemTime::from(self).convert()
    }
}

/// Holds a session key as parsed from the command line, with an optional
/// algorithm specifier.
///
/// This struct does not implement [`Display`] to prevent accidental leaking
/// of key material. If you are sure you want to print a session key, use
/// [`display_sensitive`].
///
/// [`Display`]: std::fmt::Display
/// [`display_sensitive`]: SessionKey::display_sensitive
#[derive(Debug, Clone)]
pub struct SessionKey {
    pub session_key: openpgp::crypto::SessionKey,
    pub symmetric_algo: Option<SymmetricAlgorithm>,
}


impl SessionKey {
    /// Returns an object that implements Display for explicitly opting into
    /// printing a `SessionKey`.
    pub fn display_sensitive(&self) -> SessionKeyDisplay {
        SessionKeyDisplay { csk: self }
    }
}

/// Helper struct for intentionally printing session keys with format! and {}.
///
/// This struct implements the `Display` trait to print the session key. This
/// construct requires the user to explicitly call
/// [`SessionKey::display_sensitive`]. By requiring the user to opt-in, this
/// will hopefully reduce that the chance that the session key is inadvertently
/// leaked, e.g., in a log that may be publicly posted.
pub struct SessionKeyDisplay<'a> {
    csk: &'a SessionKey,
}

/// Print the session key without prefix in hexadecimal representation.
impl<'a> std::fmt::Display for SessionKeyDisplay<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let sk = self.csk;
        write!(f, "{}", hex::encode(&sk.session_key))
    }
}

#[derive(Debug)]
pub enum Kind {
    Message {
        encrypted: bool,
    },
    Keyring,
    Cert,
    Unknown,
}

#[allow(clippy::redundant_pattern_matching)]
pub fn dump<W>(input: &mut (dyn io::Read + Sync + Send),
               output: &mut dyn io::Write,
               max_decompressed_literal_data: Option<usize>,
               mpis: bool, hex: bool,
               sk: Option<&SessionKey>,
               width: W)
               -> Result<Kind>
    where W: Into<Option<usize>>
{
    rnp_function!(dump, crate::TRACE);

    // If no limit is supplied, stop after 100 MB.
    let max_decompressed_literal_data
        = max_decompressed_literal_data.unwrap_or(100 * 1024 * 1024);
    let mut saw_decompression_packet = false;

    let mut ppr
        = self::openpgp::parse::PacketParserBuilder::from_reader(input)?;

    // To produce hex dumps, we need to enable mapping, but also turn
    // on buffering.  This makes sure that the map contains the whole
    // packet content, even if it has not been parsed (such as when
    // encountering unknown or junk pseudo packets).
    if hex {
        ppr = ppr.map(true).buffer_unread_content();
    }

    let mut ppr = ppr.build()?;

    let width = width.into().unwrap_or(80);
    let mut first_armor_block = true;
    let mut is_keyring = true;

  loop {
    let mut dumper = PacketDumper::new(width, mpis);
    let mut message_encrypted = false;
    let mut pkesks = vec![];
    let mut skesks = vec![];

    while let PacketParserResult::Some(mut pp) = ppr {
        let additional_fields = match pp.packet {
            Packet::PKESK(ref p) => {
                pkesks.push(p.clone());
                vec![]
            },
            Packet::SKESK(ref p) => {
                skesks.push(p.clone());
                vec![]
            },
            Packet::CompressedData(_) => {
                t!("Encountered compressed data packet.  \
                    Activating zip bomb protection.");
                saw_decompression_packet = true;
                Vec::new()
            }
            Packet::Literal(_) => {
                let mut prefix = vec![0; 40];
                let n = pp.read(&mut prefix)?;
                let summary = vec![
                    format!("Content: {:?}{}",
                            String::from_utf8_lossy(&prefix[..n]),
                            if n == prefix.len() { "..." } else { "" }),
                ];

                if saw_decompression_packet {
                    // Protect against a possible zip bomb.
                    t!("Zip bomb protection activated.  Will abort after \
                        reading more than {} bytes of literal data.",
                       max_decompressed_literal_data);

                    const BUFFER_SIZE: usize = 1024 * 1024;
                    let mut buffer = vec![0; BUFFER_SIZE];
                    let mut literal_data_read = prefix.len();
                    while literal_data_read <= max_decompressed_literal_data {
                        let remaining
                            = max_decompressed_literal_data - literal_data_read + 1;

                        let read = pp.read(
                            &mut buffer[..remaining.min(BUFFER_SIZE)])?;
                        if read == 0 {
                            // EOF.
                            break;
                        }

                        literal_data_read += read;
                    }
                    t!("Read {} bytes of literal data",
                       literal_data_read);

                    if literal_data_read > max_decompressed_literal_data {
                        t!("Zip bomb detected");
                        return Err(crate::Error::BadParameters.into());
                    } else {
                        t!("No zip bomb detected");
                    }
                }

                summary
            },
            Packet::SEIP(ref s) => {
		let version = s.version();
                message_encrypted = true;

                if let Some(sk) = &sk {
                    let decrypted_with = match s {
		        SEIP::V2(s) => {
			    // No need for guessing.
			    let algo = s.symmetric_algo();
			    pp.decrypt(algo, &sk.session_key).ok().map(|_| algo)
		        },
		        _ => {
			    // We don't know which algorithm to use,
			    // try to find one that decrypts the message.
			    (1u8..=19)
                                .map(SymmetricAlgorithm::from)
                                .find(|algo| pp.decrypt(*algo, &sk.session_key).is_ok())
		        },
                    };

                    let mut fields = Vec::new();
                    fields.push(format!("Session key: {}", hex::encode(&sk.session_key)));
                    if let Some(algo) = decrypted_with {
		        if version == 1 {
			    // For v2, the packet already contains that
			    // information.
			    fields.push(format!("Symmetric algo: {}", algo));
		        }
                        fields.push("Decryption successful".into());
                    } else {
                        fields.push("Decryption failed".into());
                    }
                    fields
                } else {
                    vec!["No session key supplied".into()]
                }
            },
            _ => Vec::new(),
        };

        let header = pp.header().clone();
        let map = pp.take_map();

        let recursion_depth = pp.recursion_depth();
        let packet = pp.packet.clone();

        dumper.packet(output, recursion_depth as usize,
                      header, packet, map, additional_fields)?;

        let (_, ppr_) = match pp.recurse() {
            Ok(v) => Ok(v),
            Err(e) => {
                let _ = dumper.flush(output);
                Err(e)
            },
        }?;
        ppr = ppr_;
    }

    dumper.flush(output)?;

    if let PacketParserResult::EOF(eof) = ppr {
        let is_message = eof.is_message().is_ok() && first_armor_block;
        let is_cert = eof.is_cert().is_ok() && first_armor_block;
        is_keyring &= eof.is_keyring().is_ok();
        first_armor_block = false;

        // Now, the parser is exhausted, but we may find another
        // armored blob.  Note that this can only happen if the first
        // set of packets was also armored.
        match PacketParserBuilder::from_buffered_reader(eof.into_reader())
            .and_then(
                |builder| builder
                    .dearmor(Dearmor::Enabled(
                        ReaderMode::Tolerant(None)))
                    .build())
        {
            Ok(ppr_) => {
                writeln!(output, "Note: There is another block of armored \
                                  OpenPGP data.")?;

                if is_message {
                    writeln!(output, "Note: Data concatenated to a message is \
                                      likely an error.")?;
                } else if is_cert || is_keyring {
                    writeln!(output, "Note: This is a non-standard extension \
                                      to OpenPGP.")?;
                }
                writeln!(output)?;

                ppr = ppr_;
                continue;
            },
            Err(_) => break if is_message {
                Ok(Kind::Message {
                    encrypted: message_encrypted,
                })
            } else if is_cert {
                Ok(Kind::Cert)
            } else if is_keyring {
                Ok(Kind::Keyring)
            } else {
                Ok(Kind::Unknown)
            }
        }
    } else {
        unreachable!()
    }
  }
}

struct Node {
    header: Header,
    packet: Packet,
    map: Option<Map>,
    additional_fields: Vec<String>,
    children: Vec<Node>,
}

impl Node {
    fn new(header: Header, packet: Packet, map: Option<Map>,
           additional_fields: Vec<String>) -> Self {
        Node {
            header,
            packet,
            map,
            additional_fields,
            children: Vec::new(),
        }
    }

    fn append(&mut self, depth: usize, node: Node) {
        if depth == 0 {
            self.children.push(node);
        } else {
            self.children.iter_mut().last().unwrap().append(depth - 1, node);
        }
    }
}

pub struct PacketDumper {
    width: usize,
    mpis: bool,
    root: Option<Node>,
}

impl PacketDumper {
    pub fn new(width: usize, mpis: bool) -> Self {
        PacketDumper {
            width,
            mpis,
            root: None,
        }
    }

    pub fn packet(&mut self, output: &mut dyn io::Write, depth: usize,
                  header: Header, p: Packet, map: Option<Map>,
                  additional_fields: Vec<String>)
                  -> Result<()> {
        let node = Node::new(header, p, map, additional_fields);
        if self.root.is_none() {
            assert_eq!(depth, 0);
            self.root = Some(node);
        } else if depth == 0 {
            let root = self.root.take().unwrap();
            self.dump_tree(output, "", &root)?;
            self.root = Some(node);
        } else {
            self.root.as_mut().unwrap().append(depth - 1, node);
        }
        Ok(())
    }

    pub fn flush(&self, output: &mut dyn io::Write) -> Result<()> {
        if let Some(root) = self.root.as_ref() {
            self.dump_tree(output, "", root)?;
        }
        Ok(())
    }

    fn dump_tree(&self, output: &mut dyn io::Write, indent: &str, node: &Node)
                 -> Result<()> {
        let indent_node =
            format!("{}{} ", indent,
                    if node.children.is_empty() { " " } else { "│" });
        self.dump_packet(output, &indent_node, Some(&node.header), &node.packet,
                         node.map.as_ref(), &node.additional_fields)?;
        if node.children.is_empty() {
            return Ok(());
        }

        let last = node.children.len() - 1;
        for (i, child) in node.children.iter().enumerate() {
            let is_last = i == last;
            write!(output, "{}{}── ", indent,
                   if is_last { "└" } else { "├" })?;
            let indent_child =
                format!("{}{}   ", indent,
                        if is_last { " " } else { "│" });
            self.dump_tree(output, &indent_child, child)?;
        }
        Ok(())
    }

    fn dump_packet(&self, mut output: &mut dyn io::Write, i: &str,
                  header: Option<&Header>, p: &Packet, map: Option<&Map>,
                  additional_fields: &Vec<String>)
                  -> Result<()> {
        use self::openpgp::Packet::*;

        if let Some(tag) = p.kind() {
            write!(output, "{}", tag)?;
        } else {
            write!(output, "Unknown or Unsupported Packet")?;
        }

        if let Some(h) = header {
            write!(output, ", {} CTB, {}{}",
                   if let CTB::Old(_) = h.ctb() { "old" } else { "new" },
                   if let Some(map) = map {
                       format!("{} header bytes + ",
                               map.iter().take(2).map(|f| f.as_bytes().len())
                                   .sum::<usize>())
                   } else {
                       // XXX: Mapping is disabled.  No can do for
                       // now.  Once we save the header in
                       // packet::Common, we can use this instead of
                       // relying on the map.
                       "".into()
                   },
                   match h.length() {
                       BodyLength::Full(n) =>
                           format!("{} bytes", n),
                       BodyLength::Partial(n) =>
                           format!("partial length, {} bytes in first chunk", n),
                       BodyLength::Indeterminate =>
                           "indeterminate length".into(),
                   })?;
        }
        writeln!(output)?;

        #[allow(deprecated)]
        match p {
            Unknown(ref u) => {
                writeln!(output, "{}  Tag: {}", i, u.tag())?;
                writeln!(output, "{}  Error: {}", i, u.error())?;
            },

            PublicKey(ref k) => self.dump_key(output, i, k)?,
            PublicSubkey(ref k) => self.dump_key(output, i, k)?,
            SecretKey(ref k) => self.dump_key(output, i, k)?,
            SecretSubkey(ref k) => self.dump_key(output, i, k)?,

            Signature(s) => self.dump_signature(output, i, s)?,

            OnePassSig(ref o) => {
                writeln!(output, "{}  Version: {}", i, o.version())?;
                writeln!(output, "{}  Type: {}", i, o.typ())?;
                writeln!(output, "{}  Pk algo: {}", i, o.pk_algo())?;
                writeln!(output, "{}  Hash algo: {}", i, o.hash_algo())?;
                writeln!(output, "{}  Issuer: {}", i, o.issuer())?;
		if let packet::OnePassSig::V6(o) = o {
                    writeln!(output, "{}  Salt: {}", i, hex::encode(o.salt()))?;
		}
                writeln!(output, "{}  Last: {}", i, o.last())?;
            },

            Trust(ref p) => {
                writeln!(output, "{}  Value:", i)?;
                let mut hd = hex::Dumper::new(
                    &mut output,
                    self.indentation_for_hexdump(&format!("{}  ", i), 16));
                hd.write_ascii(p.value())?;
            },

            UserID(ref u) => {
                writeln!(output, "{}  Value: {}", i,
                         String::from_utf8_lossy(u.value()))?;
            },

            UserAttribute(ref u) => {
                use self::openpgp::packet::user_attribute::{Subpacket, Image};
                use openpgp::serialize::MarshalInto;

                for subpacket in u.subpackets() {
                    match subpacket {
                        Ok(Subpacket::Image(image)) => match image {
                            Image::JPEG(data) =>
                                writeln!(output, "{}    JPEG: {} bytes", i,
                                         data.len())?,
                            Image::Private(n, data) =>
                                writeln!(output,
                                         "{}    Private image({}): {} bytes", i,
                                         n, data.len())?,
                            Image::Unknown(n, data) =>
                                writeln!(output,
                                         "{}    Unknown image({}): {} bytes", i,
                                         n, data.len())?,
                            _ =>
                                writeln!(output,
                                         "{}    Unknown image: {} bytes", i,
                                         image.serialized_len())?,
                        },
                        Ok(Subpacket::Unknown(n, data)) =>
                            writeln!(output,
                                     "{}    Unknown subpacket({}): {} bytes", i,
                                     n, data.len())?,
                        Ok(u) =>
                            writeln!(output,
                                     "{}    Unknown subpacket: {} bytes", i,
                                     u.serialized_len())?,
                        Err(e) =>
                            writeln!(output,
                                     "{}    Invalid subpacket encoding: {}", i,
                                     e)?,
                    }
                }
            },

            Marker(_) => {
            },

            Literal(ref l) => {
                writeln!(output, "{}  Format: {}", i, l.format())?;
                if let Some(filename) = l.filename() {
                    writeln!(output, "{}  Filename: {:?}", i,
                             String::from_utf8_lossy(filename))?;
                }
                if let Some(timestamp) = l.date() {
                    writeln!(output, "{}  Timestamp: {}", i,
                             timestamp.convert())?;
                }
            },

            CompressedData(ref c) => {
                writeln!(output, "{}  Algorithm: {}", i, c.algo())?;
            },

            PKESK(ref p) => {
                writeln!(output, "{}  Version: {}", i, p.version())?;
                writeln!(output, "{}  Recipient: {}", i,
                         p.recipient().as_ref().map(ToString::to_string)
                         .unwrap_or_else(|| "<anonymous recipient>".into()))?;
                writeln!(output, "{}  Pk algo: {}", i, p.pk_algo())?;
                if self.mpis {
                    writeln!(output, "{}", i)?;
                    writeln!(output, "{}  Encrypted session key:", i)?;

                    let ii = format!("{}    ", i);
                    match p.esk() {
                        mpi::Ciphertext::X25519 { e, key } =>
                            self.dump_mpis(output, &ii,
                                           &[&e[..], key],
                                           &["e", "key"])?,
                        mpi::Ciphertext::X448 { e, key } =>
                            self.dump_mpis(output, &ii,
                                           &[&e[..], key],
                                           &["e", "key"])?,
                        mpi::Ciphertext::RSA { c } =>
                            self.dump_mpis(output, &ii,
                                           &[c.value()],
                                           &["c"])?,
                        mpi::Ciphertext::ElGamal { e, c } =>
                            self.dump_mpis(output, &ii,
                                           &[e.value(), c.value()],
                                           &["e", "c"])?,
                        mpi::Ciphertext::ECDH { e, key } =>
                            self.dump_mpis(output, &ii,
                                           &[e.value(), key],
                                           &["e", "key"])?,
                        mpi::Ciphertext::Unknown { mpis, rest } => {
                            let keys: Vec<String> =
                                (0..mpis.len()).map(
                                    |i| format!("mpi{}", i)).collect();
                            self.dump_mpis(
                                output, &ii,
                                &mpis.iter().map(|m| {
                                    m.value().iter().as_slice()
                                }).collect::<Vec<_>>()[..],
                                &keys.iter().map(|k| k.as_str())
                                    .collect::<Vec<_>>()[..],
                            )?;

                            self.dump_mpis(output, &ii, &[rest], &["rest"])?;
                        },

                        // crypto::mpi::Ciphertext is non-exhaustive.
                        u => writeln!(output, "{}Unknown variant: {:?}", ii, u)?,
                    }
                }
            },

            SKESK(ref s) => {
                writeln!(output, "{}  Version: {}", i, s.version())?;
                match s {
                    self::openpgp::packet::SKESK::V4(ref s) => {
                        writeln!(output, "{}  Symmetric algo: {}", i,
                                 s.symmetric_algo())?;
                        write!(output, "{}  S2K: ", i)?;
                        self.dump_s2k(output, i, s.s2k())?;
                        if let Ok(Some(esk)) = s.esk() {
                            writeln!(output, "{}  ESK: {}", i,
                                     hex::encode(esk))?;
                        }
                    },

                    self::openpgp::packet::SKESK::V6(ref s) => {
                        writeln!(output, "{}  Symmetric algo: {}", i,
                                 s.symmetric_algo())?;
                        writeln!(output, "{}  AEAD: {}", i,
                                 s.aead_algo())?;
                        write!(output, "{}  S2K: ", i)?;
                        self.dump_s2k(output, i, s.s2k())?;
                        writeln!(output, "{}  IV: {}", i,
                                 hex::encode(s.aead_iv()))?;
                        writeln!(output, "{}  ESK: {}", i,
                                 hex::encode(s.esk()))?;
                    },

                    // SKESK is non-exhaustive.
                    u => writeln!(output, "{}    Unknown variant: {:?}", i, u)?,
                }
            },

            SEIP(ref s) => {
                writeln!(output, "{}  Version: {}", i, s.version())?;
                match s {
                    packet::SEIP::V1(_) => (),
                    packet::SEIP::V2(s) => {
                        writeln!(output, "{}  Symmetric algo: {}", i, s.symmetric_algo())?;
                        writeln!(output, "{}  AEAD algo: {}", i, s.aead())?;
                        writeln!(output, "{}  Chunk size: {}", i, s.chunk_size())?;
                        writeln!(output, "{}  Salt: {}", i, hex::encode(s.salt()))?;
                    },
                    _ => (),
                }
            },

            MDC(ref m) => {
                writeln!(output, "{}  Digest: {}",
                         i, hex::encode(m.digest()))?;
                writeln!(output, "{}  Computed digest: {}",
                         i, hex::encode(m.computed_digest()))?;
                writeln!(output, "{}  Valid: {}",
                         i, m.valid())?;
            },

            Padding(_) => {
                // Nothing to do.
            }

            // openpgp::Packet is non-exhaustive.
            u => writeln!(output, "{}    Unknown variant: {:?}", i, u)?,
        }

        for field in additional_fields {
            writeln!(output, "{}  {}", i, field)?;
        }

        writeln!(output, "{}", i)?;

        if let Some(map) = map {
            if map.iter().next().is_none() {
                // There is no data, we cannot dump anything.
                return Ok(());
            }

            let mut hd = hex::Dumper::new(output, self.indentation_for_hexdump(
                i, map.iter()
                    .map(|f| if f.name() == "body" { 16 } else { f.name().len() })
                    .max()
                    .expect("we checked that there is one entry")));

            for field in map.iter() {
                if field.name() == "body" {
                    hd.write_ascii(field.as_bytes())?;
                } else {
                    hd.write(field.as_bytes(), field.name())?;
                }
            }

            let output = hd.into_inner();
            writeln!(output, "{}", i)?;
        }

        Ok(())
    }

    /// Dumps the given key packet.
    fn dump_key<P, R>(&self, output: &mut dyn io::Write, i: &str,
                      k: &Key<P, R>)
                      -> Result<()>
    where
        P: key::KeyParts,
        R: key::KeyRole,
    {
        self.dump_key_internal(
            output, i, k.parts_as_unspecified().role_as_unspecified())
    }

    /// Dumps the given key packet, prevents monomorphization of this
    /// big function.
    fn dump_key_internal(&self, output: &mut dyn io::Write, i: &str,
                         k: &Key<key::UnspecifiedParts, key::UnspecifiedRole>)
                         -> Result<()>
    {
        writeln!(output, "{}  Version: {}", i, k.version())?;
        writeln!(output, "{}  Creation time: {}", i,
                 k.creation_time().convert())?;
        writeln!(output, "{}  Pk algo: {}", i, k.pk_algo())?;
        if let Some(bits) = k.mpis().bits() {
            writeln!(output, "{}  Pk size: {} bits", i, bits)?;
        }
        writeln!(output, "{}  Fingerprint: {}", i, k.fingerprint())?;
        writeln!(output, "{}  KeyID: {}", i, k.keyid())?;
        if self.mpis {
            writeln!(output, "{}", i)?;
            writeln!(output, "{}  Public Key:", i)?;

            let ii = format!("{}    ", i);
            match k.mpis() {
                mpi::PublicKey::X25519 { u } =>
                    self.dump_mpis(output, &ii, &[u], &["u"])?,
                mpi::PublicKey::X448 { u } =>
                    self.dump_mpis(output, &ii, &[&u[..]], &["u"])?,
                mpi::PublicKey::Ed25519 { a } =>
                    self.dump_mpis(output, &ii, &[a], &["a"])?,
                mpi::PublicKey::Ed448 { a } =>
                    self.dump_mpis(output, &ii, &[&a[..]], &["a"])?,
                mpi::PublicKey::RSA { e, n } =>
                    self.dump_mpis(output, &ii,
                                 &[e.value(), n.value()],
                                 &["e", "n"])?,
                mpi::PublicKey::DSA { p, q, g, y } =>
                    self.dump_mpis(output, &ii,
                                 &[p.value(), q.value(), g.value(),
                                   y.value()],
                                 &["p", "q", "g", "y"])?,
                mpi::PublicKey::ElGamal { p, g, y } =>
                    self.dump_mpis(output, &ii,
                                 &[p.value(), g.value(), y.value()],
                                 &["p", "g", "y"])?,
                mpi::PublicKey::EdDSA { curve, q } => {
                    writeln!(output, "{}  Curve: {}", ii, curve)?;
                    self.dump_mpis(output, &ii, &[q.value()], &["q"])?;
                },
                mpi::PublicKey::ECDSA { curve, q } => {
                    writeln!(output, "{}  Curve: {}", ii, curve)?;
                    self.dump_mpis(output, &ii, &[q.value()], &["q"])?;
                },
                mpi::PublicKey::ECDH { curve, q, hash, sym } => {
                    writeln!(output, "{}  Curve: {}", ii, curve)?;
                    writeln!(output, "{}  KDF hash algo: {}", ii, hash)?;
                    writeln!(output, "{}  KEK symmetric algo: {}", ii,
                             sym)?;
                    self.dump_mpis(output, &ii, &[q.value()], &["q"])?;
                },
                mpi::PublicKey::Unknown { mpis, rest } => {
                    let keys: Vec<String> =
                        (0..mpis.len()).map(
                            |i| format!("mpi{}", i)).collect();
                    self.dump_mpis(
                        output, &ii,
                        &mpis.iter().map(|m| {
                            m.value().iter().as_slice()
                        }).collect::<Vec<_>>()[..],
                        &keys.iter().map(|k| k.as_str())
                            .collect::<Vec<_>>()[..],
                    )?;

                    self.dump_mpis(output, &ii, &[&rest[..]], &["rest"])?;
                },

                // crypto::mpi:Publickey is non-exhaustive
                u => writeln!(output, "{}Unknown variant: {:?}", ii, u)?,
            }
        }

        if let Some(secrets) = k.optional_secret() {
            writeln!(output, "{}", i)?;
            writeln!(output, "{}  Secret Key:", i)?;

            let ii = format!("{}    ", i);
            match secrets {
                SecretKeyMaterial::Unencrypted(ref u) => {
                    writeln!(output, "{}", i)?;
                    writeln!(output, "{}  Unencrypted", ii)?;
                    if self.mpis {
                        u.map(|mpis| -> Result<()> {
                            match mpis
                            {
                                mpi::SecretKeyMaterial::X25519 { x } =>
                                    self.dump_mpis(output, &ii,
                                                   &[x], &["x"])?,
                                mpi::SecretKeyMaterial::X448 { x } =>
                                    self.dump_mpis(output, &ii,
                                                   &[&x[..]], &["x"])?,
                                mpi::SecretKeyMaterial::Ed25519 { x } =>
                                    self.dump_mpis(output, &ii,
                                                   &[x], &["x"])?,
                                mpi::SecretKeyMaterial::Ed448 { x } =>
                                    self.dump_mpis(output, &ii,
                                                   &[&x[..]], &["x"])?,
                                mpi::SecretKeyMaterial::RSA { d, p, q, u } =>
                                    self.dump_mpis(output, &ii,
                                                 &[d.value(), p.value(),
                                                   q.value(), u.value()],
                                                 &["d", "p", "q", "u"])?,
                                mpi::SecretKeyMaterial::DSA { x } =>
                                    self.dump_mpis(output, &ii, &[x.value()],
                                                 &["x"])?,
                                mpi::SecretKeyMaterial::ElGamal { x } =>
                                    self.dump_mpis(output, &ii, &[x.value()],
                                                 &["x"])?,
                                mpi::SecretKeyMaterial::EdDSA { scalar } =>
                                    self.dump_mpis(output, &ii,
                                                 &[scalar.value()],
                                                 &["scalar"])?,
                                mpi::SecretKeyMaterial::ECDSA { scalar } =>
                                    self.dump_mpis(output, &ii,
                                                 &[scalar.value()],
                                                 &["scalar"])?,
                                mpi::SecretKeyMaterial::ECDH { scalar } =>
                                    self.dump_mpis(output, &ii,
                                                 &[scalar.value()],
                                                 &["scalar"])?,
                                mpi::SecretKeyMaterial::Unknown { mpis, rest } => {
                                    let keys: Vec<String> =
                                        (0..mpis.len()).map(
                                            |i| format!("mpi{}", i)).collect();
                                    self.dump_mpis(
                                        output, &ii,
                                        &mpis.iter().map(|m| {
                                            m.value().iter().as_slice()
                                        }).collect::<Vec<_>>()[..],
                                        &keys.iter().map(|k| k.as_str())
                                            .collect::<Vec<_>>()[..],
                                    )?;

                                    self.dump_mpis(output, &ii, &[rest],
                                                 &["rest"])?;
                                },

                                // crypto::mpi::SecretKeyMaterial is non-exhaustive.
                                u => writeln!(output, "{}Unknown variant: {:?}", ii, u)?,
                            }
                            Ok(())
                        })?;
                    }
                }
                SecretKeyMaterial::Encrypted(ref e) => {
                    writeln!(output, "{}", i)?;
                    writeln!(output, "{}  Encrypted", ii)?;
                    write!(output, "{}  S2K: ", ii)?;
                    self.dump_s2k(output, &ii, e.s2k())?;
                    writeln!(output, "{}  Sym. algo: {}", ii,
                             e.algo())?;
                    if self.mpis {
                        if let Ok(ciphertext) = e.ciphertext() {
                            self.dump_mpis(output, &ii, &[ciphertext],
                                         &["ciphertext"])?;
                        }
                    }
                },
            }
        }

        Ok(())
    }

    pub fn dump_signature(&self, output: &mut dyn io::Write, i: &str,
                          s: &Signature)
                          -> Result<()>
    {
        writeln!(output, "{}  Version: {}", i, s.version())?;
        writeln!(output, "{}  Type: {}", i, s.typ())?;
        writeln!(output, "{}  Pk algo: {}", i, s.pk_algo())?;
        writeln!(output, "{}  Hash algo: {}", i, s.hash_algo())?;
        if s.hashed_area().iter().count() > 0 {
            writeln!(output, "{}  Hashed area:", i)?;
            for pkt in s.hashed_area().iter() {
                self.dump_subpacket(output, i, pkt, s)?;
            }
        }
        if s.unhashed_area().iter().count() > 0 {
            writeln!(output, "{}  Unhashed area:", i)?;
            for pkt in s.unhashed_area().iter() {
                self.dump_subpacket(output, i, pkt, s)?;
            }
        }
        writeln!(output, "{}  Digest prefix: {}", i,
                 hex::encode(s.digest_prefix()))?;
	if let packet::Signature::V6(s) = s {
            writeln!(output, "{}  Salt: {}", i, hex::encode(s.salt()))?;
	}
        write!(output, "{}  Level: {} ", i, s.level())?;
        match s.level() {
            0 => writeln!(output, "(signature over data)")?,
            1 => writeln!(output, "(notarization over signatures \
                                   level 0 and data)")?,
            n => writeln!(output, "(notarization over signatures \
                                   level <= {} and data)", n - 1)?,
        }
        if self.mpis {
            writeln!(output, "{}", i)?;
            writeln!(output, "{}  Signature:", i)?;

            let ii = format!("{}    ", i);
            match s.mpis() {
                mpi::Signature::Ed25519 { s } =>
                    self.dump_mpis(output, &ii, &[&s[..]], &["s"])?,
                mpi::Signature::Ed448 { s } =>
                    self.dump_mpis(output, &ii, &[&s[..]], &["s"])?,
                mpi::Signature::RSA { s } =>
                    self.dump_mpis(output, &ii,
                                   &[s.value()],
                                   &["s"])?,
                mpi::Signature::DSA { r, s } =>
                    self.dump_mpis(output, &ii,
                                   &[r.value(), s.value()],
                                   &["r", "s"])?,
                mpi::Signature::ElGamal { r, s } =>
                    self.dump_mpis(output, &ii,
                                   &[r.value(), s.value()],
                                   &["r", "s"])?,
                mpi::Signature::EdDSA { r, s } =>
                    self.dump_mpis(output, &ii,
                                   &[r.value(), s.value()],
                                   &["r", "s"])?,
                mpi::Signature::ECDSA { r, s } =>
                    self.dump_mpis(output, &ii,
                                   &[r.value(), s.value()],
                                   &["r", "s"])?,
                mpi::Signature::Unknown { mpis, rest } => {
                    let keys: Vec<String> =
                        (0..mpis.len()).map(
                            |i| format!("mpi{}", i)).collect();
                    self.dump_mpis(
                        output, &ii,
                        &mpis.iter().map(|m| {
                            m.value().iter().as_slice()
                        }).collect::<Vec<_>>()[..],
                        &keys.iter().map(|k| k.as_str())
                            .collect::<Vec<_>>()[..],
                    )?;

                    self.dump_mpis(output, &ii, &[&rest[..]], &["rest"])?;
                },

                // crypto::mpi::Signature is non-exhaustive.
                u => writeln!(output, "{}Unknown variant: {:?}", ii, u)?,
            }
        }

        Ok(())
    }

    fn dump_subpacket(&self, output: &mut dyn io::Write, i: &str,
                      s: &Subpacket, sig: &Signature)
                      -> Result<()> {
        use self::SubpacketValue::*;

        let hexdump_unknown = |output: &mut dyn io::Write, buf| -> Result<()> {
            let mut hd = hex::Dumper::new(output, self.indentation_for_hexdump(
                &format!("{}    ", i), 0));
            hd.write_labeled(buf, |_, _| None)?;
            Ok(())
        };

        #[allow(deprecated)]
        match s.value() {
            Unknown { body, .. } => {
                writeln!(output, "{}    {:?}{}:", i, s.tag(),
                         if s.critical() { " (critical)" } else { "" })?;
                hexdump_unknown(output, body.as_slice())?;
            },
            SignatureCreationTime(t) =>
                write!(output, "{}    Signature creation time: {}", i,
                       (*t).convert())?,
            SignatureExpirationTime(t) =>
                write!(output, "{}    Signature expiration time: {} ({})",
                       i, t.convert(),
                       if let Some(creation) = sig.signature_creation_time() {
                           (creation + (*t).into()).convert().to_string()
                       } else {
                           " (no Signature Creation Time subpacket)".into()
                       })?,
            ExportableCertification(e) =>
                write!(output, "{}    Exportable certification: {}", i, e)?,
            TrustSignature{level, trust} =>
                write!(output, "{}    Trust signature: level {} trust {}", i,
                       level, trust)?,
            RegularExpression(ref r) =>
                write!(output, "{}    Regular expression: {}", i,
                       String::from_utf8_lossy(r))?,
            Revocable(r) =>
                write!(output, "{}    Revocable: {}", i, r)?,
            KeyExpirationTime(t) =>
                write!(output, "{}    Key expiration time: {}", i,
                       t.convert())?,
            PreferredSymmetricAlgorithms(ref c) =>
                write!(output, "{}    Symmetric algo preferences: {}", i,
                       c.iter().map(|c| format!("{:?}", c))
                       .collect::<Vec<String>>().join(", "))?,
            RevocationKey(rk) => {
                let (pk_algo, fp) = rk.revoker();
                write!(output,
                       "{}    Revocation key: {}/{}", i,
                       fp, pk_algo)?;
                if rk.sensitive() {
                    write!(output, ", sensitive")?;
                }
            },
            Issuer(ref is) =>
                write!(output, "{}    Issuer: {}", i, is)?,
            NotationData(n) => if n.flags().human_readable() {
                write!(output, "{}    Notation: {}", i, n)?;
                if s.critical() {
                    write!(output, " (critical)")?;
                }
                writeln!(output)?;
            } else {
                write!(output, "{}    Notation: {}", i, n.name())?;
                let flags = format!("{:?}", n.flags());
                if ! flags.is_empty() {
                    write!(output, "{}", flags)?;
                }
                if s.critical() {
                    write!(output, " (critical)")?;
                }
                writeln!(output)?;
                hexdump_unknown(output, n.value())?;
            },
            PreferredHashAlgorithms(ref h) =>
                write!(output, "{}    Hash preferences: {}", i,
                       h.iter().map(|h| format!("{:?}", h))
                       .collect::<Vec<String>>().join(", "))?,
            PreferredCompressionAlgorithms(ref c) =>
                write!(output, "{}    Compression preferences: {}", i,
                       c.iter().map(|c| format!("{:?}", c))
                       .collect::<Vec<String>>().join(", "))?,
            KeyServerPreferences(ref p) =>
                write!(output, "{}    Keyserver preferences: {:?}", i, p)?,
            PreferredKeyServer(ref k) =>
                write!(output, "{}    Preferred keyserver: {}", i,
                       String::from_utf8_lossy(k))?,
            PrimaryUserID(p) =>
                write!(output, "{}    Primary User ID: {}", i, p)?,
            PolicyURI(ref p) =>
                write!(output, "{}    Policy URI: {}", i, String::from_utf8_lossy(p))?,
            KeyFlags(ref k) =>
                write!(output, "{}    Key flags: {:?}", i, k)?,
            SignersUserID(ref u) =>
                write!(output, "{}    Signer's User ID: {}", i,
                       String::from_utf8_lossy(u))?,
            ReasonForRevocation{code, ref reason} => {
                write!(output, "{}    Reason for revocation: {}{}{}", i, code,
                       if reason.len() > 0 { ", " } else { "" },
                       String::from_utf8_lossy(reason))?
            }
            Features(ref f) =>
                write!(output, "{}    Features: {:?}", i, f)?,
            SignatureTarget{pk_algo, hash_algo, ref digest} =>
                write!(output, "{}    Signature target: {}, {}, {}", i,
                       pk_algo, hash_algo, hex::encode(digest))?,
            EmbeddedSignature(_) =>
            // Embedded signature is dumped below.
                write!(output, "{}    Embedded signature: ", i)?,
            IssuerFingerprint(ref fp) =>
                write!(output, "{}    Issuer Fingerprint: {}", i, fp)?,

            IntendedRecipient(ref fp) =>
                write!(output, "{}    Intended Recipient: {}", i, fp)?,
            ApprovedCertifications(digests) => {
                write!(output, "{}    Approved Certifications:", i)?;
                if digests.is_empty() {
                    writeln!(output, " None")?;
                } else {
                    writeln!(output)?;
                    for d in digests {
                        writeln!(output, "{}      {}", i, hex::encode(d))?;
                    }
                }
            },
            PreferredAEADCiphersuites(p) =>
                write!(output, "{}    AEAD preferences: {}", i,
                       p.iter().map(|(symm, aead)|
                                    format!("{:?}+{:?}", symm, aead))
                       .collect::<Vec<String>>().join(", "))?,

            // SubpacketValue is non-exhaustive.
            u => writeln!(output, "{}    Unknown variant: {:?}", i, u)?,
        }

        match s.value() {
            Unknown { .. } => (),
            NotationData { .. } => (),
            EmbeddedSignature(ref sig) => {
                if s.critical() {
                    write!(output, " (critical)")?;
                }
                writeln!(output)?;
                let indent = format!("{}      ", i);
                write!(output, "{}", indent)?;
                self.dump_signature(output, &indent, sig)?;
            },
            _ => {
                if s.critical() {
                    write!(output, " (critical)")?;
                }
                writeln!(output)?;
            }
        }

        Ok(())
    }

    fn dump_s2k(&self, output: &mut dyn io::Write, i: &str, s2k: &S2K)
                -> Result<()> {
        use self::S2K::*;
        #[allow(deprecated)]
        match s2k {
            Implicit => {
                writeln!(output, "Implicit")?;
            },
            Simple { hash } => {
                writeln!(output, "Simple")?;
                writeln!(output, "{}    Hash: {}", i, hash)?;
            },
            Salted { hash, ref salt } => {
                writeln!(output, "Salted")?;
                writeln!(output, "{}    Hash: {}", i, hash)?;
                writeln!(output, "{}    Salt: {}", i, hex::encode(salt))?;
            },
            Iterated { hash, ref salt, hash_bytes } => {
                writeln!(output, "Iterated")?;
                writeln!(output, "{}    Hash: {}", i, hash)?;
                writeln!(output, "{}    Salt: {}", i, hex::encode(salt))?;
                writeln!(output, "{}    Hash bytes: {}", i, hash_bytes)?;
            },
            Argon2 { salt, t, p, m } => {
                writeln!(output, "Argon2")?;
                writeln!(output, "{}    Salt: {}", i, hex::encode(salt))?;
                writeln!(output, "{}    Passes: {}", i, t)?;
                writeln!(output, "{}    Parallelism: {}", i, p)?;
                writeln!(output, "{}    Memory: {} ({} KiB)", i, m,
                         2usize.pow((*m).into()))?;
            },
            Private { tag, parameters } => {
                writeln!(output, "Private")?;
                writeln!(output, "{}    Tag: {}", i, tag)?;
                if let Some(p) = parameters.as_ref() {
                    writeln!(output, "{}    Parameters: {:?}", i, p)?;
                }
            },
            Unknown { tag, parameters } => {
                writeln!(output, "Unknown")?;
                writeln!(output, "{}    Tag: {}", i, tag)?;
                if let Some(p) = parameters.as_ref() {
                    writeln!(output, "{}    Parameters: {:?}", i, p)?;
                }
            },

            // S2K is non-exhaustive
            u => writeln!(output, "{}    Unknown variant: {:?}", i, u)?,
        }
        Ok(())
    }

    fn dump_mpis(&self, output: &mut dyn io::Write, i: &str,
                 chunks: &[&[u8]], keys: &[&str]) -> Result<()> {
        assert_eq!(chunks.len(), keys.len());
        if chunks.is_empty() {
            return Ok(());
        }

        let max_key_len = keys.iter().map(|k| k.len()).max().unwrap();

        for (chunk, key) in chunks.iter().zip(keys.iter()) {
            writeln!(output, "{}", i)?;
            let mut hd = hex::Dumper::new(
                Vec::new(), self.indentation_for_hexdump(i, max_key_len));
            hd.write(*chunk, *key)?;
            output.write_all(&hd.into_inner())?;
        }

        Ok(())
    }

    /// Returns indentation for hex dumps.
    ///
    /// Returns a prefix of `i` so that a hexdump with labels no
    /// longer than `max_label_len` will fit into the target width.
    fn indentation_for_hexdump(&self, i: &str, max_label_len: usize) -> String {
        let amount = ::std::cmp::max(
            0,
            ::std::cmp::min(
                self.width as isize
                    - 63 // Length of address, hex digits, and whitespace.
                    - max_label_len as isize,
                i.len() as isize),
        ) as usize;

        format!("{}  ", &i.chars().take(amount).collect::<String>())
    }


}
