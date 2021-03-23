//! Re-combines encryption and signing into one operation.
//!
//! TB is broken.  It is using a [construct], which is [known to not work]
//! for 20 years.  We can fix this.  When we encrypt a message, we can
//! detect whether we just generated the signed part.  If so, we
//! transparently fix it.
//!
//!   [construct]: https://bugzilla.mozilla.org/show_bug.cgi?id=1688863
//!   [known to not work]: https://theworld.com/~dtd/sign_encrypt/sign_encrypt7.html
//!
//! Interestingly, [Section 6.2 of RFC3156] explicitly allows agents
//! decrypting a combined message to rewrite it as a multipart/signed
//! message on the fly.  We're doing the converse.
//!
//!   [Section 6.2 of RFC3156]: https://tools.ietf.org/html/rfc3156#section-6.2

use std::{
    io::{
        BufRead,
        BufReader,
    },
};

use sequoia_openpgp as openpgp;
use openpgp::{
    KeyHandle,
    Packet,
    packet::{
        Signature,
    },
    parse::{
        Parse,
        PacketParserResult,
        PacketParser,
    },
};

use crate::{
    RnpInput,
};

#[derive(Default)]
pub struct PlaintextCache {
    cache: Option<(RnpInput, Vec<Signature>)>,
}

impl PlaintextCache {
    /// Stashes the (plaintext, signatures) pair.
    ///
    /// This is a best effort mechanism.  If anything goes wrong, we
    /// don't cache.
    pub fn stash(&mut self, input: &RnpInput, signatures: &[u8])
    {
        fn doit(input: &RnpInput, signatures: &[u8])
                -> openpgp::Result<(RnpInput, Vec<Signature>)>
        {
            let mut sigs = Vec::new();

            let mut ppr = PacketParser::from_bytes(signatures)?;
            while let PacketParserResult::Some(pp) = ppr {
                let (packet, next_ppr) = pp.recurse()?;
                ppr = next_ppr;

                if let Packet::Signature(s) = packet {
                    sigs.push(s);
                } else {
                    return Err(anyhow::anyhow!("expected signature"));
                }
            }
            Ok((input.try_clone()?.to_owned(), sigs))
        }

        self.cache = doit(input, signatures).ok();
    }

    /// Gets the plaintext back given a MIME document containing a
    /// multipart/signed message.
    ///
    /// Extracts the signatures from the multipart/signed message,
    /// compares it to the cached signatures, and if they match,
    /// returns the original plaintext and a list of signing keys as
    /// identified by issuer.
    pub fn get(&mut self, signed: &RnpInput)
               -> openpgp::Result<Option<(RnpInput, Vec<KeyHandle>)>>
    {
        // Take the cache, if any.
        let cache = if let Some(c) = self.cache.take() {
            c
        } else {
            // Shortcut.
            return Ok(None);
        };

        // First, try to clone the input.  We cannot modify the input
        // in case the caller needs it to encrypt the message.
        let signed = signed.try_clone()?;

        // Now, extract the last signature.  We do this without proper
        // MIME parsing to avoid depending on a MIME parsing library.
        //
        // (As the time of this writing, none of the available options
        // are particularly stable, and none supports incremental
        // parsing, i.e. only parsing the top level without descending
        // into the tree.)
        let mut in_sig = false;
        let mut acc = Vec::new();
        for line in BufReader::new(signed).lines() {
            if let Ok(line) = line {
                if line == "-----BEGIN PGP SIGNATURE-----" {
                    acc.clear();
                    acc.push(line);
                    in_sig = true;
                } else if line == "-----END PGP SIGNATURE-----" {
                    acc.push(line);
                    in_sig = false;
                } else if in_sig {
                    acc.push(line);
                }
            }
        }

        // Parse the accumulator into signatures.
        let signature = acc.join("\n");
        let mut sigs = Vec::new();
        let mut issuers = Vec::new();
        let mut ppr = PacketParser::from_bytes(&signature)?;
        while let PacketParserResult::Some(pp) = ppr {
            let (packet, next_ppr) = pp.recurse()?;
            ppr = next_ppr;

            if let Packet::Signature(s) = packet {
                if let Some(issuer) = s.get_issuers().drain(..).nth(0) {
                    issuers.push(issuer);
                }

                sigs.push(s);
            } else {
                return Err(anyhow::anyhow!("expected signature"));
            }
        }

        if sigs == cache.1 {
            // Hit.
            Ok(Some((cache.0, issuers)))
        } else {
            // Miss.
            Ok(None)
        }
    }
}
