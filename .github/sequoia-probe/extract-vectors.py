#!/usr/bin/env python3
"""Extract the Appendix A test vectors from the text of RFC 9980.

Usage: extract-vectors.py <rfc9980.txt> <output-directory>

Writes one file per ASCII-armored block, named after its section
(A.1.1.asc, A.1.2.asc, ...), and manifest.tsv with one line per block:

    section <TAB> kind <TAB> file <TAB> title <TAB> primary-fpr <TAB> subkey-fpr

kind is the armor label (PRIVATE KEY BLOCK, PUBLIC KEY BLOCK, MESSAGE,
SIGNATURE). The fingerprint columns are the hexadecimal strings that follow
"The primary key has the fingerprint" and "The subkey has the fingerprint"
in that section, or "-" if the section has none. The script only copies text; it does not interpret the OpenPGP data.
"""
import os
import re
import sys

src, out = sys.argv[1], sys.argv[2]
os.makedirs(out, exist_ok=True)
lines = open(src, encoding="utf-8").read().split("\n")

start = next(i for i, l in enumerate(lines) if l.startswith("Appendix A.  Test Vectors"))
section, title, block, kind, fpr, sfpr = None, None, None, None, "-", "-"
manifest = []
i = start
while i < len(lines):
    l = lines[i]
    m = re.match(r"^(A\.\d+\.\d+)\.  (.*)$", l)
    if m:
        section, title, fpr, sfpr = m.group(1), m.group(2), "-", "-"
    elif re.match(r"^(Acknowledgments|Authors' Addresses|Appendix [B-Z])", l):
        break
    elif section and "has the fingerprint" in l:
        # The value is on the following line(s), up to the final period.
        j, text = i + 1, ""
        while j < len(lines) and lines[j].strip():
            text += lines[j].strip()
            j += 1
        m2 = re.match(r"^([0-9a-f]+)\.?$", text)
        if m2 and "primary key has the fingerprint" in l:
            fpr = m2.group(1)
        elif m2 and "subkey has the fingerprint" in l:
            sfpr = m2.group(1)
    elif section and l.startswith("   -----BEGIN PGP "):
        kind = l.strip()[len("-----BEGIN PGP "):-5]
        block = [l[3:]]
    elif block is not None:
        block.append(l[3:] if l.startswith("   ") else l)
        if l.startswith("   -----END PGP "):
            name = section + ".asc"
            if any(e[2] == name for e in manifest):
                raise SystemExit("more than one armored block in " + section)
            with open(os.path.join(out, name), "w", encoding="ascii") as f:
                f.write("\n".join(block) + "\n")
            manifest.append((section, kind, name, title, fpr, sfpr))
            block = None
    i += 1

with open(os.path.join(out, "manifest.tsv"), "w", encoding="utf-8") as f:
    for e in manifest:
        f.write("\t".join(e) + "\n")
print("%d blocks written to %s" % (len(manifest), out))
