# sequoia-probe

Capability probe of work packages A0 (part 3) and W1: what `sequoia-openpgp` does for the RFC 9980 algorithms on one crypto backend, and whether the generated certificates are usable under the system crypto policy as the Octopus reads it. It calls only the public API of `sequoia-openpgp` (and `Keygrip::of` from `sequoia-ipc`, and `sequoia-policy-config` for the policy), implements no cryptography, and uses only keys it generates itself and the test vectors of RFC 9980, Appendix A.

Versions: `sequoia-openpgp` 2.5.0 since W1 (2026-11-26); A0 ran it with 2.4.2. The A0 runs of 2026-11-24 are in `evidence/A0-sequoia-probe.txt` of `stavroskousidis/pqc-octopus`, and what they mean is in `analysis/A0-sequoia-capabilities.md` there; the W1 runs are in `evidence/W1-sequoia-probe.md`.

The master copy of this directory is `analysis/tools/sequoia-probe/` in `stavroskousidis/pqc-octopus`. `stavroskousidis/sequoia-octopus-librnp` carries a copy as the fork-only directory `.github/sequoia-probe/`, which the job `probe` of its CI builds with the `openssl` feature on Fedora 45.

## Run

Extract the Appendix A vectors from the RFC text, then build and run. The target directory stays outside the repository.

```
python3 extract-vectors.py ../../../sources/rfc9980.txt /home/claude/work/rfc9980-vectors
export CARGO_TARGET_DIR=/home/claude/work/probe-target
cargo build --release --locked
$CARGO_TARGET_DIR/release/sequoia-probe /home/claude/work/rfc9980-vectors
```

The default feature `rust` selects the RustCrypto backend (`crypto-rust`, `allow-experimental-crypto`, `allow-variable-time-crypto`). The other backends, each with its own target directory:

```
CARGO_TARGET_DIR=/home/claude/work/probe-target-nettle  cargo build --release --locked --no-default-features --features nettle
CARGO_TARGET_DIR=/home/claude/work/probe-target-openssl cargo build --release --locked --no-default-features --features openssl
```

The `openssl` feature needs `libclang` at build time (`openssl-sys` is built with its `bindgen` feature, which the `ossl` crate requires). Post-quantum algorithms need OpenSSL 3.5 or later there.

`Cargo.lock` is part of the probe: it records the versions of the RustCrypto crates the evidence was produced with.

## Output

One line per cell: `group | operation | status | detail`.

| Status | Meaning |
|---|---|
| `ok` | the operation worked |
| `FAIL` | the operation did not work; the error text follows |
| `rejected` | a construction that RFC 9980 forbids was refused |
| `ACCEPTED` | a construction that RFC 9980 forbids was not refused: a finding about the library, not an error of the probe |
| `info` | a value that is reported, not judged |

The exit status is 1 if any line is `FAIL`, otherwise 0. Without a vector directory the Appendix A part is skipped and a comment line says so.

## The system policy cells

The groups that start with `system policy` build the policy the way `rnp_ffi_create` of the Octopus does: `sequoia-policy-config` reads the file named in `SEQUOIA_CRYPTO_POLICY`, or `/etc/crypto-policies/back-ends/sequoia.config`, on top of `StandardPolicy`, and MD5 and SHA-1 are then rejected where Thunderbird expects it. The cells say whether that policy accepts each of the seven algorithms, and whether each generated certificate is valid, has a usable signing and encryption key, and signs, verifies, encrypts and decrypts under it. Without a policy file they repeat the `StandardPolicy` results.

## Expected cells

`expected-cells-rust.txt` and `expected-cells-openssl.txt` list `group | operation | status` for every cell of a run with the Appendix A vectors: the first recorded with the RustCrypto backend in the agent container (the reference, 255 cells), the second with the OpenSSL backend and OpenSSL 4.0.3 in the Fedora 45 container (254 cells). They differ in one place: the OpenSSL backend has no Twofish, so the two Twofish cells of the RFC 9980, section 4.3.1 case are one `info` cell there. `check-cells.py` compares a run with one of the files and ignores the detail column:

```
$CARGO_TARGET_DIR/release/sequoia-probe /home/claude/work/rfc9980-vectors > probe-output.txt
python3 check-cells.py expected-cells-rust.txt probe-output.txt
```

Its exit status is 0 only if the run has exactly the expected cells. That is the criterion of the CI job, with `expected-cells-openssl.txt`: the probe's own exit status is 1 as long as findings F21 and F23 hold, so it cannot be one. A backend that lacks the algorithms, a failing test vector, or a crypto policy that rejects one of the algorithms shows up as a difference. When a cell changes for a good reason (for example because Sequoia fixes F22), the expected files change in the same commit, with the reason.
