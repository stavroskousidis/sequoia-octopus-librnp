# Reviewer instructions

This repository is a mirror of `sequoia-octopus-librnp`, the reimplementation of RNP's C interface on top of Sequoia that Thunderbird can load instead of `librnp`. The branch `pqc` adds support for RFC 9980 (Post-Quantum Cryptography in OpenPGP). The work is done by a scheduled agent; every change comes as a pull request into `pqc`, and the agent merges only when CI is green and your latest review of the latest commit has no open P0 or P1 findings. The result is meant to go upstream, so review like a careful maintainer of a security-critical library, not like a style editor.

## Review guidelines

Scope of the work: the seven RFC 9980 algorithms (IDs 30 to 36) in v6 keys, plus ML-KEM-768+X25519 as a v4 encryption subkey. Out of scope: draft-ietf-openpgp-nist-bp-comp (IDs 37 to 44), any GnuPG or gpg-agent path for post-quantum keys, unrelated refactoring.

Also in scope, by the owner's decision of 2026-11-27: fixes that make Thunderbird's OpenPGP tests pass with this library, that is compatibility with RNP where Thunderbird depends on it and defects that Thunderbird's tests expose, even where they are not post-quantum work. Each such fix is a pull request of its own, declares and justifies any change of behaviour for existing keys, and goes upstream as a topic separate from the post-quantum series. Do not report it as outside the scope.

Treat as **P0**:
- A verification, decryption or key-validity result reported through the FFI that is better than what `sequoia-openpgp` established (a bad or unverifiable signature reported as good, an unknown algorithm treated as valid, a policy check bypassed or weakened).
- Acceptance or generation of a construction that RFC 9980 or RFC 9580 forbids, or an algorithm ID, parameter set, size or encoding that disagrees with the RFC. Name the section.
- Memory-safety or ownership errors at the FFI boundary: null or dangling pointers, wrong buffer lengths, double free, memory handed to the caller that is freed with the wrong function, a panic that can cross into C.
- Secret key material or plaintext written to logs, traces, temporary files or error messages.
- Cryptographic primitives or encodings implemented in this crate instead of using `sequoia-openpgp`.
- A change in behaviour for existing v4 keys and classic algorithms that the PR does not declare and justify.
- A test that does not test what it claims, a test, lint or check that was disabled, skipped or weakened to get a green run, or a test result claimed in the PR description that the CI run does not show.
- Real key material, or anything that is not clearly synthetic test data.

Treat as **P1**:
- FFI behaviour that differs from RNP's (function names, algorithm and curve names, return codes, output formats, JSON fields) where Thunderbird depends on it, without a recorded reason.
- Missing tests for new behaviour, in particular missing negative tests, or post-quantum tests that silently pass on a backend that does not support the algorithms.
- A certificate or message with an unknown algorithm that breaks import, listing, or the handling of the parts that are known.
- Violations of the upstream gates: new compiler warnings (`RUSTFLAGS="-D warnings"`), `Cargo.lock` not matching `Cargo.toml`, new needlessly exported symbols, codespell findings.
- New dependencies or feature flags without justification; version requirements that exclude the releases Fedora 45 ships.
- Fork-only files (`AGENTS.md`, `.github/`) mixed into a code commit; they belong in commits whose message starts with `fork:`. A pull request may carry such a commit next to code commits when the table of recorded Thunderbird results (`.github/thunderbird/expected-results.tsv`) must change with the code; it is then merged without squashing, so judge the commits of the branch, not the combined diff.
- Material outside the scope above.

Do not report formatting or naming unless it departs from the surrounding upstream code. Do not recommend generality beyond what RFC 9980 needs.

For each finding, quote the exact line, say what is wrong, and say what would fix it. If the PR has no P0 or P1 findings, say so explicitly in one sentence ("No P0/P1 findings."), so the agent can merge.
