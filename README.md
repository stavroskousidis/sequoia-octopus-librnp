# A Sequoia-based OpenPGP backend for Thunderbird

This is a drop-in replacement for the [RNP] library supported and
shipped by Thunderbird.

[RNP]: https://github.com/rnpgp/rnp

# WARNING WARNING WARNING

This is a young project.  Use it with caution with your production
Thunderbird profile and production keys, and make sure you have a
backup (of at least `pubring.gpg` and `secring.gpg`) and know how to
recover.

## Known limitations

- `rnp_import_signatures` is not implemented, therefore it is not
  possible to import revocation certifications.
- There may be dragons.

## Building & installing

First of all, you will need to [install Sequoia's build dependencies].
Then, building the Octopus is only a matter of invoking `cargo`,
optionally with the `--release` flag to build an optimized build
suitable for end users.  Non-release builds print debugging and
tracing information to stderr.  You may optionally select one of
Sequoia's cryptographic backends, for example to use [Windows CNG].

The result is a shared library (i.e. a `*.so` on Linux and *BSD, a
`*.dll` on Windows, etc.).  To use it, make your Thunderbird pick it
up instead of the `librnp.so`, e.g. by replacing it.  The details are
dependent on your deployment, and this is something distributors need
to figure out.  This document will demonstrate how to replace RNP in a
local build of Thunderbird.

[install Sequoia's build dependencies]: https://gitlab.com/sequoia-pgp/sequoia#requirements
[Windows CNG]: https://docs.microsoft.com/en-us/windows/win32/seccng/cng-portal

### Debug build with the default cryptographic backend

```sh
cargo build
cp target/debug/libsequoia_octopus_librnp.so path/to/thunderbird/obj-x86_64-pc-linux-gnu/dist/bin/librnp.so
```

### Release build with the default cryptographic backend

```sh
cargo build --release
cp target/release/libsequoia_octopus_librnp.so path/to/thunderbird/obj-x86_64-pc-linux-gnu/dist/bin/librnp.so
```

### Debug build with the Windows CNG cryptographic backend

```sh
cargo build --no-default-features --features crypto-cng
cp target/debug/sequoia_octopus_librnp.dll path/to/thunderbird/.../dist/bin/rnp.dll # XXX: I'm guessing here
```
