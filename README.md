# A Sequoia-based OpenPGP Backend for Thunderbird

This is a drop-in replacement for the [RNP] library supported and
shipped by Thunderbird.

[RNP]: https://github.com/rnpgp/rnp

This project is called the Octopus, because octopuses can fit
themselves in [unusual places], and in this project we reimplement the
RNP API as used by Thunderbird using Sequoia.

> [Octopuses'] soft bodies mean octopuses can fit into impossibly
> small nooks and crannies, as long as the holes are not smaller than
> the only hard parts of their bodies: their beaks. If all else fails,
> octopuses can lose an arm to an attacker and regrow one later.

  [unusual places]: https://www.nationalgeographic.com/animals/invertebrates/facts/octopus-facts

# A note of caution

The Thunderbird developers do not support replacing [RNP], and have
made it difficult to integrate our solution.  We [regularly run]
Thunderbird's tests using the Octopus, using the ESR91 and
beta versions of Thunderbird.  We are quite confident that the Octopus
is safe to use, and offers at least the degree of security that you
get with [RNP].

  [regularly run]: https://gitlab.com/sequoia-pgp/sequoia-octopus-librnp/-/pipelines

Nevertheless, it is a good idea to make regular backups of your
Thunderbird profile and production keys (at least `pubring.gpg`,
`secring.gpg`, and `openpgp.sqlite`) and know how to recover.

## Known limitations

- There may be dragons.

- When Thunderbird auto-updates, it overwrites the Octopus' version of
  `librnp.so` with its own version.  This issue has been [reported to
  Thunderbird].

- Thunderbird reads and caches the available certificates on startup.
  Thus if you add a new certificate to gpg, even though the Octopus
  will load it, Thunderbird [will not notice it] until either you
  manually reimport the keys using Thunderbird's `OpenPGP Keyring
  Manager`, `File`, `Reload Key Cache`, or you restart Thunderbird.

  Note: Thunderbird only caches the list of keys and some meta-data,
  so it will normally take advantage of any updates inserted into the
  gpg keystore or fetched via Parcimonie.

  [reported to Thunderbird]: https://bugzilla.mozilla.org/show_bug.cgi?id=1698540
  [will not notice it]: https://bugzilla.mozilla.org/show_bug.cgi?id=1703373

# Support

The Octopus is actively maintained by the [Sequoia PGP] team.  We will respond
to issues and support requests, but we are not actively developing new features
(however, the Octopus should have feature parity with Thunderbird's default
backend).  We are primarily financed by the [pep foundation].  Our mandate is
specifically to improve the OpenPGP ecosystem, and more generally to improve
internet freedom tools.

  [Sequoia PGP]: https://sequoia-pgp.org/
  [pep foundation]: https://pep.foundation/

Currently, the Octopus is developed outside of Thunderbird.  The
main reasons for this is that the Thunderbird developers do not
want to invest resources in supporting a new OpenPGP backend after
having recently invested in RNP.

In terms of testing, the Octopus includes a number of unit tests.  Our
CI runs these checks against all commits on Debian and Windows.  It
also runs the OpenPGP relevant [unit tests from Thunderbird] on
Debian.

  [unit tests from Thunderbird]: https://gitlab.com/sequoia-pgp/sequoia-octopus-librnp/-/merge_requests/18

## Building & Installing

### Using official Linux distribution packages

The Octopus is available from the standard **Fedora** repositories since
Fedora 34. The official Thunderbird package has also been adapted to allow
users to choose which of the available PGP backends is used.

If the `thunderbird` package is already installed (and at least at version
91), then swapping the RNP backend with the Octopus can be done by
running the following command:

```sh
sudo dnf swap thunderbird-librnp-rnp sequoia-octopus-librnp
```

Switching back to the default backend works the same way, only with reversed
arguments for the `dnf swap` command:

```sh
sudo dnf swap sequoia-octopus-librnp thunderbird-librnp-rnp
```

If Thunderbird is not yet installed, then the preferred OpenPGP backend can be
specified at install time, as well:

```sh
sudo dnf install thunderbird sequoia-octopus-librnp
```

### Building manually

First of all, you will need to [install Sequoia's build dependencies].
Then, building the Octopus is only a matter of invoking `cargo build`,
optionally with the `--release` flag to build an optimized build
suitable for end users.  Non-release builds print debugging and
tracing information to stderr.  You may optionally select one of
Sequoia's cryptographic backends, for example, on Windows you'll
probably want to use the [Windows CNG] backend instead of the [Nettle]
backend.

The result of the build is a shared library (i.e. a `*.so` on Linux
and *BSD, a `*.dll` on Windows, etc.).  To use it, make your
Thunderbird pick it up instead of the `librnp.so` that it ships,
e.g. by replacing it.  The details are dependent on your deployment,
and this is something distributors need to figure out.  This document
will demonstrate how to replace RNP in a local build of Thunderbird.

[install Sequoia's build dependencies]: https://gitlab.com/sequoia-pgp/sequoia#requirements
[Windows CNG]: https://docs.microsoft.com/en-us/windows/win32/seccng/cng-portal
[Nettle]: http://www.lysator.liu.se/~nisse/nettle/

Note: the Octopus is fully backwards compatible with RNP.  In
particular, it uses the same format for storing keys and stores them
in the same way.  Thus, if you decide you don't like the Octopus, you
can simply restore the original `librnp`, restart Thunderbird, and
Thunderbird will work as before with all of your data.  Of course, you
should still make a backup (of at least `pubring.gpg`, `secring.gpg`,
and `openpgp.sqlite`).

#### Building on Linux

To use a debug build, do the following:

```sh
cargo build
cp target/debug/libsequoia_octopus_librnp.so path/to/thunderbird/obj-x86_64-pc-linux-gnu/dist/bin/librnp.so
```

To use a release build, do the following:

```sh
cargo build --release
cp target/release/libsequoia_octopus_librnp.so path/to/thunderbird/obj-x86_64-pc-linux-gnu/dist/bin/librnp.so
```

On debian bullseye it is not possible to build versions >= v1.2.1. You can follow these instructions: [Debian Bullseye](README-Debian.md)

#### Selecting a different cryptographic backend

To select a different cryptographic backend, OpenSSL in this example,
and create a debug build, do the following:

```sh
cargo build --no-default-features --features crypto-openssl,net
cp target/debug/libsequoia_octopus_librnp.so path/to/thunderbird/obj-x86_64-pc-linux-gnu/dist/bin/librnp.so
```

To use a release build, do the following:

```sh
cargo build --no-default-features --features crypto-openssl,net --release
cp target/release/libsequoia_octopus_librnp.so path/to/thunderbird/obj-x86_64-pc-linux-gnu/dist/bin/librnp.so
```

Please see
https://gitlab.com/sequoia-pgp/sequoia/-/tree/main/openpgp#crypto-backends
for a description of the available backends.

#### Building on Windows (MSVC)

There still exist some 32-bit installations of Thunderbird, even on 64-bit Windows.
The bitness of Thunderbird and the Octopus *must* match, so please check with "About Thunderbird".

The MSVC toolchain only supports the Windows CNG cryptographic backend.

The following recipes create debug builds.  To create a release build,
add `--release` after `cargo build` (`cargo build --release ...`).

For a 64-bit build, run:

```sh
rustup target add x86_64-pc-windows-msvc
cargo build --no-default-features --features crypto-cng,net --target x86_64-pc-windows-msvc
cp target/x86_64-pc-windows-msvc/debug/sequoia_octopus_librnp.dll "C:\Program Files\Mozilla Thunderbird\rnp.dll"

```

For a 32-bit build, run:

```sh
rustup target add i686-pc-windows-msvc
cargo build --no-default-features --features crypto-cng --target i686-pc-windows-msvc
cp target/i686-pc-windows-msvc/debug/sequoia_octopus_librnp.dll "C:\Program Files (x86)\Mozilla Thunderbird\rnp.dll"
```

#### Building on Windows (MSYS2)

There still exist some 32-bit installations of Thunderbird, even on 64-bit Windows.
The bitness of Thunderbird and the Octopus *must* match, so please check with "About Thunderbird".

The MSYS2 toolchain supports both the Nettle and the Windows CNG cryptographic backend.

The following recipes create debug builds.  To create a release build,
add `--release` after `cargo build` (`cargo build --release ...`).

For a 64-bit build with CNG, run:

```sh
rustup target add x86_64-pc-windows-gnu
cargo build --no-default-features --features crypto-cng,net --target x86_64-pc-windows-gnu
cp target/x86_64-pc-windows-gnu/debug/sequoia_octopus_librnp.dll "C:\Program Files\Mozilla Thunderbird\rnp.dll"

```

For a 32-bit build with CNG, run:

```sh
rustup target add i686-pc-windows-gnu
cargo build --no-default-features --features crypto-cng --target i686-pc-windows-gnu
cp target/i686-pc-windows-gnu/debug/sequoia_octopus_librnp.dll "C:\Program Files (x86)\Mozilla Thunderbird\rnp.dll"
```

For a 64-bit build with Nettle, run:

```sh
rustup target add x86_64-pc-windows-gnu
cargo build --target x86_64-pc-windows-gnu
cp target/x86_64-pc-windows-gnu/debug/sequoia_octopus_librnp.dll "C:\Program Files\Mozilla Thunderbird\rnp.dll"

```

For a 32-bit build with Nettle, run:

```sh
rustup target add i686-pc-windows-gnu
cargo build --target i686-pc-windows-gnu
cp target/i686-pc-windows-gnu/debug/sequoia_octopus_librnp.dll "C:\Program Files (x86)\Mozilla Thunderbird\rnp.dll"
```

### Using Debian's Thunderbird

The following recipe was tested with version `1:78.9.0-1~deb10u1` of
Thunderbird (from Debian Bullseye).  This uses `dpkg`'s diversion
mechanism to move `librnp.so` out of the way.

```sh
$ sudo apt install thunderbird
...
thunderbird is already the newest version (1:78.9.0-1~deb10u1).
...
$ ls -l /usr/lib/thunderbird/librnp.so
-rw-r--r-- 1 root root 723248 Mar 24 19:57 /usr/lib/thunderbird/librnp.so
$ sudo dpkg-divert --divert /usr/lib/thunderbird/librnp-orig.so --rename /usr/lib/thunderbird/librnp.so
Adding 'local diversion of /usr/lib/thunderbird/librnp.so to /usr/lib/thunderbird/librnp-orig.so'
$ sudo cp .../target/release/libsequoia_octopus_librnp.so /usr/lib/thunderbird/
$ sudo ln -sf libsequoia_octopus_librnp.so /usr/lib/thunderbird/librnp.so
$ ls -l /usr/lib/thunderbird/*rnp*
-rw-r--r-- 1 root root    723248 Mar 24 19:57 /usr/lib/thunderbird/librnp-orig.so
lrwxrwxrwx 1 root root        28 Apr  7 13:59 /usr/lib/thunderbird/librnp.so -> libsequoia_octopus_librnp.so
-rwxr-xr-x 1 root root 129988280 Apr  7 14:01 /usr/lib/thunderbird/libsequoia_octopus_librnp.so
```

If you are using the debug version, then change 'release' to 'debug'.

To uninstall the Octopus, you just need to remove the symlink and the
diversion.

```sh
$ sudo rm /usr/lib/thunderbird/librnp.so
$ sudo dpkg-divert --rename --remove /usr/lib/thunderbird/librnp.so
Removing 'local diversion of /usr/lib/thunderbird/librnp.so to /usr/lib/thunderbird/librnp-orig.so'
$ ls -l /usr/lib/thunderbird/*rnp*
-rw-r--r-- 1 root root    723248 Mar 24 19:57 /usr/lib/thunderbird/librnp.so
-rwxr-xr-x 1 root root 129988280 Apr  7 14:01 /usr/lib/thunderbird/libsequoia_octopus_librnp.so
```

### Precompiled Binaries for 64-bit Windows

If you are feeling particularly daring, you can download a precompiled
[`rnp.dll`] for Windows.  This binary is created by our CI.  It
corresponds to the current version of the `main` branch.  Before code
is checked into the `main` branch, it must first pass our unit tests
on both Debian and Windows, and it must past the Thunderbird unit
tests on Debian.

  [`rnp.dll`]: https://gitlab.com/sequoia-pgp/sequoia-octopus-librnp/-/jobs/artifacts/main/download?job=windows-msvc-release

To use the Octopus, replace the `rnp.dll` binary in your Thunderbird
installation.  Thunderbird is usually installed to `C:\Program
Files\Mozilla Thunderbird`.

Note: this will only work with a 64-bit build of Thunderbird.  If you
are using a 32-bit build (you can tell as your Thunderbird would be
installed in `C:\Program Files (x86)`), then you need to either switch
to a 64-bit version of Thunderbird or compile a 32-bit version of the
Octopus yourself.

If you encounter any errors and wish to investigate, there is also a [debug
build] available.

  [debug build]: https://gitlab.com/sequoia-pgp/sequoia-octopus-librnp/-/jobs/artifacts/main/download?job=debug-windows-msvc-release

Before starting Thunderbird with the Octopus, be sure to backup the
files `pubring.gpg`, `secring.gpg`, and `openpgp.sqlite` in your
Thunderbird profile.  Your Thunderbird profile is usually located in
`C:\Users\USERNAME\AppData\Roaming\Thunderbird\Profiles\PROFILEXXX.default`.

# Additional Features

This library includes a number of additional features that enhance
Thunderbird.

## GnuPG Keyring Integration

When Thunderbird starts, it asks RNP to parse its keyring.  At this
point, the Octopus also runs `gpg --export` and includes that in the
results.  This makes the user's GnuPG keyring available to
Thunderbird.  (From that point on the Octopus also monitors GnuPG's
keystore for updates.)  This can be disabled by setting the
`GNUPGHOME` environment variable to `/dev/null` as follows:

```sh
GNUPGHOME=/dev/null thunderbird
```

The certificates imported from GnuPG can be used as normal.  It is
possible to examine them in Thunderbird's OpenPGP Key Manager, set
their "acceptance", etc.

There are two known limitations.  First, the first time an OpenPGP
operation is performed, Thunderbird scans the keystore and creates an
index of the available keys.  Thunderbird [does not currently update
this index] on its own.  Thus, keys that are added to gpg's keystore
will not be visible to Thunderbird until either the cache is manually
flushed (`OpenPGP Keyring Manager`, `File`, `Reload Key Cache`), or
you restart Thunderbird.  Second, if you remove a certificate managed
by GnuPG using the Thunderbird certificate manager, it will be removed
from the in-memory keystore, but it is currently not actually removed
from your gpg keystore.  As such, it will reappear the next time
Thunderbird loads the keyring.

  [does not currently update this index]: https://bugzilla.mozilla.org/show_bug.cgi?id=1703373

The Octopus carefully keeps track of what certificates were loaded
from GnuPG and only writes them out to Thunderbird's keyring if they
have been modified; modified certificates are not currently written
back to GnuPG.  But, [closer integration with GnuPG's keyring] is
planned.

  [closer integration with GnuPG's keyring]: https://gitlab.com/sequoia-pgp/sequoia-octopus-librnp/-/issues/15

## gpg agent Integration

The Octopus automatically monitors what keys are loaded into gpg's
agent, and reports to Thunderbird that secret key material is
available for them.  This means that it is trivial to mark a key
managed by the agent as a personal key in Thunderbird [without
modifying Thunderbird's configuration files].  Also, attempts to decrypt
messages encrypted to a key managed by the agent are automatically
forwarded to the agent for decryption.

  [without modifying Thunderbird's configuration files]: https://wiki.mozilla.org/Thunderbird:OpenPGP:Smartcards#Allow_the_use_of_external_GnuPG

[Unlike Thunderbird] the Octopus talks directly to the agent.  Thus,
it is not necessary to install GPGME; you only need to have `gpg` in
your `PATH`.

  [Unlike Thunderbird]: https://wiki.mozilla.org/Thunderbird:OpenPGP:Smartcards

## GnuPG's Web of Trust Data

Thunderbird only supports a custom "acceptance" mechanism for
authenticating OpenPGP certificate.  Thunderbird ignores key
signatures, and it is not possible to add [certification authorities].

  [certification authorities]: https://openpgp-ca.org

When Thunderbird starts up, the Octopus reads gpg's trust database,
and merges it into Thunderbird's acceptance database.  This means
certificates that are considered authenticated by GnuPG are also
considered authenticated by Thunderbird.

This integration is done carefully.  If a user has manually accepted a
certificate in Thunderbird, that setting is not overridden.  This
happens not only during the initial import, but also later: when the
user accepts a certificate in Thunderbird, the Octopus detects this
and will no longer update that certificate's acceptance based on
GnuPG's trust database.

The Octopus monitors GnuPG for changes to its trust database.  So,
unlike when a new certificate is added to GnuPG's keystore, it is not
necessary to restart Thunderbird to notice changes to the trust
database.

## Parcimonie

[Parcimonie] is a feature that automatically refreshes the user's
OpenPGP certificates in the background using a number of privacy
preserving techniques.  In particular, updates are staggered, and the
time between updates is drawn from a [memoryless distribution] to
frustrate an attacker who wants to predict when a user will check for
an update.  Enigmail had its own version of this mechanism, but it was
removed when Enigmail was integrated into Thunderbird.

  [Parcimonie]: https://github.com/EtiennePerot/parcimonie.sh
  [memoryless distribution]: https://en.wikipedia.org/wiki/Memorylessness

The Parcimonie feature in the Octopus currently checks for updates on
[keys.openpgp.org] and in the appropriate Web Key Directories ([WKDs])
using the aforementioned privacy preserving mechanisms.  It checks for
updates for all non-revoked, valid certificates about once a week, on
average.  It also supports merging updates from [User ID-less
certificates].

  [keys.openpgp.org]: https://keys.openpgp.org
  [WKDs]: https://wiki.gnupg.org/WKD
  [User ID-less certificates]: https://bugzilla.mozilla.org/show_bug.cgi?id=1634524

Before importing a certificate, we first check if it appears to be
[flooded].  If so, we strip third-party certifications from keys that
we don't have a certificate for as those certifications are
effectively useless.

  [flooded]: https://dkg.fifthhorseman.net/blog/openpgp-certificate-flooding.html

## Weak Cryptography

The Octopus uses Sequoia, which [rejects cryptographic algorithms that
are known to be weak by default].  Unfortunately, [RNP still accepts
MD5], among other vulnerable algorithms, without warning.  Thunderbird
has patched MD5 out of the version of RNP that they distribute,
however, Thunderbird continues to support unlimited use of SHA-1,
which is known to be [vulnerable to collision attacks].  Sequoia, and
by extension, the Octopus, rejects certificates and messages that use
weak cryptographic primitives.  Because RNP does not have a mechanism
to indicate that a certificate or component should not be used, the
Octopus reports these keys as having expired one second after their
creation time.

  [rejects cryptographic algorithms that are known to be weak by default]: https://docs.sequoia-pgp.org/sequoia_openpgp/policy/struct.StandardPolicy.html
  [RNP still accepts MD5]: https://bugzilla.mozilla.org/show_bug.cgi?id=1641720
  [vulnerable to collision attacks]: https://sha-mbles.github.io/

## Protection from Surreptitious Forwarding

When Thunderbird creates an email it uses the RFC 1847 Encapsulation
method [construct], which has been [known to be broken] for over 20
years.  The issue is that if Alice signs a message and sends it to
Bob, Bob can use the signature in a different context.

This security issue can be fixed by using OpenPGP's intended recipient
feature.  Then, if Bob forwards the signed message (e.g., "I owe you
100 Euros") to Carol, Carol's MUA will mark the signature as invalid
as she is not the intended recipient of the message.

In the Octopus, we detect the use of the encapsulation method and
automatically and transparently replace it with the safer [combined
method] whenever possible.  Specifically, when we encrypt a message,
we check whether we just generated the signed part.  If so, we fix it.
Because this generates another signature, if you are using a key
managed by gpg's agent, you may be prompted to authorize a second
signature.

  [construct]: https://bugzilla.mozilla.org/show_bug.cgi?id=1688863
  [known to be broken]: https://theworld.com/~dtd/sign_encrypt/sign_encrypt7.html
  [combined method]: https://tools.ietf.org/html/rfc3156#section-4

# Non-Functional Advantages

Sequoia has a number of non-functional advantages relative to RNP.

## Keys Encrypted at Rest

Sequoia automatically [encrypts unencrypted secret key material in
memory] when it is not in use.  This makes secret key exfiltration ala
[Heartbleed] much harder, and protects against [Spectre], Rowhammer,
etc.-style attacks.  [OpenSSH] uses the same type of protection.

RNP has the concept of locking and unlocking keys, but this is
explicit, and Thunderbird does not always relock keys after use.

  [encrypts unencrypted secret key material in memory]: https://docs.sequoia-pgp.org/sequoia_openpgp/crypto/mem/struct.Encrypted.html
  [Heartbleed]: https://en.wikipedia.org/wiki/Heartbleed
  [Spectre]: https://en.wikipedia.org/wiki/Spectre_(security_vulnerability)
  [OpenSSH]: https://www.undeadly.org/cgi?action=article;sid=20190621081455

## SHA-1 Mitigations

[SHA-1 is broken].  Unfortunately, [SHA-1 is still widely used].  To
deal with this Sequoia implements a number of countermeasures:

  - Sequoia uses [SHA1-CD], a variant of SHA-1 that detects and
    mitigates collision attacks.  This protection is also used by
    [GitHub], among others.

  - Sequoia only accepts SHA-1 in [safer contexts].  For instance,
    SHA-1 over messages, and its use in third-party certifications are
    rejected by default.  But, SHA-1 self-signatures that are not
    suspicious are allowed.

  - Sequoia has announced a timeline to completely [deprecate the
    use of SHA-1]: in 2023 SHA-1 will no longer be accepted for
    digital signatures.

  [SHA-1 is broken]: https://sha-mbles.github.io/
  [SHA-1 is still widely used]: https://gitlab.com/sequoia-pgp/sequoia/-/issues/595
  [SHA1-CD]: https://github.com/cr-marcstevens/sha1collisiondetection
  [GitHub]: https://github.blog/2017-03-20-sha-1-collision-detection-on-github-com/
  [safer contexts]: https://docs.sequoia-pgp.org/sequoia_openpgp/policy/enum.HashAlgoSecurity.html
  [deprecate the use of SHA-1]: https://docs.sequoia-pgp.org/sequoia_openpgp/policy/struct.StandardPolicy.html#method.reject_hash_property_at

RNP accepts SHA-1 everywhere without any additional protections.  By
default, it even [accepts] [MD5].  Happily, Thunderbird carries a
patch to disable MD5 support.

  [accepts]: https://tests.sequoia-pgp.org/#Detached_Sign-Verify_roundtrip_with_key__Bob___MD5
  [MD5]: https://github.com/rnpgp/rnp/issues/1281

## Collision Protection

Sequoia includes a salt in signatures and self-signatures to defend
against collision attacks, among others.  [OpenSSH does the same
thing].  Should the collision resistance of another hash be broken,
this will frustrate attackers trying to perform a Shambles-style
attack.

  [OpenSSH does the same thing]: https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.certkeys#L151

## No Split Brain Problem

RNP maintains separate public and secret keyrings.  This can lead to a
so-called split-brain problem where a certificate is present in both
keyrings, and confusingly one version is returned sometimes and the
other version other times.  This is also the model that GnuPG 1.x
used, and is one of the reasons that GnuPG migrated to a single
OpenPGP keystore in GnuPG 2.0 with only the secret key material held
by the agent.

To avoid this problem, the Octopus merges the two databases.  To
remain backwards compatible with RNP, when the Octopus writes out the
certificates, certificates with secret key material are written to
`secring.gpg` and those without are written to `pubring.gpg`.

## Multi-threading

Thanks to Rust's [safer concurrency paradigms], it is less dangerous
and less complicated for the Octopus to use threads than libraries
written in other languages.  The Octopus uses this, for instance, to
[parse keyrings faster].  And to perform updates in the background.

  [safer concurrency paradigms]: https://doc.rust-lang.org/book/ch16-00-concurrency.html
  [parse keyrings faster]: https://gitlab.com/sequoia-pgp/sequoia-octopus-librnp/-/blob/595d1e20f71f3a62f8772ab457f11974bd9be2e9/src/keyring.rs#L173

## OpenPGP Conformance

Sequoia implements [nearly all] [of the OpenPGP RFC].  The missing
bits are either obsolete or insecure.

   [nearly all]: https://sequoia-pgp.org/status/
   [of the OpenPGP RFC]: https://tests.sequoia-pgp.org/

RNP doesn't implement a number of important parts.  For instance, it
does not reject [unknown critical subpackets] and notations.  This is
a security problem.  RNP doesn't handle [unknown packet versions].
This is a future compatibility problem.  RNP also doesn't handle
"esoteric" keys, like [shared keys] where only the encryption subkey's
secret key material is shared.  This is a compatibility problem.  More
examples can be found in the [OpenPGP interoperability test suite].

  [unknown packet versions]: https://github.com/rnpgp/rnp/issues/1257
  [unknown critical subpackets]: https://github.com/rnpgp/rnp/issues/1234
  [shared keys]: https://bugzilla.mozilla.org/show_bug.cgi?id=1703368
  [OpenPGP interoperability test suite]: https://tests.sequoia-pgp.org/
