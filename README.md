# A Sequoia-based OpenPGP backend for Thunderbird

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

# WARNING WARNING WARNING

This is a young project.  Use it with caution with your production
Thunderbird profile and production keys, and make sure you have a
backup (of at least `pubring.gpg` and `secring.gpg`) and know how to
recover.

## Known limitations

- There may be dragons.
- When Thunderbird auto-updates, it overwrites the Octopus' version of
  `librnp.so` with its own version.  This issue has been [reported to
  Thunderbird].

  [reported to Thunderbird]: https://bugzilla.mozilla.org/show_bug.cgi?id=1698540

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

Note: the Octopus is fully backwards compatible with RNP.  In
particular, it uses the same format for storing keys and stores them
in the same way.  Thus, if you decide you don't like the Octopus, you
can simply restore the original `librnp`, restart Thunderbird, and
Thunderbird will work as before with all of your data.

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
# Support

The Octopus is actively developed by the [Sequoia PGP] team.  We are
primarily financed by the [pep foundation].  Our mandate is
specifically to improve the OpenPGP ecosystem, and more generally to
improve internet freedom tools.

  [Sequoia PGP]: https://sequoia-pgp.org/
  [pep foundation]: https://pep.foundation/

Currently, the Octopus is developed outside of Thunderbird.  There are
two main reasons for this.  First, the Thunderbird developers do not
want to invest resources in supporting a new OpenPGP backend after
having recently invested in RNP.  Second, Sequoia and the Octopus are
licensed under the GPLv2+.  Although the GPLv2+ is [compatible with
MPL 2.0], adding GPLv2+ code to Thunderbird is not currently aligned
with their licensing strategy.

  [compatible with MPL 2.0]: https://www.gnu.org/licenses/license-list.html#MPL-2.0

In terms of testing, the Octopus includes a number of unit tests.  Our
CI runs these checks against all commits.  It also runs the OpenPGP
relevant [unit tests from Thunderbird].

  [unit tests from Thunderbird]: https://gitlab.com/sequoia-pgp/sequoia-octopus-librnp/-/merge_requests/18

# Additional Features

This library includes a number of additional features that enhance
Thunderbird.

## GnuPG Keyring Integration

When Thunderbird starts it asks `librnp` to parse its keyring.  At
this point, the Octopus also runs `gpg --export` and includes that in
the results that it returns to Thunderbird.  This makes the user's
GnuPG keyring available to Thunderbird.  This can be disabled by
setting the `GNUPGHOME` environment variable to `/dev/null` as
follows:

```sh
GNUPGHOME=/dev/null thunderbird
```

The certificates imported from GnuPG can be used as normal.  It is
possible to examine them in Thunderbird's OpenPGP Key Manager, set
their "acceptance", etc.  The only known limitation is that if a
certificate managed by GnuPG is removed using the Thunderbird
certificate manager, it will reappear the next time Thunderbird loads
the keyring (this will typically only happen when the user restarts
Thunderbird) unless the certificate is also manually deleted from the
GnuPG keyring.

The Octopus carefully keeps track of what certificates were loaded
from GnuPG and only writes them out to Thunderbird's keyring if they
have been modified; modified certificates are not currently written
back to GnuPG.  But, [closer integration with GnuPG's keyring] is
planned.

  [closer integration with GnuPG's keyring]: https://gitlab.com/sequoia-pgp/sequoia-octopus-librnp/-/issues/15

## GnuPG Web of Trust

Currently, Thunderbird only supports a custom "acceptance" mechanism
for authenticating OpenPGP certificate.  There is currently no way to
make use of OpenPGP's standard authentication mechanisms; Thunderbird
ignores key signatures, and it is not possible to add [certificate
authorities].

  [certificate authorities]: https://openpgp-ca.org

When Thunderbird starts up, the Octopus loads the set of authenticated
certificates, and merges them into Thunderbird's key acceptance
database.  This means certificates that are considered authenticated
by GnuPG are also considered authenticated by Thunderbird.

The integration is done carefully.  If a user has manually accepted a
certificate in Thunderbird, that setting is not overridden.  This
happens not only during the initial import, but also later: when the
user accepts a certificate in Thunderbird, the Octopus detects this
and will no longer update that certificate's acceptance using GnuPG's
trust database.

To take advantage of this feature, you need to use `gpg`.  For
instance to add the FSFE's OpenPGP CA key, you could do:

```
$ gpg --auto-key-locate nodefault,clear,wkd --locate-keys openpgp-ca@fsfe.org
$ gpg --edit-key 'A30A C9F8 FA7A 883C 0060  3070 699D 9E7F 63B4 0E79'
...
gpg> tlsign

pub  rsa4096/0x699D9E7F63B40E79
     created: 2021-01-21  expires: never       usage: C
     trust: unknown       validity: unknown
 Primary key fingerprint: A30A C9F8 FA7A 883C 0060  3070 699D 9E7F 63B4 0E79

     FSFE OpenPGP CA <openpgp-ca@fsfe.org>

Please decide how far you trust this user to correctly verify other users' keys
(by looking at passports, checking fingerprints from different sources, etc.)

  1 = I trust marginally
  2 = I trust fully

Your selection? 1

Please enter the depth of this trust signature.
A depth greater than 1 allows the key you are signing to make
trust signatures on your behalf.

Your selection? 1

Please enter a domain to restrict this signature, or enter for none.

Your selection? fsfe.org

Are you sure that you want to sign this key with your
key "Neal H. Walfield (certification key)" (0xCDFDE3090F11A850)

The signature will be marked as non-exportable.

Really sign? (y/N) y

gpg> save
```

When you restart, many `@fsfe.org` certificates will now be considered
marginally trusted (i.e., partially authenticated).

The Octopus does [not yet monitor GnuPG] for changes to its trust
database.  So, it is necessary to restart Thunderbird to notice any
changes.

  [not yet monitor GnuPG]: https://gitlab.com/sequoia-pgp/sequoia-octopus-librnp/-/issues/11

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
updates for all non-revoked, valid certificates about once a week on
average.  It also supports merging updates from [User ID-less
certificates].

  [keys.openpgp.org]: https://keys.openpgp.org
  [WKDs]: https://wiki.gnupg.org/WKD
  [User ID-less certificates]: https://bugzilla.mozilla.org/show_bug.cgi?id=1634524

## Weak Cryptography

The Octopus uses Sequoia, which [rejects cryptographic algorithms that
are known to be weak by default].  Unfortunately, [RNP still accepts
MD5], among other vulnerable algorithms, without warning.  Thunderbird
has patched MD5 out of the version of RNP that they distribute,
however, Thunderbird continues to support unlimited use of SHA-1,
which is known to be [vulnerable to collision attacks].  Sequoia, and
by extension, the Octopus, rejects certificates and messages that use
vulnerable cryptographic primitives.

  [rejects cryptographic algorithms that are known to be weak by default]: https://docs.sequoia-pgp.org/sequoia_openpgp/policy/struct.StandardPolicy.html
  [RNP still accepts MD5]: https://bugzilla.mozilla.org/show_bug.cgi?id=1641720
  [vulnerable to collision attacks]: https://sha-mbles.github.io/

## Protection from Surreptitious Forwarding

When Thunderbird creates an email it uses the RFC 1847 Encapsulation
method [construct], which has been [known to not work] for over 20
years.  The issue is that if Alice signs a message and sends it to
Bob, Bob can use the signature in a different context.

This problem can be fixed by using OpenPGP's intended recipient
feature.  Then, if Bob forwards the signed message (e.g., "I owe you
100 Euros") to Carol, Carol's MUA will mark the signature as invalid
as she is not the intended recipient of the message.

In the Octopus, we detect the use of the encapsulation method and
automatically and transparently replace it with the safer [combined
method] whenever possible.  Specifically, when we encrypt a message,
we check whether we just generated the signed part.  If so, we fix it.

  [construct]: https://bugzilla.mozilla.org/show_bug.cgi?id=1688863
  [known to not work]: https://theworld.com/~dtd/sign_encrypt/sign_encrypt7.html
  [combined method]: https://tools.ietf.org/html/rfc3156#section-4

# Non-Functional Advantages

Sequoia has a number of non-functional advantages relative to RNP.
These include:

  - Sequoia automatically [encrypts unencrypted secret key material in
    memory] when it is not in use.  This makes secret key exfiltration
    ala [Heartbleed] much harder, and protects against [Sprectre],
    Rowhammer, etc.-style attacks.  [OpenSSH] uses the same type of
    protection.

    RNP has the concept of locking and unlocking keys, but this is
    explicit, and Thunderbird does not always relock keys after use.

      [encrypts unencrypted secret key material in memory]: https://docs.sequoia-pgp.org/sequoia_openpgp/crypto/mem/struct.Encrypted.html
      [Heartbleed]: https://en.wikipedia.org/wiki/Heartbleed
      [Sprectre]: https://en.wikipedia.org/wiki/Spectre_(security_vulnerability)
      [OpenSSH]: https://www.undeadly.org/cgi?action=article;sid=20190621081455

  - [SHA-1 is broken].  Unfortunately, [SHA-1 is still widely used].
    To deal with this Sequoia implements a number of countermeasures:

      - Sequoia uses [SHA1-CD], a variant of SHA-1 that detects and
        mitigates collision attacks.  This protection is also used
        by, for instance, [GitHub].

      - Sequoia only accepts SHA-1 in [safer contexts].  For instance,
        SHA-1 over data is rejected by default.  But, SHA-1
        self-signatures that are not suspicious are allowed.

      - Sequoia has announced a timeline to completely [deprecate the
        use of SHA-1]: in 2023 SHA-1 will no longer be accepted for
        digital signatures.

      [SHA-1 is broken]: https://sha-mbles.github.io/
      [SHA-1 is still widely used]: https://gitlab.com/sequoia-pgp/sequoia/-/issues/595
      [SHA1-CD]: https://github.com/cr-marcstevens/sha1collisiondetection
      [GitHub]: https://github.blog/2017-03-20-sha-1-collision-detection-on-github-com/
      [safer contexts]: https://docs.sequoia-pgp.org/sequoia_openpgp/policy/enum.HashAlgoSecurity.html
      [deprecate the use of SHA-1]: https://docs.sequoia-pgp.org/sequoia_openpgp/policy/struct.StandardPolicy.html#method.reject_hash_property_at

    RNP accepts SHA-1 everywhere without any additional protections.
    It even [accepts] [MD5].  (Thunderbird carries a patch to disable
    MD5 support.)

      [accepts]: https://tests.sequoia-pgp.org/#Detached_Sign-Verify_roundtrip_with_key__Bob___MD5
      [MD5]: https://github.com/rnpgp/rnp/issues/1281

  - Sequoia includes a salt in signatures and self-signatures to
    defend against collision attacks (among others).  [OpenSSH], for
    instance, does the same thing.  Should the collision resistance of
    another hash be broken, this will frustrate attackers trying to
    perform a SHA-1 is a Shambles-style attack.

      [OpenSSH]: https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.certkeys#L151

  - RNP maintains separate public and secret keyrings.  This can lead
    to a so-called split-brain problem where a certificate is present
    in both keyrings, and confusingly one version is returned
    sometimes and the other version other times.  This is also the
    model that GnuPG 1.x used, and is one of the reasons that GnuPG
    migrated to a single OpenPGP keystore in GnuPG 2.0 with only the
    secret key material held by the agent.

    To avoid this problem, the Octopus merges the two databases.  To
    remain backwards compatible with RNP, when the Octopus writes out
    the certificates, certificates with secret key material are
    written to `secring.gpg` and those without are written to
    `pubring.gpg`.

  - Thanks to Rust's [safer concurrency paradigms], it is less
    dangerous and less complicated for the Octopus to use threads than
    libraries written in other languages.  The Octopus uses this, for
    instance, to [parse keyrings faster].

      [safer concurrency paradigms]: https://doc.rust-lang.org/book/ch16-00-concurrency.html
      [parse keyrings faster]: https://gitlab.com/sequoia-pgp/sequoia-octopus-librnp/-/blob/595d1e20f71f3a62f8772ab457f11974bd9be2e9/src/keyring.rs#L173

  - Sequoia implements [nearly all] [of the OpenPGP RFC].  The missing
    bits are either obsolete or insecure.

      [nearly all]: https://sequoia-pgp.org/status/
      [of the OpenPGP RFC]: https://tests.sequoia-pgp.org/

    RNP doesn't implement a number of important parts.  For instance,
    it does not reject [unknown critical subpackets] and notations.
    This is a security problem.  RNP doesn't handle [unknown packet
    versions].  This is a future compatibility problem.  More examples
    can be found in the [OpenPGP interoperability test suite].

    [unknown packet versions]: https://github.com/rnpgp/rnp/issues/1257
    [unknown critical subpackets]: https://github.com/rnpgp/rnp/issues/1234
    [OpenPGP interoperability test suite]: https://tests.sequoia-pgp.org/
