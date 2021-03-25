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


