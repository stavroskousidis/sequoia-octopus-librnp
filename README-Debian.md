# Debian stable installation

### General

On Debian stable it is not possible to build versions >= v1.2.1.  We
target Debian testing while developing, and thus the Rust toolchain
shipped by Debian stable is often too old to compile current releases
of the Octopus.

You have two options to fix this. Either you install cargo and rustc in a current version from source [rust-lang.org](https://rust-lang.org/ "Rust Programming Language")

Or you go the "debian way" and use the packages from the testing release. This is described below.

### APT preparation

Copy your `sources.list` file to `/etc/apt/sources.list.d/testing.list` and edit as follow:

```
sudo cp /etc/apt/sources.list /etc/sources.list.d/testing.list
sudo sed -i 's/stable/testing/g' /etc/apt/sources.list.d/testing.list
```

Add apt preferences (as root):

```
cat << EOF > /etc/apt/preferences.d/stable.pref
Package: *
Pin: release a=stable
Pin-Priority: 900
EOF
```

```
cat << EOF > /etc/apt/preferences.d/testing.pref
Package: *
Pin: release a=testing
Pin-Priority: 400
EOF
```

### Install

Now, update sources lists and install cargo and rustc from testing.

```
sudo apt update
sudo apt -t testing install rustc cargo
```
You're done. Now you can continue [here](https://gitlab.com/sequoia-pgp/sequoia-octopus-librnp#building-on-linux "Building on Linux")
