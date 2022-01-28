# Debian stable installation

### General

On debian bullseye it is not possible to build versions >= v1.2.1. This is because cargo is shipped in version 0.47 by debian stable. You will get the following error when trying to build:

`this version of Cargo is older than the 2021 edition, and only supports 2015 and 2018 editions.`

The build of <= v1.1.0 is possible, but not compatible with thunderbird 91. You will not be able to receive your keys from the keychain in thunderbird.

You have two options to fix this. Either you install cargo and rustc in a current version from source [rust-lang.org](https://rust-lang.org/ "Rust Programming Language")

Or you go the "debian way" and use the packages from the testing release. This is described below.

### APT preparation

Copy your `sources.list` file to `/etc/apt/sources.list.d/testing.list` and edit as follow:

```
sudo cp /etc/apt/sources.list /etc/sources.list.d/testing.list
sudo sed -i 's/bullseye/bookworm/g' /etc/apt/sources.list.d/testing.list
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
sudo apt -t bookworm install rustc cargo
```
You're done. Now you can continue [here](https://gitlab.com/sequoia-pgp/sequoia-octopus-librnp#building-on-linux "Building on Linux")
