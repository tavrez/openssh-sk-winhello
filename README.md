# OpenSSH SK WinHello [![Release](https://img.shields.io/github/v/release/tavrez/openssh-sk-winhello)](https://github.com/tavrez/openssh-sk-winhello/releases) ![Platform](https://img.shields.io/badge/platform-win32%20%7C%20win64-blue) [![License](https://img.shields.io/github/license/tavrez/openssh-sk-winhello)](https://github.com/tavrez/openssh-sk-winhello/blob/master/LICENSE)

A plugin for OpenSSH to connect to FIDO/U2F security keys through native Windows Hello APIs.
![demo](https://user-images.githubusercontent.com/9096461/79240813-7d887100-7e87-11ea-836b-2d6b6931b593.gif)

## Introduction

OpenSSH version 8.2 added support for authentication using FIDO/U2F hardware security keys.
There are two new key type `ecdsa-sk` and `ed25519-sk` which can be used for this.

Communicating with keys is done through a helper app named `ssh-sk-helper`(by default it is in `/usr/lib/ssh`).
This helper has an internal implementation to connect to FIDO/U2F keys using [libfido2](https://github.com/yubico/libfido2) library and support connecting to keys via HID protocol on USB(no Bluetooth or other things).
`ssh-sk-helper` also supports dynamically loaded middleware libraries to be used instead of internal implementation so you can connect to security keys through other ways.
Details about how to implement those middlewares are described in OpenSSH source in file `PROTOCOL.u2f`.

Internal implementation works well in Windows. However, in Windows 10 version 1903 or higher, you need administrator privileges to be able to access any FIDO device, which means you need to run bash or other apps calling OpenSSH as administrator or they won't detect your keys, and this is painful.

Windows provides an API set called Windows Hello to access to FIDO/U2F keys without administrator privileges, these APIs are being used in major browsers(Chrome, Firefox, Edge) in Windows for JavaScript WebAuthn implementation.
Windows Hello also supports other types of authenticators like internal TPM device(if they support generating ecdsa or ed25519 keys, they can be used instead of FIDO/U2F security keys).

So I created this middleware module for OpenSSH to access FIDO/U2F keys through Windows Hello APIs and make everything easier.

## Installation

Compiled files of this project are available on GitHub releases. It is compiled for the MSYS environment([Git for Windows](https://gitforwindows.org) is using MSYS).
For other environments like Cygwin please download the source code and compile it yourself.

**Note:** If you are using OpenSSH version 8.2p1, you need to install and configure(or compile) a modified [`ssh-sk-helper`](#ssh-sk-helper), if you are using OpenSSH 8.3p1 or higher, it's not needed.

### winhello.dll

Copy this file wherever you want, `/usr/lib` directory is preferred.

### Configure OpenSSH to use winhello

`ssh`, `ssh-keygen`, `ssh-add` can use this module(`sshd` could also use security keys but it's a little weird to do so).

To use in `ssh` open `ssh_config`(normally in `/etc/ssh`) and add this:

```ssh_config
Host *
    SecurityKeyProvider winhello.dll
```

For use in `ssh-keygen` use `-w` argument like this:

```bash
ssh-keygen -t ecdsa-sk -w winhello.dll
```

And for use in `ssh-add` use `-S` command(If you do not use full path in `ssh-add`, `ssh-agent` may block you):

```bash
ssh-add -S /usr/lib/winhello.dll ~/.ssh/id_ecdsa_sk
```

You can also set `SSH_SK_PROVIDER` environment variable in your shell init code for `ssh-keygen` and `ssh-add` instead of argument method explained above. For example if you are using bash, add this line in `~/.bashrc` file:

```bash
export SSH_SK_PROVIDER=/usr/lib/winhello.dll
```

Use the full path to `winhello.dll` or `ssh-agent` will probably refuse to add your key.

## Building

If you are downloading tarball:

```bash
./configure
make
```

If you are cloning from Git:

```bash
autoreconf --install
./configure
make
```

`make install` will copy the DLL file properly into `/usr/lib` but it also copies some static files for linking, those files are not needed because OpenSSH will use `dlopen` to access to middlewares.

## ssh-sk-helper

Due to some limitations in the version 8.2p1 of OpenSSH, to use this project you need to change some code inside OpenSSH `ssh-sk-helper` binary(more detail about this on the next part).
The patch to these changes is available in this repository, also a binary version is provided.
This modified `ssh-sk-helper` functionality is the same and you won't fill any differences when using it unless you want to use another module that expects the original interface.

### Technical Info

`ssh-sk-helper` hash the challenge before it sends it to the module, so in `sk_enroll` and `sk_sign` functions received challenge is hashed, but Windows requires receiving the plain challenge and hash it by itself, so currently we will hash data two times which cause failure in server verification.
I've changed `ssh-sk.c` and removed hashing from it and moved it to `sk-usbhid.c` and bumped API version to prevent other modules expecting original implementation to connect.

### Installing ssh-sk-helper.exe

Copy the uploaded `ssh-sk-helper.exe` into `/usr/lib/ssh`. You should rename the original file in that directory before copying this one.

### Setup ssh-sk-helper.exe

Use the `SSH_SK_HELPER` environment variable to call the modified helper whenever you want to use this projects module:

```bash
SSH_SK_HELPER=/usr/lib/ssh/custom_ssh-sk-helper.exe ssh ...
```

Or just add this into your shell init file:

```bash
export SSH_SK_HELPER=/usr/lib/ssh/custom_ssh-sk-helper.exe
```

### Builing ssh-sk-helper

Download OpenSSH 8.2p1 source code and apply the provided patch to it:

```bash
cd openssh-source
patch -p1 < ssh-sk-helper.patch
```

Then compile it according to your environment instructions.
After that, just copy `ssh-sk-helper` and use it on your main installation of OpenSSH.

## Limitations

- This module doesn't support `no-touch-required` option due to its support not available in Windows Hello APIs.
- Windows Hello API does not support empty user ID, so if you do not specify any user ID(using `-O user=myusername` option) this module uses a default user ID `SSH User`, this behavior is different from the internal implementation which uses empty user ID.
- Support for copying resident keys from security key is not available(yet), use internal implementation for this(do not add `-w` to `ssh-key` or `-S` to `ssh-add` or use the word `internal` as the path to middleware):

    ```bash
    ssh-keygen -K
    ssh-add -K
    OR
    ssh-keygen -K -w internal
    ssh-add -K -S internal
    ```

    Be sure that you are running bash as administrator whenever you use internal implementation or you get "Device not found" error.

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## License

OpenSSH project uses BSD license.
Microsoft webauthn.h interface uses MIT license.
This project is available through [LGPLv3](./LICENSE) license.
