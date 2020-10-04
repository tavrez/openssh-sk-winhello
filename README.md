# OpenSSH SK WinHello [![Release](https://img.shields.io/github/v/release/tavrez/openssh-sk-winhello?include_prereleases&sort=semver)](https://github.com/tavrez/openssh-sk-winhello/releases) ![Platform](https://img.shields.io/badge/platform-win32%20%7C%20win64-blue) [![License](https://img.shields.io/github/license/tavrez/openssh-sk-winhello)](https://github.com/tavrez/openssh-sk-winhello/blob/master/LICENSE)

A plugin for OpenSSH to connect to FIDO/U2F security keys through native Windows Hello APIs.
![demo](https://user-images.githubusercontent.com/9096461/79240813-7d887100-7e87-11ea-836b-2d6b6931b593.gif)

## Introduction

OpenSSH version 8.2 added support for authentication using FIDO/U2F hardware security keys.
There are two new key type `ecdsa-sk` and `ed25519-sk` which can be used for this.

Communicating with keys is done through a helper app named `ssh-sk-helper`(by default it is in `/usr/lib/ssh`).
This helper has an internal implementation to connect to FIDO/U2F keys using [libfido2](https://github.com/yubico/libfido2) library and support connecting to keys via HID protocol on USB(no Bluetooth or other things).
`ssh-sk-helper` also supports dynamically loaded middleware libraries to be used instead of internal implementation so you could be able to connect to security keys through other ways.
Details about how to implement those middlewares are described in OpenSSH source in file `PROTOCOL.u2f`.

Internal implementation works well in Windows. However, in Windows 10 version 1903 or higher, you need administrator privileges to be able to access any FIDO device, which means you need to run Bash or other apps calling OpenSSH as administrator or they won't detect your keys, and this is painful.

Windows provides an API set called Windows Hello to access to FIDO/U2F keys without administrator privileges, these APIs are being used in major browsers(Chrome, Firefox, Edge) in Windows for JavaScript WebAuthn implementation.
Windows Hello also supports other types of authenticators like internal TPM device(if they support generating ECDSA or Ed25519 keys, they can be used instead of FIDO/U2F security keys).

So I created this middleware module for OpenSSH to access FIDO/U2F keys through Windows Hello APIs and make everything easier.

## Install

Compiled files of this project are available on GitHub releases. It is compiled for the MSYS environment([Git for Windows](https://gitforwindows.org) is using MSYS).
For other environments like Cygwin please download the source code and compile it yourself according to [Build](#Build) instructions.
**Note:** If you are using OpenSSH version 8.2p1, you need to install and configure(or compile) a modified `ssh-sk-helper`, if you are using OpenSSH 8.3p1 or higher, it's not needed.

1. Download a version of this module which matches your installed OpenSSH Version:
    *Run `ssh -V` to detect your OpenSSH version.*

    - OpenSSH v8.3: Get latest 1.x
    - OpenSSH v8.2: Get latest 1.x **and** custom `openssh-sk-helper`

1. Copy files:

    - Copy `winhello.dll` wherever you want, `/usr/lib` directory is preferred.
    - **v8.2 Only:** Copy `v8.2p1-ssh-sk-helper.exe` into `/usr/lib/ssh` directory, do not replace it with the original `ssh-sk-helper`.

1. Configure OpenSSH to use winhello:

    1. Configure `ssh`:

        - open your local config file on `~/.ssh/config`(or global config file on `/etc/ssh/ssh_config`) and add this:

            ```ssh_config
            Host *
                SecurityKeyProvider winhello.dll
            ```

        - Or use `-oSecurityKeyProvider` every time you use `ssh` command:

            ```bash
            ssh -oSecurityKeyProvider=winhello.dll user@host
            ```

    1. Configure `ssh-keygen` and `ssh-add`/`ssh-agent`:

        - You can set it in your shell init code instead of argument method explained above. For example if you are using Bash, add this line in `~/.bashrc` file:

            ```bash
            export SSH_SK_PROVIDER=/usr/lib/winhello.dll
            ```

            Use absolute path to `winhello.dll` or `ssh-agent` will refuse to add your key.

        - Or set it on every call:

            ```bash
            SSH_SK_PROVIDER=winhello.dll ssh-keygen -t  ecdsa-sk
            SSH_SK_PROVIDER=winhello.dll ssh-add ~/.ssh/id_ecdsa_sk
            ```

        - Or use argument like this:

            ```bash
            ssh-keygen -w winhello.dll -t ecdsa-sk
            ssh-add -S /usr/lib/winhello.dll ~/.ssh/id_ecdsa_sk
            ```

            Note: Use absolute path in `ssh-add`, or `ssh-agent` will block you.

1. **v8.2 Only:** Configure path to custom `ssh-sk-helper`
    you need to set `SSH_SK_HELPER` environment variable

    - In your shell init code:

        ```bash
        export SSH_SK_HELPER=/usr/lib/v8.2p1-ssh-sk-helper.exe
        ```

    - Call it with every command:

        ```bash
        SSH_SK_HELPER=/usr/lib/v8.2p1-ssh-sk-helper.exe ssh user@host
        SSH_SK_HELPER=/usr/lib/v8.2p1-ssh-sk-helper.exe ssh-keygen -t ecdsa-sk
        SSH_SK_HELPER=/usr/lib/v8.2p1-ssh-sk-helper.exe ssh-add ~/.ssh/id_ecdsa_sk
        ```

## Supported flags

You can use some flags during key generation with `ssh-keygen`, there are some small notes about them:

### no-touch-required

Using the `-O no-touch-required` option you can generate a key that doesn't need interacting(e.g touching) with your security key during login(during key generation you should always interact with security key). You should also add `no-touch-required` into the server's `authorized_keys` file or it will prevent you from logging in, for example:

```authorized_keys
no-touch-required sk-ecdsa-sha2-nistp256@openssh.com AAA..... user@host
```

However, Windows API does not support this option(meaning you should always interact with your security key).

Before version 1.1.0 of this module, it would have prevented you from creating or using these keys. But since version 1.1.0, you can create and use them. However, you need to interact with your security key anyway regardless of key settings when you are logging in to a server. This won't make the server becoming angry at you, since you touched your security key when it said it's not necessary.

### resident

By using `-O resident` you can make your key stored inside your security key(it should be FIDO2 compatible). With this, when you want to use your key on a new machine, you don't need to transfer your private/public key files. You can simply run `ssh-keygen -K` command and it will regenerate same private/public keys on new machine.

Using this module can generate these type of keys, but it doesn't support copying resident keys. You need to do it with internal module of OpenSSH. Check [known issues](#Known-issues-and-limitations) for more info.

### credProt Extension

Since OpenSSH version 8.4, if you use OpenSSH internal module and set any of the `resident` or `verify-required` flag, it will also force you to use credProt extension(Before v8.4 there was no `verify-required` option and `resident` option wasn't forced to be this way). I should also note that using or not using this extension has no effect on your login process.

I tried to write this module as close as possible to the internal implementation, but for now seems like credProt is not working correctly in Windows Hello. You can't create keys with this extension and you can't use keys created with this extension(you will get "the key doesn't seems to be familiar" message).
So:

- If you use internal module to create key with credprot enabled: You can use it to login with internal module, but not this module.
- If you use this module to generate keys with `verify-required` and/or `resident` flag: **You can use it anywhere**.

### application

You can change application name with `-O application=ssh:something`, name can be anything starts with `ssh:`.

### user

You can set user name with `-O user=name`, this module use `SSH User` as default name, I strongly recommend you to **set your desired name** if you are using more than one key.

### device

With multiple security keys attached to one system, you can specify which one you are working with using `-O device=id` option.

Windows Hello automatically find your device, so this is not needed and not supported.

### attestation

use `-O attestation=/path/to/newfile` to store attestation data created.

- Check [Limitaions](#Known-issues-and-limitations).

## Use inside WSL

Security keys are not available inside WSL, but you can use a `ssh-sk-helper` on windows and configure your WSL to use it, Check [WSL.md](./WSL.md) for more info.

## Build

### Requirements

`make`, `gcc` and `libssl-dev` are required, you also need `autoconf` `automake` `libtool` if you are cloning from git.

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

You can use `make install` to copy the DLL file into `/usr/lib` but that also copies some static files for linking, those files are not needed because OpenSSH uses `dlopen` to access to middlewares.

## Known issues and limitations

- credProt extension is not working with Windows Hello, you can't create keys with credProt extension and you can't use keys created with this extension.
- because credProt is affecting Attestation data, output attestation of this module will be different with internal module when you use `verify-required` or `resident` flag(both are correct, they are different because configurations are different).
- Windows Hello API does not support empty user ID, so if you do not specify any user ID(using `-O user=myusername` option) this module uses a default user ID `SSH User`. This behavior is different with the internal implementation which uses empty user ID.
- Support for copying resident keys from security key is not available, use internal implementation for this(do not add `-w` to `ssh-key` or `-S` to `ssh-add` or use the word `internal` as the path to the middleware if you have env variable set):

    ```bash
    ssh-keygen -K
    ssh-add -K
    OR
    ssh-keygen -K -w internal
    ssh-add -K -S internal
    ```

    Be sure that you are running Bash as administrator whenever you use internal implementation or you get "Device not found" error.

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## License

OpenSSH project uses BSD license.
Microsoft webauthn.h interface uses MIT license.
This project is available through [LGPLv3](./LICENSE) license.
