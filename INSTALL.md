# Installation

these files are compiled for the MSYS environment([Git for Windows](https://gitforwindows.org) is using MSYS).
For other environments like Cygwin please refer to [README](https://github.com/tavrez/openssh-sk-winhello/blob/master/README.md#building) file to learn how to download the source code and compile it.

**Note:** If you are using OpenSSH version 8.2p1, you need to install and configure(or compile) a modified [`ssh-sk-helper`](https://github.com/tavrez/openssh-sk-winhello/blob/master/README.md#ssh-sk-helper), if you are using OpenSSH 8.3p1 or higher, it's not needed.

## winhello.dll

Copy this file wherever you want, `/usr/lib` directory is preferred.

## Configure OpenSSH to use winhello

`ssh`, `ssh-keygen`, `ssh-add` can use this module(`sshd` could also use security keys but it's a little weird to do so).

To use in `ssh` open local config file `~/.ssh/config`(or global config `/etc/ssh/ssh_config`) and add this:

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
