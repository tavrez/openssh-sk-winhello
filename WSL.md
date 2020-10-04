# How to use this project on WSL

**TBD**
TL;DR version for now:
Since WSL has no access to security keys, you can use a windows `ssh-sk-helper` and set your WSL OpenSSH to interact with keys through it.
You need to run something like this inside WSL:

```bash
SSH_SK_HELPER=/mnt/c/gitforwindows/usr/lib/ssh/ssh-sk-helper.exe SSH_SK_PROVIDER=c:/gitforwindows/usr/lib/winhello.dll ssh-keygen -t ecdsa-sk
SSH_SK_HELPER=/mnt/c/gitforwindows/usr/lib/ssh/ssh-sk-helper.exe ssh -oSecurityKeyProvider=c:/gitforwindows/usr/lib/winhello.dll user@host
```

- Path to `SSH_SK_HELPER` should be a Linux WSL address but `SSH_SK_PROVIDER` should be a Windows address.

- Any DLL dependency `ssh-sk-helper` needs should be in **Windows `PATH` env variable** or they need to be copied in same folder where `ssh-sk-helper` is(having them in WSL `PATH` env variable won't help).

- `ssh-sk-helper` in Windows and OpenSSH in WSL should use same protocol. So far, all released versions of `ssh-sk-helper` have same protocol.
