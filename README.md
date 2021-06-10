# BadPotato

Forked from [here](https://github.com/BeichenDream/BadPotato). Modified to act as a [pwncat-windows-c2](https://github.com/calebstewart/pwncat-windows-c2) plugin, and also not trigger Windows Defender when loaded reflectively.

BadPotato leaks a system token handle through the MS RPN API, which can be used to get `NT AUTHORITY\SYSTEM` access if you have the `SeImpersonatePrivilege`.

# Upstream Sources

[https://github.com/vletoux/pingcastle](https://github.com/vletoux/pingcastle "pingcastle")


[https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/ "PrintSpoofer")
