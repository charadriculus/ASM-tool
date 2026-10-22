# ASM Tool 0.12.2 candidate payload locks

These new locks are separate from the immutable 0.12.1 locks. They add the
existing Obscura 0.2.2 executable and its required sibling worker for Linux
x86-64 and Windows x64; the TCP-only Go scanner remains in place and Nmap is
not included. They also retain existing Typst, Subfaster, DejaVu, platform
runtime files, and the existing Obscura notice file.

The Linux Obscura executable digest is the accepted expected identity
`c1b4548e36549a0228c39c1cc842df425bc7253af2b0a56bd2a538d8ff7e3406`.
The Linux worker digest `1770966b98d1f9c881e7d4f5adda1375b5eec553485d807c35efa5d72a662379`
was observed in the prior phase 6 evidence. No trusted upstream expected
worker digest was available. The lock pins its bytes for this owner-trial
candidate only; worker origin authenticity remains **NOT_VERIFIED**.

The Windows inputs come from the existing Obscura 0.2.2 archive, SHA-256
`db5a3c951f7172eb8f25e6d71bd7120c7128f70f6daed55a6cc4caaabe1674d6`. Prior
evidence recorded the exact two archive members and their hashes. The lock
records those executable member identities and includes the existing x64
`VCRUNTIME140.dll` and `VCRUNTIME140_1.dll` required by both EXEs. Static PE
inspection confirmed both imports. `VCRUNTIME140_1.dll` is taken from the same
previously locked Windows development archive; its SHA-256 is
`a7146c08f89fe5b04541ab507cdb59ff7b44534d4ba3c668a426c6450a03434e`. This does
not establish runtime compatibility on Windows 10 or 11.

Both Linux executables are launched directly by their sibling file paths using
the system ELF interpreter. Obscura's worker path is resolved beside the main
executable; custom loader arguments on the parent would not be inherited by
the worker, so the Obscura binaries are not placed in the bundle's custom
loader tool list. Upstream installation guidance targets Ubuntu 22.04 / glibc
2.35 or newer and requires `libgcc_s.so.1` and `libm.so.6` on the host. Those
libraries are recorded in the payload lock as existing artifact inputs; the
bundled copy under `bin/linux-runtime` is not used by direct Obscura launch.
The owner trial must confirm Linux startup compatibility on its target host.

Obscura browser execution is available for owner trials. The previous network
safety findings remain unresolved: candidate31 recorded a browser TCP/HTTP
contact before CDP Fetch pause, and the Linux strict network gate remains FAIL.
Restoring the browser does not resolve or supersede those findings. Do not
interpret build-time hashes or local fixture checks as a security qualification.

The lock files are build inputs only. Their source paths must resolve to the
same recorded hashes before staging. They do not perform network access,
launch component binaries, establish public redistribution rights, or qualify
a portable release. See the separately prepared 0.12.2 license review and
owner trial plan for remaining distribution and runtime checks.
