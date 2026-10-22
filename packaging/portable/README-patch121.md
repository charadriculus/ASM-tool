# Portable payload locks for ASM Tool 0.12.1

`linux-amd64-patch121.lock.json` and `windows-amd64-patch121.lock.json` are
new lock files for the 0.12.1 patch. The accepted 0.12.0 locks remain
unchanged. These files preserve the existing approved Typst, Subfaster, font,
and platform-runtime inputs while removing Nmap executables, data files, and
the Linux libraries needed only by Nmap. The Linux Subfaster ELF was inspected
as data: its only `DT_NEEDED` entry is `libc.so.6`; the locked loader and libc
remain in the Linux runtime closure.

Nmap is not a supported tool or file path in 0.12.1 portable manifests. The
application uses the built-in Go TCP connect scanner and the TCP limits in the
current YAML schema. The locks do not contain Nmap tool entries or staged
Nmap paths. The Windows development archive remains an immutable input source
for other approved files; only explicitly listed members are staged.

The lock entries retain their previously reviewed SHA-256 and provenance
records. No binary was run to create these locks. They are inputs to the
existing offline payload stager and do not by themselves qualify a portable
build.
