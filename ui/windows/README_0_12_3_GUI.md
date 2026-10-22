# ASM Tool 0.12.3 Windows GUI

The WinUI 3 application starts the sibling `asm-tool.exe` after verifying its
SHA-256 entry in `SHA256SUMS`. The GUI passes arguments with
`ProcessStartInfo.ArgumentList`; it does not invoke a shell. Active profiles
require the user to confirm authorization before the Go process starts.

The browser option is enabled by default for active profiles. The GUI displays
the `NOT_SECURITY_QUALIFIED` warning and the historical candidate31 network
security failure. This warning reports the known status; this integration does
not claim to correct or requalify browser isolation. Users can explicitly
disable browser checks.

The interface retains the existing Passive, Verify, and Full profiles and the
native Go TCP port selection. Nmap service detection is not supported. Linux
continues to use the existing interactive Go command line.

Stopping a running scan remains a confirmed force termination. The Go CLI has
no cooperative GUI cancellation protocol. Forced termination can leave
partial results. The process is assigned to the existing Windows Job Object
with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`; the known small interval between
process start and Job assignment remains.

Windows GUI compilation and native interaction must be performed with the
Windows .NET 10 / Windows App SDK toolchain. Source and Linux static checks do
not establish that the WinUI application builds or runs on Windows.
