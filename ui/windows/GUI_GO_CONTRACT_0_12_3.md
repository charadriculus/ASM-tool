# Windows GUI ↔ Go CLI contract (0.12.3)

This mapping was checked against the 0.12.2 CLI sources at the 0.12.3 base.
The GUI constructs an argument list and the runner adds each token separately
to `ProcessStartInfo.ArgumentList`.

| GUI field | Go argument | Rule |
|---|---|---|
| Profile | `start --profile passive\|verify\|full` | `passive` default; noninteractive GUI invocation |
| Domain | `--domain VALUE` | Bare DNS name or HTTP(S) origin only; no userinfo, path, query, fragment, or port |
| Results | `--output-dir VALUE` | Fresh output path; existing paths are rejected |
| DNS budget | `--dns-budget N` | Integer 1–1,000,000 in GUI; CLI performs its own validation |
| Passive source depth | `--passive-sources standard\|deep` | `standard` default |
| Report language | `--language ru\|en` | `en` default |
| Full report | `--full-report` | Emitted only when checked |
| Active authorization | `--confirm-authorization` | Emitted only for Verify/Full after GUI confirmation |
| Primary domain only | `--primary-domain-only` | Active profiles only |
| Wildcard ambiguity | `--include-wildcard-ambiguous` | Active profiles only |
| HTTP fallback | `--allow-http-fallback` | Explicit opt-in only |
| Browser disabled | `--browser disabled` | Active profiles only; no browser argument means the Go CLI default |
| TCP ports | `--ports CSV` | Full only; integer ports 1–65535, comma-normalized; empty means Go default |

The old `--service-detection` GUI field was removed because the 0.12.2 Go CLI
does not provide that Nmap option. Native TCP port selection remains available.
The GUI has no separate “browser required” field; it follows the Go active-mode
default unless the user checks “Disable browser checks”. Browser risk remains
unqualified and is displayed before starting an active profile.

The current Go status file has `initializing`, `running`, `complete`, `error`,
and `interrupted` states. The GUI accepts success only for exit code 0 with a
`complete` status and `incomplete=false`; exit code 4 requires `complete` plus
`incomplete=true`; exit code 130 requires `interrupted`. Missing status while
the run is starting is shown as pending. Malformed, oversized, unreadable, or
missing final status receives a bounded diagnostic and cannot become success.
Progress is determinate only when a worker provides valid `completed` and
positive `planned` values. Root/worker error messages remain visible.

The GUI keeps the existing explicit force-stop confirmation and Job Object
cleanup. No cooperative cancellation protocol was added.
