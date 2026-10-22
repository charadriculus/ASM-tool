# GUI / Go compatibility matrix — 0.12.3

Source basis: imported GUI source ZIP `ASM_Tool_0.12.0_GUI_development_sources.zip`
(SHA-256 `eed5fa3bc0ce0c8644da8fa688703b26741c48eeb3bf031f76938368ee79d117`),
the 0.12.2 Go source at base `1476e6f`, and the read-only audit in
`planning/patch123/COMPATIBILITY_AUDIT.md`. The older Windows binary ZIP was
not used as a payload.

| Contract | GUI 0.12.0 source | Go 0.12.2 source | 0.12.3 adaptation / evidence |
|---|---|---|---|
| Profiles | Passive, Verify, Full | Same CLI modes | Retained; `start`, profile and `--non-interactive` passed as separate argv tokens |
| Domain | GUI accepted a bare domain/origin | CLI has stricter domain and scope validation | GUI keeps rejection of paths, query, userinfo and ports; Go remains authoritative |
| Authorization | Confirmation dialog before active run | `--confirm-authorization` required for active CLI | Retained; argv emitted only after affirmative confirmation |
| Output | Select output root | CLI requires a new run directory | Retained; runner proposes unique child path and rejects existing output |
| DNS budget | 1..1,000,000 | Positive integer CLI validation | Retained, bounded integer input |
| Passive sources | standard/deep | standard/deep | Retained |
| Report language/full | RU/EN and boolean | RU/EN and `--full-report` | Retained |
| Primary-domain-only / wildcard | Active-only flags | Same flags | Retained; no passive-mode emission |
| HTTP backend fallback | Explicit checkbox | Go fallback requires explicit opt-in | Retained; flag omitted unless checked |
| Browser | GUI 0.12.0 defaulted disable checkbox on | Go active defaults browser enabled; explicit disabled flag exists | Checkbox now defaults off; visible active-mode warning states `NOT_SECURITY_QUALIFIED` and candidate31 FAIL; explicit disable remains available |
| Nmap service detection | Obsolete GUI checkbox and flag | Absent from Go 0.12.2 | Removed from UI, model, argv and test cases |
| TCP ports | Port list in Full | Native Go TCP port scan via `--ports` | Retained; validated 1..65535 and comma-normalized |
| Status states | Historical assumptions | `initializing`, `running`, `complete`, `error`, `interrupted` | Reader validates known state values; exit/status pairing remains authoritative |
| Incomplete | Could be conflated with success | `complete` may carry `incomplete=true`; exit 4 | Only paired exit4+complete+incomplete is shown incomplete; never success |
| Damaged/missing status | Both appeared as null | JSON is atomically written during run | Missing during startup is pending; malformed/oversized/unreadable and absent final status show a diagnostic and cannot pass success |
| Progress | Worker progress if known | `completed` and `planned` may be null | Percent only from valid worker counts; unknown remains indeterminate |
| Worker errors | Diagnostic output | Root status message and per-worker `message`/`state` | Failed worker ID/state/message is shown; error forces indeterminate progress and exit0+complete cannot be treated as success |
| Cancellation | Confirmed forced termination | No cooperative GUI cancellation API | Existing confirmation and Job Object retained; partial results warning retained |
| Process invocation | Separate process | Go executable | `UseShellExecute=false`; `ArgumentList`; verified bundle hash; existing kill-on-job-close Job Object |
| Linux UI | Separate historical GUI not applicable | Existing interactive Go CLI | No Go changes; Linux TUI behavior untouched |

## Targeted scenarios

The adapted GUI self/integration sources cover exact passive argv, active
authorization, explicit browser disable versus the Go default, no legacy
service/Nmap flag, retained TCP ports, malformed/oversized/missing status,
worker error visibility (including contradictory exit0+complete+worker-error),
exit-zero without final status, incomplete/error/
interrupted outcomes, output-directory safety, and accepted-Go `--validate-only`
variants without collection.

These C# scenarios were **not executed here**: the available environment is
Linux without `dotnet` or a Windows runtime. C# build, test execution, GUI
launch, UI automation, and native Job Object behavior are `BLOCKED/NOT_RUN`,
not PASS. The exact Windows commands are in `GUI_INTEGRATION_REPORT.md`.
