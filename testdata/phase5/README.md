# Phase 5 source fixtures

`fixtures/contracts.json` is generated offline by
`scripts/build_phase5_fixtures.py`. The script extracts selected functions and
data classes from immutable Windows 0.11.3 source, records their SHA-256 pins
and Linux byte parity, and uses only Python standard library code and local
temporary inputs. It does not import the legacy application, run tests from the
legacy project, contact a network, execute native tools, or install packages.

The pin for `active/web/probe.py` is supplementary source identity only;
none of its definitions execute in this oracle.

Regenerate from this directory with `python3 -B scripts/build_phase5_fixtures.py`.
Run `python3 -B scripts/build_phase5_fixtures.py --check` to compare exact bytes;
check mode does not rewrite the fixture file.

The JSON groups cover HTTP record normalization and errors, relative/off-scope/
invalid/budget-limited redirects, robots path extraction and user-agent policy,
HTML semantic URL/text/metadata normalization and dynamic URL candidates,
DNS-confirmed web target ordering/eligibility (including root-first, multiple
eligible targets, primary-only selection, stale ineligible replacement, and
uncertain/out-of-scope exclusions), and the streaming eligibility predicate.
HTTP response rows, redirect scope, DNS events and HTML parser observations
are local fixture inputs. HTTP cases include header normalization, status/error
mapping, a 512-character preview with partial-body state, title and TLS fields.

The AST loader compiles only named top-level definitions. For normalization it
injects stdlib `ipaddress`, `urllib.parse` functions (`urlsplit`, `urlunsplit`,
`parse_qsl`, `urlencode`), then executes the actual `normalize_domain` and
`normalize_url` definitions. The HTML semantic functions receive stdlib `json`,
`re`, `urljoin`, that source-loaded `normalize_url`, `_WS_RE=re.compile(r"\s+")`,
and `_JS_URL_RE=re.compile(r"(?P<url>(?:https?://|/)[A-Za-z0-9_./?=&:%#@+-]+)")`;
`Iterable` and `Any` are annotation-only placeholders. The HTTP record
definitions receive stdlib dataclass helpers and `urljoin`/`urlsplit`; redirect
scope is a local object exposing `check_url` whose result carries `status` and
`reason`. Web target planning reads a temporary JSONL file through an injected
local line reader, calls source-loaded `normalize_domain`, and receives a
fixture ScopeChecker that admits `example.test` and its descendants. Robots
uses stdlib `urllib.robotparser` as the production source does.

HTML feature samples are hand-authored parser observations. The source semantic
normalizer and dynamic-candidate extractor execute unchanged, but BeautifulSoup
and selectolax parser implementations are not executed because their packages
are absent in this offline fixture environment. Therefore these fixtures do not
establish parser or rendered-browser DOM parity. The pipeline fixture covers
only its pure eligibility predicate; async scheduling, live HTTP transport,
native HTTPX and crawler fairness remain outside this oracle.
