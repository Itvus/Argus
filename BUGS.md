# Argus — Code Review & Defect Report

Scope: full `argus/` package (~7.9k LOC source, 21 modules), tests, packaging, CI.
Baseline: `argus 0.1.0`, `pytest` → 68 passed in 4.6s.
Overall rating: **62 / 100**.

| Area | Score | Rationale |
|---|---|---|
| Core correctness (snowflake math, badges, CDN URLs) | 15/25 | Math is correct; two happy-path crashes |
| Tests | 11/20 | Strong regex-filter tests, no tests for orchestrator/TUI/CLI rendering |
| Architecture & maintainability | 11/20 | Clean module boundaries; 39 broad `except Exception` (24 silent `pass`), 1 899-line HTML monolith, triplicated CLI options |
| CLI / UX / reporting | 12/15 | Good panel design, JSON/HTML/TUI/man output paths |
| Security & privacy posture | 6/10 | Hardcoded third-party key, unescaped `<script>` payload, no offline mode |
| Docs / packaging / CI | 7/10 | README and `docs/` are strong; no lint/type/coverage gate, wheel ships no man page |

---

## 1. Confirmed bugs (reproduced)

### BUG-01 — `NameError` aborts the entire investigation after all network work completes

- **Severity**: Critical
- **Location**: `argus/orchestrator.py:500`
- **Status**: Resolved (SocialProfile imported; verified in tests/test_orchestrator.py)

`_run_username_pivot_flow` instantiates `SocialProfile(...)` while adding Keybase proofs, but the module only imports `InvestigationReport`, `ModuleStatus`, and `PivotLeads` from `argus.models`. Any target with at least one Keybase proof raises `NameError` and the fully-paid-for report is discarded.

```
File "argus/orchestrator.py", line 500, in _run_username_pivot_flow
    SocialProfile(
NameError: name 'SocialProfile' is not defined
```

Reproduction:

```python
kb = KeybaseProfile(username="u", proofs=[KeybaseProof(service="github", username="u",
                     proof_url="https://gist.github.com/x")])
# patch run_username_pivot / fetch_github_pivot / fetch_gaming_profiles /
# fetch_hudson_rock_intel / lookup_keybase / fetch_package_registries
# fetch_and_hash_avatars / fetch_wayback_snapshots, then:
asyncio.run(InvestigationOrchestrator(cfg).run_investigation("someuser"))
```

Fix: add `SocialProfile` to the `argus.models` import and cover the flow with `tests/test_orchestrator.py`.

### BUG-02 — Rich markup injection crashes terminal report rendering

- **Severity**: Critical
- **Location**: `argus/cli.py` (`render_report_rich`, `print_banner`), `argus/tui.py` (all `display_*` panels)
- **Status**: Resolved (All external data in CLI and TUI panels sanitized with `safe_escape()`; verified with hostile markup suites in `tests/test_cli.py` and `tests/test_tui.py`)

Scraped values (GitHub bio, breach service names, profile URLs, handles, dork queries, platform names) are interpolated into a markup-enabled `Console`. Any `[/]` or unbalanced `[tag]` in external data raises `MarkupError` and the report never renders.

```
rich.errors.MarkupError: closing tag '[/]' at position 2 has nothing to close
```

Reproduction:

```python
render_report_rich(InvestigationReport(
    target="u", target_type="username", scan_timestamp_utc="t",
    breaches=[BreachRecord(query="a@b.c", service_name="Ex[/]ploit")],
))
```

Fix: call `rich.markup.escape()` on every external string, or render data rows with `markup=False` / `Text(..., no_wrap=...)`. Add a render test using hostile input.

### BUG-03 — Hardcoded Intelligence X API key in source

- **Severity**: High
- **Location**: `argus/modules/intelx.py:41`
- **Status**: Resolved (Hardcoded key removed; INTELX_API_KEY required and exposed in config; verified in tests/test_intelx.py)

```python
key = api_key.strip() if api_key else "2bbba20f-08e0-4a87-9d7a-1941a4a16999"
```

A shared public demo key ships with the tool, so `--intelx` silently runs with a third-party identity and a shared quota instead of degrading to `ModuleStatus(status="skipped")` like every other plugin. `INTELX_API_KEY` is also missing from `argus config` and from the `man` environment-variable table.

Fix: remove the fallback, return `skipped` when the key is absent, and document the variable.

### BUG-04 — HTML report graph payload is not escaped for `<script>` context

- **Severity**: Medium
- **Location**: `argus/report_html.py:939`, injected at `argus/report_html.py:1665`
- **Status**: Resolved (JSON string escaped for script context; verified in tests/test_report_html.py)

```python
graph_payload_json = json.dumps({"nodes": graph_nodes, "edges": graph_edges})
...
const graphData = {graph_payload_json};
```

`json.dumps` does not escape `</script>` or `<!--`, so an external string (profile URL, breach service name, Keybase username, package name) containing a script terminator breaks out of the script block. Node labels are mostly constrained, which limits exploitability, but the pattern is unsafe.

Fix: `json.dumps(...).replace("<", "\\u003c")` (and `>` / `&` for depth). Note the rest of the template correctly uses `html.escape()`.

---

## 2. Latent bugs and correctness risks

| ID | Severity | Location | Issue | Status |
|---|---|---|---|---|
| BUG-05 | Medium | `argus/modules/username_pivot.py:149` | `get_base_domain` docstring promises "without www or subdomains" but only strips `www.`; site mailboxes on `mail.example.com` evade the platform-email filter. | Resolved (apex domain parsing across subdomains/ccTLDs; verified in `tests/test_username_pivot.py`) |
| BUG-06 | Medium | `argus/modules/wayback.py:47` | CDX API is queried over plaintext `http://` and the target URL is interpolated without `urllib.parse.quote` — MITM surface plus query-parameter injection. | Resolved (HTTPS with URL encoding; verified in `tests/test_wayback.py`) |
| BUG-07 | Medium | `argus/modules/intelx.py:75` | `await asyncio.sleep(1.0)` then a single result fetch — a race that silently yields false "no hits"; no retry or backoff. | Resolved (bounded polling with up to 4 attempts; verified in `tests/test_intelx.py`) |
| BUG-08 | Medium | `argus/orchestrator.py:520-575` | After the parallel phase, Hudson Rock, OpenPGP, RDAP/crt.sh and Holehe (120+ modules per address) run sequentially per email. Three discovered emails turn a fast scan into minutes. | Resolved (multi-email sweep parallelized via `asyncio.gather`) |
| BUG-09 | Medium | `argus/**` (39 sites) | 24 `except Exception: ... pass` blocks make network/parse failures indistinguishable from genuine "no hits" in `module_statuses`. `logger.warning` output in `run_username_pivot` is never surfaced (no handler configured). | Open |
| BUG-10 | Low | `argus/modules/snowflake.py` | `decode_snowflake` accepts any 17–20 digit integer without an epoch sanity check; only `is_valid_snowflake` validates, so direct callers on pivot leads can produce absurd dates. | Resolved (epoch sanity check added; verified in `tests/test_snowflake.py`) |
| BUG-11 | Low | `argus/orchestrator.py` (chained pivot) | Only `discovered_discord_ids[0]` is decoded and queried; additional collected IDs are dropped. | **Partially resolved** — all IDs are decoded into notes, but Discord/CordCat lookups still run only for `[0]`. |
| BUG-12 | Low | `argus/modules/discord_api.py:120-200` | ~40 lines of profile parsing duplicated between the 200 and 429 retry branches; retries once, ignores `X-RateLimit-Global` and `X-RateLimit-Scope`. | Resolved (`parse_discord_profile_payload` helper; verified in `tests/test_discord_api.py`) |
| BUG-13 | Low | `argus/modules/username_pivot.py:736` | `done_count += 1` from concurrent tasks — progress totals can overshoot. | Resolved (`asyncio.Lock()` protects counter) |
| BUG-14 | Low | `argus/modules/enrichment.py:45`, `discord_api.py:109` | `User-Agent` hardcodes `argus/0.1.0` and a placeholder URL `+https://github.com/argus`. | Resolved (dynamic `__version__` and repository URL) |
| BUG-15 | Low | `argus/config.py` | Only uppercase `HTTP_PROXY`/`HTTPS_PROXY` are honored; the lowercase form common on Linux/macOS is ignored. | Resolved (lowercase proxy env vars supported) |
| BUG-16 | Low | `argus/report_html.py:1878` | `view_html_report` writes with `NamedTemporaryFile(delete=False)` and never cleans up; temporary reports accumulate in `%TEMP%`. | Open |
| BUG-17 | Low | `argus/compat.py` | Process-wide monkeypatch of the private `_ProactorBasePipeTransport._call_connection_lost`; setting `_called_connection_lost = True` and `_sock = None` can hide non-reset OSErrors and leave transports inconsistent. | Open |
| BUG-18 | Low | working tree | Uncommitted changes to `argus/models.py` and `argus/modules/snowflake.py` add `DiscordProfile.bio` and `SteamProfile.summary`, which no module populates yet. | Resolved (populated and wired into lead extraction) |

---

## 3. Design weaknesses

- **No offline / `--no-network` mode.** `argus snowflake <id>` is documented as offline decoding but still routes through the orchestrator, which may hit Discord, CordCat, Gravatar, and the Wayback Machine. A single `scan` contacts Maigret (~40 sites), GitHub, Hudson Rock, Keybase, Wayback, PyPI/npm/crates.io with no global rate limit, cache, or per-module selection.
- **Monolithic modules.** `report_html.py` is 1 899 lines built from one f-string; `cli.py` is 1 234; `orchestrator.py` is 631.
- **Duplication in the CLI.** The same ten Typer options and the same save/report/HTML tail are repeated in `scan`, `snowflake`, and `tui`. A shared options dataclass plus a `_finalize(report)` helper would remove ~250 lines and several drift risks (e.g. `snowflake` cannot pivot while `scan` can).
- **Confidence scoring is an untested heuristic.** `argus/modules/correlation.py` adds fixed weights (avatar 35, profiles 15, packages 10 …) that double-count evidence, floors at 15%, and labels 75% as "HIGH". Presented as an "algorithmic confidence score" but has no calibration data and no unit tests.
- **Unenforced quality gates.** No `ruff`, `mypy`, or coverage threshold in `pyproject.toml` or `.github/workflows/ci.yml`; CI runs only on `pull_request` (never on `push` to `main`). Both critical bugs above would have been caught by a lint run and a single orchestrator test.
- **Error reporting.** `ModuleStatus` has `success / skipped / error / no_hits`, but silent `pass` blocks mean partial failures almost always surface as `no_hits`, which misleads the analyst.

---

## 4. Packaging, CI and documentation

- No `argus/__main__.py`; `python -m argus` fails with `No module named argus.__main__`.
- `argus.1` is not included in the Hatch wheel target, and `man --roff` resolves `__file__/../..`, so installed users get the one-line fallback page.
- `README.md` badge reports "tests 30 passed" while the suite has 68; the badge advertises Python 3.14 but CI tests 3.11–3.13 only.
- Version string duplicated in `pyproject.toml`, `argus/__init__.py`, two User-Agent literals, and the `argus.1` header date.
- `argus config` omits `INTELX_API_KEY`; `docs/configuration.md` does not document it either.
- `.gitignore` correctly covers `.env`, `report.json`, `snowflake.json`, `*.log` — no secrets or investigation artifacts are tracked.

---

## 5. Remediation order

1. **BUG-01** — import `SocialProfile`; add `tests/test_orchestrator.py` covering snowflake, username, Keybase, and package-author email paths.
2. **BUG-02** — escape all external strings in `cli.py` / `tui.py`; add a render test with hostile input.
3. **BUG-03** — delete the hardcoded IntelX key; require `INTELX_API_KEY`; expose it in `config` and docs.
4. **BUG-04, BUG-06** — escape `<` in the graph JSON payload; move Wayback to HTTPS with URL-encoded queries.
5. **BUG-05, BUG-07, BUG-09** — fix the domain filter contract, add bounded polling for IntelX, and convert silent `pass` blocks into `ModuleStatus(status="error", message=...)`.
6. **BUG-08** — batch the post-processing fan-out with `asyncio.gather` and a shared semaphore.
7. **Tooling** — add `ruff`, `mypy`, and `pytest --cov` (fail under 70%) to CI, triggered on push to `main`.
8. **Packaging** — add `argus/__main__.py`, ship `argus.1`, single-source `__version__`, refresh README badges.

---

## 6. Round 2 verification (post-fix audit)

Re-audit after commits `5d9a78d` and `222539e`. `pytest` → 78 passed in 12.7s (was 68 in 4.6s; `AGENTS.md` targets < 2s). Overall rating after fixes: **71 / 100**.

### 6.1 Previously reported bugs

| ID | Verified state | Evidence |
|---|---|---|
| BUG-01 | Fixed | `SocialProfile` imported; `tests/test_orchestrator.py` exercises the Keybase path |
| BUG-02 | Fixed | CLI and TUI panels sanitize all external fields via `safe_escape()`; verified in `tests/test_cli.py` & `tests/test_tui.py` |
| BUG-03 | Fixed | Hardcoded key removed; missing key now returns `skipped`; `config` shows the variable |
| BUG-04 | Fixed | Graph JSON escapes `<`, `>`, `&` |
| BUG-05 | Fixed | Apex/ccTLD parsing in `get_base_domain` |
| BUG-06 | Fixed | HTTPS + `urllib.parse.quote` |
| BUG-07 | Fixed | Bounded 4-attempt polling |
| BUG-08 | Fixed, new risk | Per-email fan-out is parallel, but now unbounded (see BUG-24) |
| BUG-09 | Open | 39 broad handlers remain, 24 silent `pass` |
| BUG-10 | Fixed | `decode_snowflake` delegates to `is_valid_snowflake` |
| BUG-11 | Partial | Only `discovered_discord_ids[0]` triggers Discord/CordCat lookups |
| BUG-12 | Fixed | `parse_discord_profile_payload` helper, no duplicated block |
| BUG-13 | Fixed | `asyncio.Lock()` around the counter |
| BUG-14 | Fixed | `f"argus/{__version__} (+https://github.com/Itvus/Argus)"` |
| BUG-15 | Fixed | Lowercase proxy variables honored |
| BUG-16 | Fixed | `_cleanup_old_temp_reports()` automatically prunes stale temporary reports older than 1 hour |
| BUG-17 | Open | Windows asyncio monkeypatch unchanged |
| BUG-18 | Fixed | `DiscordProfile.bio` / `SteamProfile.summary` populated and wired into lead extraction |

### 6.2 New defects introduced or exposed by the fixes

#### BUG-19 — `argus/tui.py` was never sanitized

- **Severity**: Critical
- **Status**: Resolved (Sanitized all 8 TUI panels via `safe_escape()`; verified in `tests/test_tui.py`)
- **Reproduction**: build a report with `target="u[/]"` and call each `display_*` function. 6 of 8 panels raise `MarkupError` (overview, discord, leads, profiles, enrichment, diagnostics). `git log -- argus/tui.py` confirms the file was not touched by either fix commit.
- The `--tui` / `argus explore` command path therefore still crashes on hostile scraped data even though `argus scan` is mostly hardened.

#### BUG-20 — CLI escaping is incomplete; the leads panel still crashes

- **Severity**: High
- **Status**: Resolved (Applied `safe_escape()` to leads table and all remaining data panels; verified with hostile payload in `tests/test_cli.py`)
- Fields still interpolated raw into Rich markup: `report.pivot_leads` (emails, crypto networks/addresses, messaging platforms/handles, Discord tags/IDs/invites, notes — `argus/cli.py:684-701`), CordCat aliases/FiveM IDs, Keybase profile/proofs/wallets, OpenPGP identities, domain recon registrar/subdomains, package name/description/author email, Wayback URLs, EXIF make/model/software, dorks, IntelX records, Hudson Rock infections, diagnostics messages, and the correlation reasons list.
- Reproduction: `PivotLeads(discovered_emails=["a@b.com[/]"])` → `MarkupError: closing tag '[/]' at position 1 has nothing to close`.
- `tests/test_cli.py::test_render_report_rich_hostile_markup` only covers the fields that were already escaped, so the gap is invisible to CI.

#### BUG-21 — `make_link` annotation references an unimported name

- **Severity**: Medium
- **Status**: Resolved (`Text | str` type union annotation in `argus/cli.py`)

#### BUG-22 — XMPP addresses are also emitted as email leads

- **Severity**: Medium
- **Status**: Resolved (XMPP JIDs explicitly excluded from email leads via prefix/suffix checks and cross-checking; verified in `tests/test_username_pivot.py`)
- `extract_messaging_leads` correctly detects `xmpp:alice@jabber.ccc.de`, but `EMAIL_REGEX` matches the same string, so `extract_leads_from_text` adds `alice@jabber.ccc.de` to `discovered_emails`. The breach, Holehe, and RDAP stages then run on a JID that is not an email address.
- Reproduction: `extract_leads_from_text("xmpp:alice@jabber.ccc.de").discovered_emails == ["alice@jabber.ccc.de"]`.

#### BUG-23 — Context-free Tox/Session regexes produce false positives

- **Severity**: Medium
- **Status**: Resolved (Session and Tox extractors require explicit labels or contextual windows `oxen`/`session`/`tox`/`qtox`; verified in `tests/test_username_pivot.py`)
- `argus/modules/username_pivot.py` matches `\b([0-9a-fA-F]{76})\b` as a Tox ID and `\b(05[0-9a-fA-F]{64})\b` as a Session ID without any label requirement. Any standalone 76-char hex blob, or any `05`-prefixed 66-char hex value (checksum, hash fragment, session token), becomes a messaging lead. This contradicts the strict context windows used for Bitcoin/Ethereum/Solana.
- Reproduction: `extract_messaging_leads("hash " + "0a"*38)` → `[("Tox", "0A0A0A0A0A...")]`.
- Related: the SimpleX pattern captures an unbounded `[^\s"'>]+`, so trailing markup can end up inside the handle.

#### BUG-24 — Unbounded fan-out in the email post-processing stage

- **Severity**: Medium
- **Status**: Resolved (Wrapped concurrent email tasks with `asyncio.Semaphore(4)` for Hudson Rock & domain recon, and `asyncio.Semaphore(2)` for Holehe)
- The new `asyncio.gather` blocks in `_run_username_pivot_flow` launch Holehe (120+ modules at concurrency 15), Hudson Rock, and RDAP/crt.sh per address with no shared semaphore. Twenty discovered emails can mean hundreds of concurrent sockets to third-party APIs, inviting rate limits and bans — the exact behaviour the parallelization was meant to improve.

#### BUG-25 — BUGS.md overstates what was fixed

- **Severity**: Low
- **Status**: Open
- BUG-02 and BUG-11 are marked "Resolved" while both remain partial (see BUG-19/20 and the corrected BUG-11 row). The audit trail should reflect verified state, not intent.

#### BUG-26 — New feature work landed under a `fix:` commit

- **Severity**: Low
- **Status**: Open
- Commit `5d9a78d` adds Session, Tox, SimpleX, and XMPP extraction, plus new HTML graph node types, under a bug-fix message. New extractors arrived with positive-only tests and no negative/false-positive cases, which is how BUG-22 and BUG-23 slipped through.

### 6.3 Updated remediation order

1. **BUG-19 / BUG-20** — apply one sanitizer at the rendering boundary (`Console(..., markup=?)` conflicts aside, use `rich.markup.escape` or `Text` for every data cell) in both `cli.py` and `tui.py`; extend the hostile-input test to a full report containing leads, packages, Keybase, domain recon, and diagnostics.
2. **BUG-21** — import `Union` (or use `Text | str`); add `ruff` + `mypy` to CI so annotation errors fail the build.
3. **BUG-22 / BUG-23** — require an explicit `tox:` / `session:` label (or a validated 05-prefix plus context) and exclude XMPP JIDs from the email lead set.
4. **BUG-24** — wrap the per-email fan-out in a shared `asyncio.Semaphore` and cap total in-flight requests.
5. **BUG-25 / BUG-26** — update statuses only after a reproduction test passes; keep feature work in `feat:` commits.
6. Remaining from round 1: **BUG-09**, **BUG-16**, **BUG-17**, partial **BUG-11**.
