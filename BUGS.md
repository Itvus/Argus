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
- **Status**: Resolved (safe_escape and Style-based make_link applied; hostile markup verified in tests/test_cli.py)

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

| ID | Severity | Location | Issue |
|---|---|---|---|
| BUG-05 | Medium | `argus/modules/username_pivot.py:149` | `get_base_domain` docstring promises "without www or subdomains" but only strips `www.`; site mailboxes on `mail.example.com` evade the platform-email filter. |
| BUG-06 | Medium | `argus/modules/wayback.py:47` | CDX API is queried over plaintext `http://` and the target URL is interpolated without `urllib.parse.quote` — MITM surface plus query-parameter injection. |
| BUG-07 | Medium | `argus/modules/intelx.py:75` | `await asyncio.sleep(1.0)` then a single result fetch — a race that silently yields false "no hits"; no retry or backoff. |
| BUG-08 | Medium | `argus/orchestrator.py:520-575` | After the parallel phase, Hudson Rock, OpenPGP, RDAP/crt.sh and Holehe (120+ modules per address) run sequentially per email. Three discovered emails turn a fast scan into minutes. |
| BUG-09 | Medium | `argus/**` (39 sites) | 24 `except Exception: ... pass` blocks make network/parse failures indistinguishable from genuine "no hits" in `module_statuses`. `logger.warning` output in `run_username_pivot` is never surfaced (no handler configured). |
| BUG-10 | Low | `argus/modules/snowflake.py` | `decode_snowflake` accepts any 17–20 digit integer without an epoch sanity check; only `is_valid_snowflake` validates, so direct callers on pivot leads can produce absurd dates. |
| BUG-11 | Low | `argus/orchestrator.py` (chained pivot) | Only `discovered_discord_ids[0]` is decoded and queried; additional collected IDs are dropped. |
| BUG-12 | Low | `argus/modules/discord_api.py:120-200` | ~40 lines of profile parsing duplicated between the 200 and 429 retry branches; retries once, ignores `X-RateLimit-Global` and `X-RateLimit-Scope`. |
| BUG-13 | Low | `argus/modules/username_pivot.py:736` | `done_count += 1` from concurrent tasks — progress totals can overshoot. |
| BUG-14 | Low | `argus/modules/enrichment.py:45`, `discord_api.py:109` | `User-Agent` hardcodes `argus/0.1.0` and a placeholder URL `+https://github.com/argus`. |
| BUG-15 | Low | `argus/config.py` | Only uppercase `HTTP_PROXY`/`HTTPS_PROXY` are honored; the lowercase form common on Linux/macOS is ignored. |
| BUG-16 | Low | `argus/report_html.py:1878` | `view_html_report` writes with `NamedTemporaryFile(delete=False)` and never cleans up; temporary reports accumulate in `%TEMP%`. |
| BUG-17 | Low | `argus/compat.py` | Process-wide monkeypatch of the private `_ProactorBasePipeTransport._call_connection_lost`; setting `_called_connection_lost = True` and `_sock = None` can hide non-reset OSErrors and leave transports inconsistent. |
| BUG-18 | Low | working tree | Uncommitted changes to `argus/models.py` and `argus/modules/snowflake.py` add `DiscordProfile.bio` and `SteamProfile.summary`, which no module populates yet. |

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
