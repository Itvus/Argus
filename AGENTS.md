# AGENTS.md — Developer & AI Agent Guidelines for Argus

This document serves as the operational handbook for AI agents and automated assistants working within the **Argus** codebase. Follow these rules and workflows strictly to ensure code quality, platform safety, and seamless repository synchronization.

---

## 1. Project Overview & Tech Stack

Argus is a fast, modular, Windows-optimized OSINT reconnaissance CLI designed to pivot between 64-bit Discord Snowflake IDs, cross-platform social profiles, and third-party transparency indexers.

- **Language**: Python 3.11+
- **Build System**: Hatchling (`pyproject.toml`)
- **CLI Framework**: Typer with universal `-h` / `--help` and `-v` / `--version` flags
- **Terminal UI**: Rich (Panels, Tables, Live Progress Bars)
- **HTTP Engine**: `httpx` with `asyncio`
- **Username Enumeration**: `maigret` (imported library with async subprocess fallback)
- **DOM & Bio Parsing**: `beautifulsoup4`
- **Data Validation**: Pydantic v2
- **Testing**: `pytest` & `pytest-asyncio`

---

## 2. Environment & Working Directory

- The project root is `st/` (`Argus/`).
- The virtual environment is located at `.venv/`.
- Commands on Windows PowerShell should target the virtual environment directly:
  ```powershell
  # Run test suite
  .\.venv\Scripts\pytest

  # Execute CLI through virtualenv
  .\.venv\Scripts\python -m argus.cli --help

  # Or via global uv tool if installed in editable mode
  argus --help
  ```

---

## 3. Commit Message Standards (No Cringe Overexplanation)

Commit messages must be concise, professional, and written in the imperative mood.

### Format
`<type>: <short imperative subject>`

### Types
- `feat`: A new feature or capability
- `fix`: A bug fix or false-positive correction
- `refactor`: Code changes that neither fix a bug nor add a feature
- `test`: Adding or correcting unit tests
- `docs`: Documentation, README, or guide updates
- `chore`: Dependency updates, tooling, or CI configuration

### Rules
1. **Be concise**: Keep the commit summary under 72 characters.
2. **Imperative mood**: Use "add", "fix", "update", "refactor" (not "added", "fixed", "updating").
3. **No conversational fluff**: Never explain your thought process, cite user conversations, apologize, or write essays in commit messages.
4. **Good examples**:
   - `fix: filter role-based emails and npm versions from profile scrape`
   - `docs: update capabilities matrix and roadmap in README`
   - `feat: implement SOCKS5 proxy rotation flag`
   - `test: add unit tests for Discord ID mention pattern`
5. **Bad examples**:
   - ❌ `I fixed the email bug that the user told me about in chat and also cleaned some files`
   - ❌ `Updated README to be super cool and awesome 🚀🚀`
   - ❌ `Fixed stuff`

---

## 4. Documentation & README Style Guidelines

When editing `README.md` or files in `docs/`, strictly follow these anti-slop rules:

1. **Emojis**: Avoid decorative emoji clutter in titles, headings, and paragraph body text. Clean status indicators (e.g., ✅ Supported, ⏳ Planned) inside the Capabilities & Roadmap matrix table are permitted.
2. **No Fake Terminal Previews**: Never insert simulated ASCII terminal box art. Show real command examples and code snippets instead.
3. **No Cheesy ASCII Logo Art**: Use the clean SVG banner (`assets/banner.svg`) or standard Markdown text headers.
4. **Self-Comparison & Roadmap Only**: Never create competitive comparison matrices attacking or comparing against other tools. Instead, maintain a clear **Current Capabilities & Roadmap** table documenting what Argus currently supports vs. what is planned for future releases.
5. **Tone**: Direct, technical, and engineer-focused. Avoid marketing buzzwords, vague superlatives, and filler text.
6. **Alert Callouts**: Use GitHub Alerts (`[!CAUTION]` red for Legal & Ethical Disclaimers, `[!NOTE]` for License notices) to frame policy statements clearly.

---

## 5. CRITICAL: HOW TO PUSH (Important)

Every agent must follow this exact step-by-step workflow whenever saving and pushing changes to GitHub. **Never skip pre-push verification.**

### Step 1: Pre-Push Verification (Mandatory)
Before touching Git, you **MUST** run the full test suite and confirm 100% pass rate:
```powershell
.\.venv\Scripts\pytest
```
If any test fails, resolve the regression immediately before staging.

### Step 2: Safety & Secret Check
Verify that no sensitive files or investigation artifacts are untracked or staged:
- Never commit `.env` or any file containing live API keys (`DISCORD_BOT_TOKEN`, `CORDCAT_API_KEY`, etc.).
- Never commit test investigation dumps (`report.json`, `snowflake.json`, `*.log`).
- Check that `.gitignore` properly covers temporary artifacts.

### Step 3: Check Git Status & Stage Changes
Inspect modified files to ensure only intentional changes are included:
```powershell
git status
```
Stage specific modified files:
```powershell
git add <path/to/file1> <path/to/file2>
# Or stage all tracked and relevant new files:
git add -A
```

### Step 4: Write a Descriptive Commit Message
Follow the commit message standards defined in Section 3:
```powershell
git commit -m "<type>: <concise description>"
```

### Step 5: Push to Remote Tracking Branch
Push to the upstream repository on the `main` branch:
```powershell
git push origin main
# Or if upstream tracking is set:
git push
```

### Step 6: Verify Remote Synchronization
Confirm that local and remote branches are in sync:
```powershell
git status
```
The output must report: `Your branch is up to date with 'origin/main'.` and `nothing to commit, working tree clean`.

---

## 6. Architectural Rules & Invariants

When adding features or modifying modules, you must adhere to the following architectural invariants:

### A. Windows Asyncio Socket Lifecycle (`argus.compat`)
- **Problem**: On Windows, CPython's `ProactorEventLoop` throws unhandled `ConnectionResetError: [WinError 10054]` exceptions inside `_ProactorBasePipeTransport._call_connection_lost` when remote HTTP servers forcibly terminate TCP connections.
- **Rule**: Always import `argus.compat` early and execute CLI async operations through `argus.compat.run_async()`. Never bypass the socket suppression patches.

### B. Profile Lead Extraction & Anti-Noise Standards (`username_pivot.py`)
- **Problem**: Running unconstrained regular expressions over raw HTML source code extracts script URLs, CDN package versions (`bundle@1.2.1`), and corporate footer mailboxes (`support@discord.com`, `staff@engadget.com`).
- **Rule**:
  1. Always parse HTML with `BeautifulSoup` and **decompose** `<script>`, `<style>`, `<noscript>`, `<header>`, `<footer>`, `<nav>`, `<aside>`, `<iframe>`, cookie banners, and widgets before text extraction.
  2. Prioritize dedicated metadata (`<meta name="description">`, `<meta property="og:description">`) and bio containers (`.user-bio`, `.profile-bio`, `.p-note`).
  3. **Discord IDs**: Must require explicit contextual markers (e.g., `discord: <id>`, `<@id>`, `discord.com/users/<id>`) and pass `is_valid_snowflake()`. Never match raw un-prefixed numbers from general page text.
  4. **Emails**: Must conform to strict RFC domain syntax with alphabetic TLDs. Discard role-based mailboxes (`support@`, `info@`, `admin@`, etc.) and emails matching the host domain of the site being scraped.
  5. **Discord Invites**: Must filter out known platform servers and servers matching the scraped site's name.

### C. Discord Handle Representation
- Discord has no public profile landing pages (`https://discord.com` is just the marketing homepage).
- Discord accounts detected during a pivot must be formatted as `@username` with `(Handle Registered)`. Never display `https://discord.com` as a profile link.

### D. Graceful Module Degradation
- All third-party plugins (CordCat, Have I Been Pwned, LeakCheck, GitHub) must run concurrently and degrade gracefully when API keys are absent.
- If a key is missing, return `ModuleStatus(status="skipped")` with an informative message. **Never crash or raise an unhandled exception for a missing key.**

---

## 7. Adding Tests for New Changes

Any change or addition to the codebase requires corresponding tests in `tests/`:
- Keep unit tests deterministic and fast (< 2 seconds total suite execution).
- Mock external network requests using `unittest.mock.AsyncMock` or dummy responses rather than querying live production APIs.
- Ensure all 30+ baseline tests pass before pushing.
