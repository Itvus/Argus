# Contributing to Argus

Thank you for your interest in contributing to Argus.

## Development Setup

1. **Clone the repository**:
   ```bash
   git clone https://github.com/your-username/argus.git
   cd argus
   ```

2. **Create a virtual environment**:
   ```bash
   uv venv .venv
   # On Windows:
   .\.venv\Scripts\activate
   # On Linux / macOS:
   source .venv/bin/activate
   ```

3. **Install editable package with dev dependencies**:
   ```bash
   uv pip install -e ".[dev]"
   ```

## Running Tests

All test cases are written using `pytest` and `pytest-asyncio`:

```bash
pytest
```

Ensure all tests pass before opening a pull request.

## Coding Standards

- Type annotations are required for public functions and class methods.
- Keep dependencies minimal to preserve performance.
- Any network operations should be non-blocking and use `httpx.AsyncClient`.
- Avoid extracting or storing personally identifiable data beyond the scope of public OSINT investigation summaries.
