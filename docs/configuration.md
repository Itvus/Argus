# Configuration & Environment Variables

Argus loads configuration values sequentially from:
1. `~/.argus/.env` (Global user-level configuration)
2. `.env` (Project-level configuration in current working directory)
3. Active operating system environment variables

### Supported Environment Variables

| Variable | Required | Description |
| :--- | :--- | :--- |
| `DISCORD_BOT_TOKEN` | Optional | Discord Bot token for retrieving user profiles, badges, and avatars. |
| `CORDCAT_API_KEY` | Optional | API key for CordCat historical username and FiveM lookup. |
| `HIBP_API_KEY` | Optional | Have I Been Pwned API key for email breach checks. |
| `LEAKCHECK_API_KEY` | Optional | LeakCheck API key alternative for breach exposure lookups. |
| `GITHUB_TOKEN` | Optional | GitHub personal access token to raise rate limits from 60 to 5,000 req/hr. |

### Verifying Configuration

Check the status of loaded keys and file paths using the built-in command:

```powershell
argus config
```

Unset keys will display as `Not Configured`, and any modules depending on them will degrade cleanly without interrupting your scan.
