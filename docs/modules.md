# Module Reference

### 1. Snowflake Decoder (`argus.modules.snowflake`)
- **Purpose**: Offline 64-bit Discord ID decoding.
- **Operations**:
  - Shifts 22 bits right and adds Discord Epoch (1420070400000 ms) to extract millisecond UTC timestamps.
  - Bitmasks worker ID (`(id & 0x3E0000) >> 17`), process ID (`(id & 0x1F000) >> 12`), and increment counter (`id & 0xFFF`).
  - Calculates human-readable account age (years, days, hours).

### 2. Discord REST API (`argus.modules.discord_api`)
- **Purpose**: Authenticated Discord user lookup via HTTP REST v10.
- **Operations**:
  - Queries `https://discord.com/api/v10/users/{user_id}` with a Bot token.
  - Translates `public_flags` bitmasks into account badges (e.g., Early Supporter, Bug Hunter, Active Developer).
  - Generates 1024px avatar and profile banner URLs.
  - Builds direct search query URLs for Google Lens, Yandex, TinEye, and Bing Visual Search.

### 3. Username Pivot (`argus.modules.username_pivot`)
- **Purpose**: Platform enumeration and bio lead extraction.
- **Operations**:
  - Leverages Maigret for profile checks across developer and gaming networks.
  - Strips page scripts, stylesheets, and corporate footers using BeautifulSoup DOM filtering.
  - Extracts personal Discord tags (`User#1234`), mentions, and personal contact emails.
  - Filters out organizational mailboxes (`support@`, `info@`, `partners@`) and host-matching domains.

### 4. Enrichment Plugins (`argus.modules.enrichment`)
- **Purpose**: Third-party indexer lookups and secondary pivots.
- **Operations**:
  - **CordCat**: Queries historical usernames and CFX/FiveM identifiers.
  - **Breach Lookups**: Checks discovered emails against Have I Been Pwned or LeakCheck APIs.
  - **GitHub Public Audit**: Analyzes public commit history to uncover author emails and compare account creation timelines.
