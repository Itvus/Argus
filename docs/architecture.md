# Argus Architecture & System Design

Argus is an asynchronous OSINT investigation tool designed to pivot between Discord Snowflake IDs and cross-platform username handles.

```
                  +-----------------------+
                  |  Target Specification |
                  +-----------+-----------+
                              |
                     [Auto-Detection]
                              |
               +--------------+--------------+
               |                             |
      (Snowflake ID)                    (Username)
               |                             |
       +-------v-------+             +-------v-------+
       |   Snowflake   |             |    Maigret    |
       |    Decoder    |             |  Enumerator   |
       +-------+-------+             +-------+-------+
               |                             |
       +-------v-------+             +-------v-------+
       |  Discord API  |             | Bio Lead Ext. |
       | & CDN Ingest  |             | (DOM Parsed)  |
       +-------+-------+             +-------+-------+
               |                             |
       +-------v-------+             +-------v-------+
       |    CordCat    |             |  Breach Check |
       |  Enrichment   |             | & GitHub Audit|
       +-------+-------+             +-------+-------+
               |                             |
               +--------------+--------------+
                              |
                    +---------v---------+
                    |  Unified Report   |
                    | (Pydantic Models) |
                    +-------------------+
```

## Key Components

1. **Snowflake Math**: Uses bitwise operations to compute UTC timestamps and hardware identifiers directly from 64-bit Discord IDs without network overhead.
2. **Discord API Client**: Resolves public profiles, avatars, banners, and account badges via the official REST endpoints.
3. **Username Enumerator**: Integrates Maigret to check account presence across online platforms.
4. **Lead Extractor**: Uses BeautifulSoup DOM parsing to extract personal contact references from profile descriptions while excluding website boilerplate and analytics noise.
5. **Data Layer**: Enforces type safety and structure across all modules using Pydantic models.
