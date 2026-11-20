"""Google Dork URL generator module for Argus.

Pre-computes safe, actionable Google Dork URLs targeting public pastes,
Telegram channels, source code secrets, Discord server invites, and document leaks.
Zero network scraping; generates pre-formatted browser search links.
"""

from __future__ import annotations

import urllib.parse
from argus.models import GoogleDork
from argus.modules.snowflake import is_valid_snowflake


def generate_google_dorks(target: str, emails: list[str] = []) -> list[GoogleDork]:
    """Generate categorized Google Dork query objects with encoded search URLs."""
    clean_target = target.strip()
    if not clean_target:
        return []

    is_snowflake = is_valid_snowflake(clean_target)

    if is_snowflake:
        dork_templates = [
            (
                "Discord Channel & Message Archives",
                f'site:discord.com/channels "{clean_target}"',
            ),
            (
                "Bot Audit & Moderation Logs",
                f'"{clean_target}" (ban | kick | mute | warn | audit | "user id")',
            ),
            (
                "GitHub Code Search (Bots & Configs)",
                f'site:github.com "{clean_target}"',
            ),
            (
                "Discord Transparency & Indexers",
                f'"{clean_target}" (site:discord.id | site:discordlookup.com | site:lookup.guru)',
            ),
            (
                "Public Pastes & Text Dumps",
                f'(site:pastebin.com | site:rentry.co | site:justpaste.it) "{clean_target}"',
            ),
        ]
    else:
        dork_templates = [
            (
                "Pastes & Text Dumps",
                f'(site:pastebin.com | site:rentry.co | site:justpaste.it | site:ghostbin.com) "{clean_target}"',
            ),
            (
                "Telegram Channels & Chats",
                f'site:t.me "{clean_target}"',
            ),
            (
                "Source Code Secrets & Configs",
                f'(site:github.com | site:gitlab.com) "{clean_target}" (password | token | key | secret)',
            ),
            (
                "Discord Server Mentions",
                f'"{clean_target}" (site:discord.com | site:discord.gg)',
            ),
            (
                "Public Documents & PDFs",
                f'"{clean_target}" (filetype:pdf | filetype:docx | filetype:txt | filetype:xlsx)',
            ),
            (
                "Breach & Database Mentions",
                f'"{clean_target}" ("database dump" | "breached" | "combo list" | "leaked")',
            ),
        ]

    # Additional email-specific dorks if emails available
    if emails:
        primary_email = emails[0].strip()
        dork_templates.append(
            (
                "Email Web Presence",
                f'"{primary_email}" -site:{primary_email.split("@")[-1]}',
            )
        )
        dork_templates.append(
            (
                "Email Paste Dumps",
                f'(site:pastebin.com | site:rentry.co) "{primary_email}"',
            )
        )

    dorks: list[GoogleDork] = []
    for category, query in dork_templates:
        encoded_query = urllib.parse.quote(query)
        search_url = f"https://www.google.com/search?q={encoded_query}"
        dorks.append(
            GoogleDork(
                category=category,
                query=query,
                url=search_url,
            )
        )

    return dorks
