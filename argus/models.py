"""Pydantic data models for argus investigations."""

from __future__ import annotations

from typing import Any, Optional
from pydantic import BaseModel, Field


class SnowflakeMetadata(BaseModel):
    """Decoded Discord Snowflake metadata."""
    snowflake_id: int
    timestamp_ms: int
    created_at_utc: str
    age_human: str
    worker_id: int
    process_id: int
    increment: int


class ReverseImageUrls(BaseModel):
    """Direct reverse-image-search URLs for an avatar."""
    google_lens: str
    yandex: str
    tineye: str
    bing_visual: str


class DiscordProfile(BaseModel):
    """Discord Public API profile information."""
    id: str
    username: str
    global_name: Optional[str] = None
    discriminator: str = "0"
    avatar_hash: Optional[str] = None
    avatar_url: Optional[str] = None
    banner_hash: Optional[str] = None
    banner_url: Optional[str] = None
    accent_color: Optional[int] = None
    banner_color: Optional[str] = None
    public_flags: int = 0
    badges: list[str] = Field(default_factory=list)
    bot: bool = False
    system: bool = False
    reverse_image_urls: Optional[ReverseImageUrls] = None


class SocialProfile(BaseModel):
    """Discovered cross-platform social profile."""
    platform: str
    url: str
    status: str = "Claimed"
    tags: list[str] = Field(default_factory=list)
    extracted_data: dict[str, Any] = Field(default_factory=dict)


class CordCatRecord(BaseModel):
    """Historical records from CordCat indexer."""
    user_id: str
    historical_usernames: list[str] = Field(default_factory=list)
    fivem_identifiers: list[str] = Field(default_factory=list)
    records: list[dict[str, Any]] = Field(default_factory=list)
    status: str = "success"


class BreachRecord(BaseModel):
    """Exposed account / breach incident notification record."""
    query: str
    service_name: str
    breach_date: Optional[str] = None
    pwn_count: Optional[int] = None
    data_classes: list[str] = Field(default_factory=list)
    description: Optional[str] = None


class GitHubPivotLead(BaseModel):
    """GitHub profile and public commit audit results."""
    username: str
    profile_url: str
    name: Optional[str] = None
    company: Optional[str] = None
    blog: Optional[str] = None
    location: Optional[str] = None
    bio: Optional[str] = None
    created_at: Optional[str] = None
    account_age_days: Optional[int] = None
    commit_emails: list[str] = Field(default_factory=list)
    age_comparison_discord: Optional[str] = None


class CryptoLead(BaseModel):
    """Discovered cryptocurrency wallet address."""
    network: str  # "Bitcoin", "Ethereum", "Solana"
    address: str


class MessagingLead(BaseModel):
    """Discovered messaging handle or link."""
    platform: str  # "Telegram", "Matrix", "Signal"
    handle: str
    url: Optional[str] = None


class MinecraftProfile(BaseModel):
    """Minecraft account metadata resolved via Mojang API."""
    username: str
    uuid: str
    uuid_formatted: str
    skin_render_url: Optional[str] = None


class SteamProfile(BaseModel):
    """Steam account metadata resolved via Community XML."""
    steam_id_64: str
    custom_url: str
    profile_url: str
    real_name: Optional[str] = None
    location: Optional[str] = None
    avatar_url: Optional[str] = None
    member_since: Optional[str] = None
    vac_banned: bool = False
    trade_ban_state: Optional[str] = None
    online_state: Optional[str] = None


class GamingProfiles(BaseModel):
    """Aggregated gaming ecosystem profiles (Minecraft, Steam)."""
    minecraft: Optional[MinecraftProfile] = None
    steam: Optional[SteamProfile] = None


class EmailAccountResult(BaseModel):
    """Discovered registered service for an email address via Holehe."""
    platform: str
    domain: str
    rate_limit: bool = False
    email_recovery: Optional[str] = None
    phone_number: Optional[str] = None
    other_info: Optional[str] = None


class EmailRegistrationReport(BaseModel):
    """Email registration check results across platforms (Holehe)."""
    email: str
    total_checked: int = 0
    accounts: list[EmailAccountResult] = Field(default_factory=list)


class StealerInfection(BaseModel):
    """Infostealer malware infection details resolved via Hudson Rock."""
    stealer_family: Optional[str] = None
    date_compromised: Optional[str] = None
    computer_name: Optional[str] = None
    operating_system: Optional[str] = None
    ip: Optional[str] = None
    malware_path: Optional[str] = None
    top_logins: list[str] = Field(default_factory=list)


class HudsonRockReport(BaseModel):
    """Hudson Rock infostealer cybercrime intelligence report."""
    query: str
    query_type: str  # "username" or "email"
    total_stealers: int = 0
    total_corporate_services: int = 0
    total_user_services: int = 0
    infections: list[StealerInfection] = Field(default_factory=list)


class AvatarHash(BaseModel):
    """Perceptual difference hash (dHash) for an avatar."""
    platform: str
    url: str
    dhash: str
    dhash_int: int


class AvatarMatch(BaseModel):
    """Confirmed cross-platform avatar perceptual match based on Hamming distance."""
    platform_a: str
    url_a: str
    platform_b: str
    url_b: str
    hamming_distance: int  # 0 to 64; <= 5 indicates same image
    is_match: bool = True


class CorrelationScore(BaseModel):
    """Algorithmic confidence assessment for discovered pivot identity."""
    confidence_score: int  # 0 - 100
    confidence_level: str  # "HIGH", "MEDIUM", "LOW"
    reasons: list[str] = Field(default_factory=list)


class GoogleDork(BaseModel):
    """Pre-computed Google Dork query and clickable search URL."""
    category: str
    query: str
    url: str


class IntelXRecord(BaseModel):
    """Intelligence X selector search record."""
    system_id: str
    name: str
    date: Optional[str] = None
    media_type: Optional[str] = None


class IntelXReport(BaseModel):
    """Intelligence X darknet and data leak search results."""
    query: str
    total_results: int = 0
    records: list[IntelXRecord] = Field(default_factory=list)


class PivotLeads(BaseModel):
    """Aggregated investigative leads discovered during pivoting."""
    discovered_emails: list[str] = Field(default_factory=list)
    discovered_discord_ids: list[str] = Field(default_factory=list)
    discovered_discord_tags: list[str] = Field(default_factory=list)
    discovered_invites: list[str] = Field(default_factory=list)
    discovered_crypto: list[CryptoLead] = Field(default_factory=list)
    discovered_messaging: list[MessagingLead] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class ModuleStatus(BaseModel):
    """Execution status and diagnostics for an investigation module."""
    module_name: str
    status: str  # "success", "skipped", "error", "no_hits"
    message: Optional[str] = None


class InvestigationReport(BaseModel):
    """Unified investigation report returned by argus."""
    target: str
    target_type: str  # "snowflake" or "username"
    scan_timestamp_utc: str
    scan_duration_seconds: float = 0.0
    snowflake: Optional[SnowflakeMetadata] = None
    discord_profile: Optional[DiscordProfile] = None
    social_profiles: list[SocialProfile] = Field(default_factory=list)
    cordcat: Optional[CordCatRecord] = None
    breaches: list[BreachRecord] = Field(default_factory=list)
    github_pivot: Optional[GitHubPivotLead] = None
    gaming: Optional[GamingProfiles] = None
    email_registrations: list[EmailRegistrationReport] = Field(default_factory=list)
    hudson_rock: list[HudsonRockReport] = Field(default_factory=list)
    avatar_hashes: list[AvatarHash] = Field(default_factory=list)
    avatar_matches: list[AvatarMatch] = Field(default_factory=list)
    correlation: Optional[CorrelationScore] = None
    dorks: list[GoogleDork] = Field(default_factory=list)
    intelx: Optional[IntelXReport] = None
    pivot_leads: PivotLeads = Field(default_factory=PivotLeads)
    module_statuses: list[ModuleStatus] = Field(default_factory=list)
