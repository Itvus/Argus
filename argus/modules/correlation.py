"""Correlation and confidence scoring engine for Argus investigations.

Mathematically synthesizes evidence across Discord Snowflakes, cross-platform profiles,
avatar perceptual hashes, bio references, infostealer breaches, and registered accounts
to produce an objective 0-100% confidence rating for the target identity.
"""

from __future__ import annotations

from typing import Optional

from argus.models import CorrelationScore, InvestigationReport


def calculate_correlation_score(report: InvestigationReport) -> CorrelationScore:
    """Evaluate investigative evidence and return an algorithmic confidence score (0-100)."""
    score = 0
    reasons: list[str] = []

    # 1. Avatar Perceptual Hash Match (Highest confidence visual proof)
    if report.avatar_matches:
        best_match = min(report.avatar_matches, key=lambda m: m.hamming_distance)
        score += 35
        reasons.append(
            f"Visual proof: Avatar on {best_match.platform_a} matches {best_match.platform_b} "
            f"(Hamming distance: {best_match.hamming_distance}/64 bits)"
        )

    # 2. Explicit Bio Cross-References (Snowflake ID or handles in text)
    if report.pivot_leads.discovered_discord_ids:
        score += 30
        reasons.append(f"Direct link: Profile bio explicitly references Discord Snowflake ID {report.pivot_leads.discovered_discord_ids[0]}")
    elif report.pivot_leads.discovered_discord_tags:
        score += 20
        reasons.append(f"Direct link: Profile bio references Discord Tag '{report.pivot_leads.discovered_discord_tags[0]}'")

    # 3. CordCat Community Correlation
    if report.cordcat and report.cordcat.historical_usernames:
        score += 20
        reasons.append(f"Historical telemetry: CordCat verified {len(report.cordcat.historical_usernames)} previous alias(es)")

    # 4. GitHub Commit Author Verification
    if report.github_pivot and report.github_pivot.commit_emails:
        score += 15
        reasons.append(f"Source control telemetry: Public Git commit logs verified author email(s)")

    # 5. Infostealer Compromise Correlation
    if report.hudson_rock:
        total_infections = sum(h.total_stealers for h in report.hudson_rock)
        if total_infections > 0:
            score += 15
            reasons.append(f"Threat telemetry: Hudson Rock verified {total_infections} infostealer malware compromise(s)")

    # 6. Verified Email Registrations (Holehe)
    if report.email_registrations:
        total_regs = sum(len(r.accounts) for r in report.email_registrations)
        if total_regs >= 3:
            score += 15
            reasons.append(f"Account validation: Holehe confirmed registration across {total_regs} web platforms")
        elif total_regs > 0:
            score += 10
            reasons.append(f"Account validation: Holehe confirmed registration across {total_regs} web platform(s)")

    # 7. Multi-Platform Presence (Breadth of footprint)
    matched_profiles = len(report.social_profiles)
    if matched_profiles >= 6:
        score += 15
        reasons.append(f"Footprint breadth: Matched {matched_profiles} social/developer platform profiles")
    elif matched_profiles >= 2:
        score += 10
        reasons.append(f"Footprint breadth: Matched {matched_profiles} social/developer platform profiles")

    # 8. Gaming Ecosystem Corroboration
    if report.gaming and (report.gaming.minecraft or report.gaming.steam):
        platforms = []
        if report.gaming.minecraft:
            platforms.append("Minecraft")
        if report.gaming.steam:
            platforms.append("Steam")
        score += 10
        reasons.append(f"Gaming ecosystem: Exact handle resolved on {' & '.join(platforms)}")

    # Baseline presence
    if not reasons:
        score = 15
        reasons.append("Preliminary finding: Single isolated identifier without cross-platform correlation")
    else:
        # Cap at 100
        score = min(100, score)

    # Determine confidence level
    if score >= 75:
        level = "HIGH"
    elif score >= 40:
        level = "MEDIUM"
    else:
        level = "LOW"

    return CorrelationScore(
        confidence_score=score,
        confidence_level=level,
        reasons=reasons,
    )
