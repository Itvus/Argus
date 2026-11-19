"""Unit tests for Pydantic models and investigation reports."""

import json
from argus.models import (
    InvestigationReport,
    ModuleStatus,
    PivotLeads,
    SnowflakeMetadata,
    SocialProfile,
)


def test_investigation_report_serialization():
    report = InvestigationReport(
        target="155149108183695360",
        target_type="snowflake",
        scan_timestamp_utc="2026-11-19T17:00:00Z",
        scan_duration_seconds=1.25,
        snowflake=SnowflakeMetadata(
            snowflake_id=155149108183695360,
            timestamp_ms=1457060829922,
            created_at_utc="2016-03-04T03:07:09.922000+00:00",
            age_human="10 years, 260 days",
            worker_id=1,
            process_id=0,
            increment=0,
        ),
        social_profiles=[
            SocialProfile(platform="GitHub", url="https://github.com/test", status="Claimed")
        ],
        pivot_leads=PivotLeads(
            discovered_emails=["test@example.org"],
            notes=["Test lead found"],
        ),
        module_statuses=[
            ModuleStatus(module_name="TestModule", status="success", message="Completed OK")
        ],
    )

    json_str = report.model_dump_json(indent=2)
    data = json.loads(json_str)

    assert data["target"] == "155149108183695360"
    assert data["snowflake"]["worker_id"] == 1
    assert data["social_profiles"][0]["platform"] == "GitHub"
    assert "test@example.org" in data["pivot_leads"]["discovered_emails"]

    # Reconstitute
    reloaded = InvestigationReport.model_validate(data)
    assert reloaded.snowflake.snowflake_id == 155149108183695360
