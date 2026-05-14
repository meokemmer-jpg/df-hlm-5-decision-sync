from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from decision_sync import (  # noqa: E402
    ChromeMCPUnavailable,
    Decision,
    DecisionSyncConfig,
    DecisionSyncEngine,
    MockSalesforceClient,
    SalesforceUnavailable,
)


def sample_decision(decision_id: str = "dec-1", decision_type: str = "approve") -> dict[str, str]:
    return {
        "decision_id": decision_id,
        "asset_id": "asset-1",
        "hotel_id": "hotel-1",
        "persona_id": "persona-1",
        "decision_type": decision_type,
        "reason": "Imke approved Wave-2 creative",
        "imke_timestamp": "2026-05-14T08:00:00Z",
        "browser_session_id": "browser-session-1",
    }


def write_mock(path: Path, decisions: list[dict[str, str]]) -> None:
    path.write_text(json.dumps({"decisions": decisions}), encoding="utf-8")


def cfg(tmp_path: Path, env: dict[str, str] | None = None) -> DecisionSyncConfig:
    return DecisionSyncConfig.from_file(ROOT / "config.yaml", env=env or {}, project_root=tmp_path)


def test_default_mock_mode_no_chrome_no_sf(tmp_path: Path) -> None:
    mock = tmp_path / "mock.json"
    write_mock(mock, [sample_decision()])
    c = cfg(tmp_path)
    c.mock_localstorage_path = mock
    result = DecisionSyncEngine(c).run(enforce_mutex=False)
    assert result["stats"]["synced"] == 1
    assert result["results"][0]["sync"]["mode"] == "mock"


def test_env_var_true_real_mode_both_enabled(tmp_path: Path) -> None:
    c = cfg(tmp_path, {"DF_HLM_5_REAL_CHROME_MCP_ENABLED": "true", "DF_HLM_5_REAL_SALESFORCE_ENABLED": "true", "SF_ENV": "sandbox", "PHRONESIS_TICKET": "PT-2026-05-001"})
    engine = DecisionSyncEngine(c, localstorage_reader=StaticReader([sample_decision()]), salesforce_client=MockSalesforceClient())
    assert engine.resolve_mode() == "full"


def test_concurrent_spawn_protection(tmp_path: Path) -> None:
    c = cfg(tmp_path)
    c.lock_dir = tmp_path / "lock"
    first = DecisionSyncEngine(c)
    second = DecisionSyncEngine(c)
    first.acquire_mutex()
    try:
        with pytest.raises(Exception):
            second.acquire_mutex()
    finally:
        first.release_mutex()


def test_cascade_containment(tmp_path: Path) -> None:
    c = cfg(tmp_path)
    result = DecisionSyncEngine(c, localstorage_reader=StaticReader([sample_decision(), {"decision_id": "bad"}])).run(enforce_mutex=False)
    assert result["stats"]["synced"] == 1
    assert result["stats"]["failed"] == 1
    assert (c.dlq_dir / "bad.json").exists()


def test_external_anchor_two_sources(tmp_path: Path) -> None:
    c = cfg(tmp_path)
    result = DecisionSyncEngine(c, localstorage_reader=StaticReader([sample_decision()]), salesforce_client=MockSalesforceClient()).run(enforce_mutex=False)
    provenance = result["results"][0]["decision"]
    stats = json.loads(c.stats_path.read_text(encoding="utf-8"))
    assert provenance["browser_session_id"] == "browser-session-1"
    assert stats["results"][0]["sync"]["custom_object"] == "Marketing-Decision-Item"


def test_circuit_breaker_open(tmp_path: Path) -> None:
    c = cfg(tmp_path)
    engine = DecisionSyncEngine(c, salesforce_client=FailingSF())
    decision = Decision.from_raw(sample_decision())
    payload = engine._build_payload(decision)
    for _ in range(c.open_threshold):
        engine._sync_or_queue(decision, payload)
    assert engine.salesforce_breaker.is_open


def test_direct_mode_local_queue(tmp_path: Path) -> None:
    c = cfg(tmp_path)
    result = DecisionSyncEngine(c, localstorage_reader=StaticReader([sample_decision()]), salesforce_client=FailingSF(31.0)).run(enforce_mutex=False)
    assert result["stats"]["queued"] == 1
    assert list(c.queue_dir.glob("*.json"))


def test_idempotent_hash_key(tmp_path: Path) -> None:
    d1 = Decision.from_raw(sample_decision())
    d2 = Decision.from_raw(sample_decision())
    assert DecisionSyncEngine.idempotency_key(d1) == DecisionSyncEngine.idempotency_key(d2)


def test_health_check_no_deps(tmp_path: Path) -> None:
    assert DecisionSyncEngine(cfg(tmp_path)).health_check()["dependencies"] == []


def test_decision_schema_validation() -> None:
    with pytest.raises(ValueError):
        Decision.from_raw({"decision_id": "x"})


def test_duplicate_sync_prevention(tmp_path: Path) -> None:
    c = cfg(tmp_path)
    sf = MockSalesforceClient()
    engine = DecisionSyncEngine(c, localstorage_reader=StaticReader([sample_decision()]), salesforce_client=sf)
    assert engine.run(enforce_mutex=False)["stats"]["synced"] == 1
    assert engine.run(enforce_mutex=False)["stats"]["duplicate"] == 1
    assert len(sf.calls) == 1


def test_decision_types_approve_reject_modify() -> None:
    for kind in ("approve", "reject", "modify"):
        assert Decision.from_raw(sample_decision(decision_type=kind)).decision_type == kind


def test_provenance_browser_session_id(tmp_path: Path) -> None:
    c = cfg(tmp_path)
    engine = DecisionSyncEngine(c)
    payload = engine._build_payload(Decision.from_raw(sample_decision()))
    assert payload["provenance"]["browser_session_id"] == "browser-session-1"


def test_pre_action_domain_check_sf_env(tmp_path: Path) -> None:
    with pytest.raises(Exception):
        cfg(tmp_path, {"DF_HLM_5_REAL_SALESFORCE_ENABLED": "true", "SF_ENV": "prod", "PHRONESIS_TICKET": "PT-2026-05-001"})


def test_audit_log_appended_per_run(tmp_path: Path) -> None:
    c = cfg(tmp_path)
    DecisionSyncEngine(c, localstorage_reader=StaticReader([])).run(enforce_mutex=False)
    DecisionSyncEngine(c, localstorage_reader=StaticReader([])).run(enforce_mutex=False)
    assert c.audit_log_path.read_text(encoding="utf-8").count("run_started") == 2


def test_daily_sync_report_format(tmp_path: Path) -> None:
    c = cfg(tmp_path)
    DecisionSyncEngine(c, localstorage_reader=StaticReader([sample_decision()])).run(enforce_mutex=False)
    report = c.report_path.read_text(encoding="utf-8")
    assert report.startswith("# DF-HLM-5 Daily Decision Sync Report")
    assert "## Provenance" in report


def test_decision_stats_aggregation(tmp_path: Path) -> None:
    c = cfg(tmp_path)
    decisions = [sample_decision("a", "approve"), sample_decision("b", "reject"), sample_decision("c", "modify")]
    result = DecisionSyncEngine(c, localstorage_reader=StaticReader(decisions)).run(enforce_mutex=False)
    assert result["stats"]["by_decision_type"] == {"approve": 1, "modify": 1, "reject": 1}


class StaticReader:
    def __init__(self, decisions: list[dict[str, str]]):
        self.decisions = decisions

    def read_decisions(self) -> list[dict[str, str]]:
        return self.decisions


class FailingReader:
    def read_decisions(self) -> list[dict[str, str]]:
        raise ChromeMCPUnavailable("down")


class FailingSF:
    def __init__(self, unreachable_for_s: float = 31.0):
        self.unreachable_for_s = unreachable_for_s

    def sync_decision_item(self, payload: dict[str, str]) -> dict[str, str]:
        raise SalesforceUnavailable("sf down", unreachable_for_s=self.unreachable_for_s)
