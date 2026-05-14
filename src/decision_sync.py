from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol
from urllib.parse import urlparse

try:
    import structlog
except ModuleNotFoundError:  # pragma: no cover - dependency fallback
    class _JsonRenderer:
        def __call__(self, _logger: object, event: str, event_dict: dict[str, Any]) -> str:
            return json.dumps({"event": event} | event_dict, sort_keys=True)

    class _Processors:
        @staticmethod
        def JSONRenderer(*_: Any, **__: Any) -> _JsonRenderer:
            return _JsonRenderer()

    class _StructlogFallback:
        processors = _Processors()

    structlog = _StructlogFallback()  # type: ignore[assignment]

import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DARK_FACTORIES_ROOT = PROJECT_ROOT.parent
if str(DARK_FACTORIES_ROOT) not in sys.path:
    sys.path.insert(0, str(DARK_FACTORIES_ROOT))

from _df_common.pii_scrubber import PIIScrubber, scrub_audit_payload
from _df_common.welle_b2_patches import (
    K13PreActionVerifier,
    K16MutexGuard,
    MOCK_PREFIX,
    make_mock_url,
    make_provenance_envelope,
)
from _df_common.canonical_event_hash import compute_canonical_hash
from _df_common.secret_vault import SecretVault, VaultError

UTC = timezone.utc
DECISION_TYPES = {"approve", "reject", "modify"}
PII_SCRUB_KEYS = {"reason", "error", "details", "notes", "objective"}


class ConfigurationError(RuntimeError):
    pass


class ConcurrentRunError(RuntimeError):
    pass


class ChromeMCPUnavailable(RuntimeError):
    pass


class SalesforceUnavailable(RuntimeError):
    def __init__(self, message: str, *, unreachable_for_s: float = 0.0):
        super().__init__(message)
        self.unreachable_for_s = unreachable_for_s


class LocalStorageReader(Protocol):
    def read_decisions(self) -> list[dict[str, Any]]:
        ...


class SalesforceClient(Protocol):
    def sync_decision_item(self, payload: dict[str, Any]) -> dict[str, Any]:
        ...


@dataclass(frozen=True)
class Decision:
    decision_id: str
    asset_id: str
    hotel_id: str
    persona_id: str
    decision_type: str
    reason: str
    imke_timestamp: str
    browser_session_id: str
    source: str = "chrome-localstorage"

    @classmethod
    def from_raw(cls, raw: Mapping[str, Any]) -> "Decision":
        required = {
            "decision_id",
            "asset_id",
            "hotel_id",
            "persona_id",
            "decision_type",
            "reason",
            "imke_timestamp",
            "browser_session_id",
        }
        missing = sorted(k for k in required if not raw.get(k))
        if missing:
            raise ValueError(f"decision schema missing fields: {', '.join(missing)}")
        decision_type = str(raw["decision_type"])
        if decision_type not in DECISION_TYPES:
            raise ValueError(f"invalid decision_type: {decision_type}")
        return cls(**{k: str(raw[k]) for k in required})


@dataclass
class CircuitBreaker:
    timeout_s: int = 30
    open_threshold: int = 3
    failures: int = 0
    is_open: bool = False

    def record_success(self) -> None:
        self.failures = 0
        self.is_open = False

    def record_failure(self) -> None:
        self.failures += 1
        if self.failures >= self.open_threshold:
            self.is_open = True


@dataclass
class DecisionSyncConfig:
    project_root: Path
    mock_localstorage_path: Path
    queue_dir: Path
    dlq_dir: Path
    report_path: Path
    stats_path: Path
    state_path: Path
    audit_log_path: Path
    lock_dir: Path
    real_chrome_enabled: bool = False
    real_salesforce_enabled: bool = False
    sf_env: str | None = None
    phronesis_ticket: str | None = None
    salesforce_custom_object: str = "Marketing-Decision-Item"
    modes: tuple[str, ...] = ("full", "degraded_chrome_mcp", "degraded_salesforce_api", "standalone_local_queue")
    timeout_s: int = 30
    open_threshold: int = 3
    health_check_dependencies: tuple[str, ...] = ()

    @classmethod
    def from_file(
        cls,
        config_path: Path | str,
        *,
        env: Mapping[str, str] | None = None,
        project_root: Path | None = None,
    ) -> "DecisionSyncConfig":
        config_path = Path(config_path).resolve()
        root = project_root or config_path.parent
        with config_path.open("r", encoding="utf-8") as handle:
            raw = yaml.safe_load(handle)
        env_map = dict(os.environ if env is None else env)
        execution = raw["execution"]
        constraints = raw["constraints"]
        lc = raw["lose_coupling"]
        cfg = cls(
            project_root=root,
            mock_localstorage_path=Path(execution["phase_1_mock_localstorage_path"]),
            queue_dir=(root / execution["queue_dir"]).resolve(),
            dlq_dir=(root / execution["dlq_dir"]).resolve(),
            report_path=(root / execution["output_report_markdown"]).resolve(),
            stats_path=(root / execution["output_stats_json"]).resolve(),
            state_path=(root / execution["state_json"]).resolve(),
            audit_log_path=(root / execution["audit_log"]).resolve(),
            lock_dir=Path(constraints["k16"]["lock_dir"]),
            real_chrome_enabled=env_map.get("DF_HLM_5_REAL_CHROME_MCP_ENABLED", "").lower() == "true",
            real_salesforce_enabled=env_map.get("DF_HLM_5_REAL_SALESFORCE_ENABLED", "").lower() == "true",
            sf_env=env_map.get("SF_ENV"),
            phronesis_ticket=env_map.get("PHRONESIS_TICKET"),
            salesforce_custom_object=execution["salesforce_custom_object"],
            modes=tuple(lc["lc1"]["modes"]),
            timeout_s=int(lc["lc3"]["timeout_s"]),
            open_threshold=int(lc["lc3"]["open_threshold"]),
            health_check_dependencies=tuple(lc["lc5"]["health_check_dependencies"]),
        )
        cfg.ensure_dirs()
        cfg.validate_pre_action()
        return cfg

    def ensure_dirs(self) -> None:
        for path in (self.queue_dir, self.dlq_dir, self.report_path.parent, self.stats_path.parent):
            path.mkdir(parents=True, exist_ok=True)

    def validate_pre_action(self) -> None:
        if not self.real_salesforce_enabled:
            return
        if self.sf_env not in {"sandbox", "production"}:
            raise ConfigurationError("SF_ENV must be sandbox or production for live Salesforce sync.")
        if not self.phronesis_ticket or not self.phronesis_ticket.startswith("PT-2026-"):
            raise ConfigurationError("PHRONESIS_TICKET=PT-2026-XX-XXX is required for live Salesforce sync.")


class JsonAuditLogger:
    def __init__(self, path: Path, *, pii_scrubber: PIIScrubber):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.pii_scrubber = pii_scrubber

    def info(self, event: str, **fields: Any) -> None:
        payload = scrub_audit_payload({"event": event, "ts": utc_now().isoformat(), **fields})
        rendered = json.dumps(payload, sort_keys=True, default=str)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(rendered + "\n")


class MockLocalStorageReader:
    def __init__(self, path: Path):
        self.path = path

    def read_decisions(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        raw = json.loads(self.path.read_text(encoding="utf-8"))
        if isinstance(raw, dict):
            raw = raw.get("decisions", [])
        if not isinstance(raw, list):
            raise ValueError("mock localStorage payload must be a list or {'decisions': list}")
        return raw


class ChromeMCPLocalStorageReader:
    def __init__(self, javascript_tool: Callable[[str], str] | None = None):
        self.javascript_tool = javascript_tool

    def read_decisions(self) -> list[dict[str, Any]]:
        if self.javascript_tool is None:
            raise ChromeMCPUnavailable("Chrome-MCP javascript_tool unavailable")
        value = self.javascript_tool('window.localStorage.getItem("imke-decisions")')
        if not value:
            return []
        parsed = json.loads(value)
        return parsed if isinstance(parsed, list) else parsed.get("decisions", [])


class MockSalesforceClient:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def sync_decision_item(self, payload: dict[str, Any]) -> dict[str, Any]:
        self.calls.append(payload)
        return {
            "mode": "mock",
            "anchor_id": payload["idempotency_key"],
            "custom_object": payload["custom_object"],
            "sf_env": "mock",
        }


class RealSalesforceClient:
    def __init__(self, config: DecisionSyncConfig, *, session: Any | None = None):
        import requests

        self.config = config
        self.session = session or requests.Session()
        self.base_url = os.environ.get("SF_API_BASE_URL", "https://example.invalid")
        self.token = self._load_token()

    def _load_token(self) -> str:
        if os.environ.get("DF_HLM_5_SF_OAUTH_TOKEN"):
            return os.environ["DF_HLM_5_SF_OAUTH_TOKEN"]
        vault_path = Path(os.environ.get("DF_HLM_5_SECRET_VAULT_PATH", self.config.project_root / "vault.bin"))
        key_path = Path(os.environ.get("DF_HLM_5_SECRET_VAULT_MASTER_KEY_PATH", self.config.project_root / "vault.key"))
        try:
            return SecretVault(vault_path=vault_path, master_key_path=key_path).get_secret("salesforce_oauth_access_token")
        except (VaultError, FileNotFoundError) as exc:
            raise ConfigurationError(f"Salesforce OAuth token unavailable via SecretVault: {exc}") from exc

    def sync_decision_item(self, payload: dict[str, Any]) -> dict[str, Any]:
        url = f"{self.base_url.rstrip('/')}/services/data/v1/custom-objects/{self.config.salesforce_custom_object}"
        headers = {"Authorization": f"Bearer {self.token}", "Content-Type": "application/json"}
        response = self.session.post(url, headers=headers, json=payload, timeout=self.config.timeout_s)
        response.raise_for_status()
        body = response.json() if getattr(response, "content", b"") else {}
        return {
            "mode": "full",
            "anchor_id": body.get("id", payload["idempotency_key"]),
            "custom_object": self.config.salesforce_custom_object,
            "sf_env": self.config.sf_env,
        }


class DecisionSyncEngine:
    def __init__(
        self,
        config: DecisionSyncConfig,
        *,
        localstorage_reader: LocalStorageReader | None = None,
        salesforce_client: SalesforceClient | None = None,
        now_provider: Callable[[], datetime] = lambda: datetime.now(UTC),
    ):
        self.config = config
        self.now_provider = now_provider
        self.pii_scrubber = PIIScrubber(enabled=True, kemmer_names_enabled=True)
        self.audit = JsonAuditLogger(config.audit_log_path, pii_scrubber=self.pii_scrubber)
        self.localstorage_reader = localstorage_reader or (
            ChromeMCPLocalStorageReader() if config.real_chrome_enabled else MockLocalStorageReader(config.mock_localstorage_path)
        )
        self.salesforce_client = salesforce_client or (
            RealSalesforceClient(config) if config.real_salesforce_enabled else MockSalesforceClient()
        )
        self.salesforce_breaker = CircuitBreaker(config.timeout_s, config.open_threshold)
        self.lock: K16MutexGuard | None = None

    def health_check(self) -> dict[str, Any]:
        return {"healthy": True, "dependencies": list(self.config.health_check_dependencies)}

    @staticmethod
    def idempotency_key(decision: Decision) -> str:
        return compute_canonical_hash(
            event_id=decision.decision_id,
            event_type="df-hlm-5-decision-sync",
            payload={
                "decision_id": decision.decision_id,
                "browser_session_id": decision.browser_session_id,
                "imke_timestamp": decision.imke_timestamp,
            },
            tenant_id=decision.hotel_id,
        )

    def acquire_mutex(self) -> None:
        guard = K16MutexGuard(lock_dir=self.config.lock_dir, df_engine_marker="decision_sync.py")
        result = guard.acquire()
        if not result.acquired:
            raise ConcurrentRunError(f"K16-VETO: {result.reason}")
        self.lock = guard

    def release_mutex(self) -> None:
        if self.lock is not None:
            self.lock.release()
            self.lock = None

    def run(self, *, enforce_mutex: bool = True) -> dict[str, Any]:
        if not enforce_mutex:
            return self._run_unlocked()
        with K16MutexGuard(lock_dir=self.config.lock_dir, df_engine_marker="decision_sync.py"):
            return self._run_unlocked()

    def _run_unlocked(self) -> dict[str, Any]:
        started = self.now_provider()
        self.audit.info("run_started", mode=self.resolve_mode())
        raw_decisions = self._read_with_fallback()
        results: list[dict[str, Any]] = []
        for raw in raw_decisions:
            decision_id = str(raw.get("decision_id", "unknown"))
            try:
                decision = Decision.from_raw(raw)
                if self._already_synced(decision):
                    results.append(self._duplicate_result(decision))
                    continue
                payload = self._build_payload(decision)
                sync_result = self._sync_or_queue(decision, payload)
                result = {"decision": asdict(decision), "sync": sync_result, "status": sync_result["status"]}
                self._persist_state(decision, result)
                results.append(result)
            except Exception as exc:
                if isinstance(exc, RuntimeError) and str(exc).startswith("K13-VETO"):
                    raise
                self._write_dlq(decision_id, raw, exc)
                results.append({"decision_id": decision_id, "status": "failed", "error": str(exc)})
        summary = self._write_outputs(started, results)
        self.audit.info(
            "mock_run_complete" if self._is_mock_mode() else "run_complete",
            synced=summary["stats"]["synced"],
            queued=summary["stats"]["queued"],
            failed=summary["stats"]["failed"],
        )
        return summary

    def resolve_mode(self) -> str:
        if self.salesforce_breaker.is_open:
            return "standalone_local_queue"
        if self.config.real_chrome_enabled and self.config.real_salesforce_enabled:
            return "full"
        if self.config.real_chrome_enabled:
            return "degraded_salesforce_api"
        if self.config.real_salesforce_enabled:
            return "degraded_chrome_mcp"
        return "standalone_local_queue"

    def _read_with_fallback(self) -> list[dict[str, Any]]:
        try:
            return self.localstorage_reader.read_decisions()
        except ChromeMCPUnavailable:
            self.audit.info("chrome_mcp_degraded", fallback="mock_localstorage")
            return MockLocalStorageReader(self.config.mock_localstorage_path).read_decisions()

    def _build_payload(self, decision: Decision) -> dict[str, Any]:
        key = self.idempotency_key(decision)
        return {
            "custom_object": self.config.salesforce_custom_object,
            "idempotency_key": key,
            "decision_hash": key,
            "decision_id": decision.decision_id,
            "asset_id": decision.asset_id,
            "hotel_id": decision.hotel_id,
            "persona_id": decision.persona_id,
            "decision_type": decision.decision_type,
            "reason": decision.reason,
            "imke_timestamp": decision.imke_timestamp,
            "browser_session_id": decision.browser_session_id,
            "sf_env": self.config.sf_env if self.config.real_salesforce_enabled else "mock",
            "phronesis_ticket": self.config.phronesis_ticket,
            "provenance": {
                "decision_hash": key,
                "imke_timestamp": decision.imke_timestamp,
                "browser_session_id": decision.browser_session_id,
                "anchors": ["browser_localstorage", "salesforce_api"],
            },
        }

    def _verify_real_dispatch(self) -> None:
        if not self.config.real_salesforce_enabled:
            return
        verifier = K13PreActionVerifier(
            expected_env_tag="dev",
            expected_mount_pattern="/Users/make",
            blast_radius_class="state-only",
        )
        result = verifier.verify()
        if not result.ok:
            raise RuntimeError(f"K13-VETO: {result.failed_check}")

    def _is_mock_mode(self) -> bool:
        return self.resolve_mode() != "full"

    def _sync_or_queue(self, decision: Decision, payload: dict[str, Any]) -> dict[str, Any]:
        if self.salesforce_breaker.is_open:
            self._queue_decision(decision, payload, "circuit_open")
            return {"status": "queued", "mode": "standalone_local_queue", "anchor_id": payload["idempotency_key"]}
        try:
            self._verify_real_dispatch()
            result = self.salesforce_client.sync_decision_item(payload)
            self.salesforce_breaker.record_success()
            return {"status": "synced", **result}
        except SalesforceUnavailable as exc:
            self.salesforce_breaker.record_failure()
            if exc.unreachable_for_s > self.config.timeout_s or self.salesforce_breaker.is_open:
                self._queue_decision(decision, payload, str(exc))
                return {"status": "queued", "mode": "standalone_local_queue", "anchor_id": payload["idempotency_key"]}
            raise

    def _already_synced(self, decision: Decision) -> bool:
        state = self._load_state()
        return self.idempotency_key(decision) in state.get("synced_hashes", [])

    def _duplicate_result(self, decision: Decision) -> dict[str, Any]:
        return {"decision": asdict(decision), "sync": {"status": "duplicate", "anchor_id": self.idempotency_key(decision)}, "status": "duplicate"}

    def _persist_state(self, decision: Decision, result: dict[str, Any]) -> None:
        if result["status"] != "synced":
            return
        state = self._load_state()
        hashes = set(state.get("synced_hashes", []))
        hashes.add(self.idempotency_key(decision))
        state["synced_hashes"] = sorted(hashes)
        self._write_json_output(self.config.state_path, state)

    def _queue_decision(self, decision: Decision, payload: dict[str, Any], reason: str) -> None:
        self._write_json_output(self.config.queue_dir / f"{self.idempotency_key(decision)}.json", {"reason": reason, "payload": payload})

    def _write_dlq(self, decision_id: str, raw: Mapping[str, Any], exc: Exception) -> None:
        self._write_json_output(self.config.dlq_dir / f"{decision_id}.json", {"decision_id": decision_id, "error": str(exc), "raw": dict(raw)})

    def _load_state(self) -> dict[str, Any]:
        if not self.config.state_path.exists():
            return {"synced_hashes": []}
        return json.loads(self.config.state_path.read_text(encoding="utf-8"))

    def _write_outputs(self, started: datetime, results: list[dict[str, Any]]) -> dict[str, Any]:
        completed = self.now_provider()
        stats = aggregate_stats(results)
        provenance = make_provenance_envelope(
            df_id="DF-HLM-5",
            timestamp_iso=completed.isoformat(),
            is_mock=self._is_mock_mode(),
            activation_gate_id=None if self._is_mock_mode() else self.config.phronesis_ticket,
        )
        if self._is_mock_mode():
            provenance["reference_url"] = make_mock_url("https://df.local/decision-sync", completed.strftime("%Y%m%dT%H%M%SZ"))
            provenance["reference_prefix"] = MOCK_PREFIX
        payload = {
            "run_started": started.isoformat(),
            "run_completed": completed.isoformat(),
            "mode": "mock" if self._is_mock_mode() else "real-api",
            "provenance": provenance,
            "stats": stats,
            "results": results,
        }
        self._write_json_output(self.config.stats_path, payload)
        self._write_text_output(self.config.report_path, render_report(payload))
        return payload

    def _write_json_output(self, path: Path, payload: Mapping[str, Any]) -> None:
        scrubbed_payload = scrub_output_payload(self.pii_scrubber, dict(payload))
        atomic_write_json(path, scrubbed_payload)

    def _write_text_output(self, path: Path, content: str) -> None:
        atomic_write_text(path, self.pii_scrubber.scrub(content))


def aggregate_stats(results: list[dict[str, Any]]) -> dict[str, Any]:
    by_type = {kind: 0 for kind in sorted(DECISION_TYPES)}
    counts = {"total": len(results), "synced": 0, "queued": 0, "duplicate": 0, "failed": 0, "by_decision_type": by_type}
    for result in results:
        status = result.get("status", "failed")
        counts[status] = counts.get(status, 0) + 1
        decision = result.get("decision") or {}
        if decision.get("decision_type") in by_type:
            by_type[decision["decision_type"]] += 1
    return counts


def render_report(payload: Mapping[str, Any]) -> str:
    stats = payload["stats"]
    output_provenance = payload.get("provenance") or {}
    lines = [
        "# DF-HLM-5 Daily Decision Sync Report",
        "",
        f"- Run started: {payload['run_started']}",
        f"- Run completed: {payload['run_completed']}",
        f"- Output mode: {payload.get('mode', 'unknown')}",
        f"- Total decisions: {stats['total']}",
        f"- Synced: {stats['synced']}",
        f"- Queued: {stats['queued']}",
        f"- Failed: {stats['failed']}",
        "",
        "## Output Provenance",
        f"- DF ID: {output_provenance.get('df_id', 'DF-HLM-5')}",
        f"- Mode: {output_provenance.get('mode', payload.get('mode', 'unknown'))}",
        f"- Timestamp: {output_provenance.get('timestamp_iso', payload['run_completed'])}",
        "",
        "## Provenance",
    ]
    if output_provenance.get("reference_url"):
        lines.append(f"- Mock reference: {output_provenance['reference_url']}")
    for result in payload["results"]:
        decision = result.get("decision") or {}
        sync = result.get("sync") or {}
        if decision:
            lines.append(
                f"- {decision['decision_id']}: hash={sync.get('anchor_id')} "
                f"imke_timestamp={decision['imke_timestamp']} "
                f"browser_session_id={decision['browser_session_id']} status={result['status']}"
            )
    return "\n".join(lines) + "\n"


def scrub_output_payload(scrubber: PIIScrubber, payload: Mapping[str, Any]) -> dict[str, Any]:
    scrubbed: dict[str, Any] = {}
    for key, value in payload.items():
        scrubbed[key] = scrub_output_value(scrubber, key, value)
    return scrubbed


def scrub_output_value(scrubber: PIIScrubber, key: str, value: Any) -> Any:
    if isinstance(value, dict):
        return scrub_output_payload(scrubber, value)
    if isinstance(value, list):
        return [scrub_output_value(scrubber, key, item) for item in value]
    if isinstance(value, str) and key in PII_SCRUB_KEYS:
        return scrubber.scrub(value)
    return value


def utc_now() -> datetime:
    return datetime.now(UTC)


def atomic_write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
        os.replace(temp_name, path)
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)


def atomic_write_json(path: Path, payload: Any) -> None:
    atomic_write_text(path, json.dumps(payload, indent=2, sort_keys=True, default=str))


def validate_salesforce_base_url(raw_url: str) -> bool:
    parsed = urlparse(raw_url)
    return parsed.scheme == "https" and bool(parsed.netloc)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default=str(PROJECT_ROOT / "config.yaml"))
    parser.add_argument("--no-mutex", action="store_true")
    args = parser.parse_args(argv)
    cfg = DecisionSyncConfig.from_file(args.config)
    if cfg.real_salesforce_enabled and not validate_salesforce_base_url(os.environ.get("SF_API_BASE_URL", "https://example.invalid")):
        raise ConfigurationError("SF_API_BASE_URL must be https for live Salesforce sync.")
    summary = DecisionSyncEngine(cfg).run(enforce_mutex=not args.no_mutex)
    print(json.dumps({"stats": summary["stats"], "report": str(cfg.report_path), "stats_path": str(cfg.stats_path)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
