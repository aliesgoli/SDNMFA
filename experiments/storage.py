"""Transactional persistence for campaign manifests and task observations."""

from __future__ import annotations

import json
import uuid
from typing import Any, Dict, Set

from experiments.campaign import CampaignManifest, CampaignTask


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)


class CampaignStore:
    def _connection(self):
        from database.db_config import get_db_connection
        conn = get_db_connection()
        if conn is None:
            raise RuntimeError("Database connection is unavailable")
        return conn

    @staticmethod
    def _release(conn) -> None:
        from database.db_config import release_db_connection
        release_db_connection(conn)

    def register(self, manifest: CampaignManifest, study_id: str = None) -> None:
        payload = manifest.to_dict()
        digest = str(payload["manifest_sha256"])
        conn = self._connection()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT manifest_sha256 FROM experiment_campaigns WHERE campaign_id = %s",
                    (manifest.campaign_id,),
                )
                existing = cur.fetchone()
                if existing and str(existing[0]) != digest:
                    raise RuntimeError("Campaign identifier already exists with a different manifest")
                cur.execute(
                    """
                    INSERT INTO experiment_campaigns (
                        campaign_id, study_id, protocol_id, schema_version, seed, scenario,
                        topology_id, binding_profile, repetitions, design,
                        manifest, manifest_sha256, status
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s, 'planned')
                    ON CONFLICT (campaign_id) DO UPDATE SET
                        study_id=COALESCE(experiment_campaigns.study_id, EXCLUDED.study_id)
                    """,
                    (
                        manifest.campaign_id,
                        study_id,
                        manifest.protocol_id,
                        manifest.schema_version,
                        manifest.seed,
                        manifest.scenario,
                        manifest.topology_id,
                        manifest.binding_profile,
                        manifest.repetitions,
                        manifest.design,
                        _json(payload),
                        digest,
                    ),
                )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            self._release(conn)

    def completed_task_ids(self, campaign_id: str) -> Set[str]:
        conn = self._connection()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT task_id
                    FROM experiment_runs
                    WHERE campaign_id = %s AND execution_status = 'completed'
                    """,
                    (campaign_id,),
                )
                return {str(row[0]) for row in cur.fetchall()}
        finally:
            self._release(conn)

    def set_campaign_status(self, campaign_id: str, status: str) -> None:
        if status not in {"planned", "running", "completed", "interrupted", "failed"}:
            raise ValueError("Unsupported campaign status")
        conn = self._connection()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE experiment_campaigns
                    SET status = %s,
                        started_at = CASE WHEN %s = 'running' THEN COALESCE(started_at, CURRENT_TIMESTAMP) ELSE started_at END,
                        completed_at = CASE WHEN %s = 'completed' THEN CURRENT_TIMESTAMP ELSE completed_at END
                    WHERE campaign_id = %s
                    """,
                    (status, status, status, campaign_id),
                )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            self._release(conn)

    def start_task(
        self,
        task: CampaignTask,
        run_id: str,
        operator_attempt_id: str,
        task_auth_attempt_id: str,
        experiment_username: str = None,
    ) -> None:
        uuid.UUID(str(run_id))
        uuid.UUID(str(operator_attempt_id))
        uuid.UUID(str(task_auth_attempt_id))
        conn = self._connection()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO experiment_runs (
                        task_id, campaign_id, sample_id, run_id, operator_attempt_id,
                        task_auth_attempt_id, experiment_username,
                        scenario, intensity_level, repetition, policy_position,
                        mfa_mode, binding_profile, topology_id, sampled_parameters,
                        execution_status, started_at
                    ) VALUES (
                        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s::jsonb, 'running', CURRENT_TIMESTAMP
                    )
                    ON CONFLICT (task_id) DO UPDATE SET
                        run_id = EXCLUDED.run_id,
                        operator_attempt_id = EXCLUDED.operator_attempt_id,
                        task_auth_attempt_id = EXCLUDED.task_auth_attempt_id,
                        experiment_username = EXCLUDED.experiment_username,
                        execution_status = 'running',
                        started_at = CURRENT_TIMESTAMP,
                        completed_at = NULL
                    WHERE experiment_runs.execution_status <> 'completed'
                    """,
                    (
                        task.task_id,
                        task.campaign_id,
                        task.sample_id,
                        run_id,
                        operator_attempt_id,
                        task_auth_attempt_id,
                        experiment_username,
                        task.scenario,
                        task.intensity,
                        task.repetition,
                        task.policy_position,
                        task.policy,
                        task.binding_profile,
                        task.topology_id,
                        _json(task.parameters),
                    ),
                )
                if cur.rowcount != 1:
                    raise RuntimeError(
                        "Experiment task is already completed; use a different seed for a new campaign"
                    )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            self._release(conn)

    def finish_task(
        self,
        task_id: str,
        observed_result: Dict[str, Any],
        resource_metrics: Dict[str, Any],
        pcap_evidence: Dict[str, Any],
    ) -> None:
        metrics = observed_result.get("metrics") if isinstance(observed_result, dict) else {}
        if not isinstance(metrics, dict):
            metrics = {}
        status = str(metrics.get("execution_status") or "technical_error")
        conn = self._connection()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE experiment_runs
                    SET observed_result = %s::jsonb,
                        resource_metrics = %s::jsonb,
                        pcap_evidence = %s::jsonb,
                        execution_status = %s,
                        is_valid = %s,
                        completed_at = CURRENT_TIMESTAMP
                    WHERE task_id = %s
                    """,
                    (
                        _json(observed_result),
                        _json(resource_metrics),
                        _json(pcap_evidence),
                        status,
                        bool(metrics.get("is_valid")),
                        task_id,
                    ),
                )
                if cur.rowcount != 1:
                    raise RuntimeError("Experiment task was not registered")
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            self._release(conn)
