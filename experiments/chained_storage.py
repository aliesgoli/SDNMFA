"""Transactional checkpoints for end-to-end chained observations."""

from __future__ import annotations

import json
from typing import Any, Dict, Set

from experiments.chained_protocol import ChainedTask


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)


class ChainedStore:
    @staticmethod
    def _connection():
        from database.db_config import get_db_connection

        conn = get_db_connection()
        if conn is None:
            raise RuntimeError("Database connection is unavailable")
        return conn

    @staticmethod
    def _release(conn) -> None:
        from database.db_config import release_db_connection

        release_db_connection(conn)

    def completed_ids(self, study_id: str, topology_id: str) -> Set[str]:
        conn = self._connection()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT chain_id
                    FROM chained_experiment_runs
                    WHERE study_id=%s AND topology_id=%s
                      AND execution_status='completed' AND is_valid IS TRUE
                    """,
                    (study_id, topology_id),
                )
                return {str(row[0]) for row in cur.fetchall()}
        finally:
            self._release(conn)

    def save(
        self,
        *,
        study_id: str,
        task: ChainedTask,
        username: str,
        authentication: Dict[str, Any],
        network_stage_status: str,
        network_result: Dict[str, Any],
        resource_metrics: Dict[str, Any],
        pcap_evidence: Dict[str, Any],
        chain_outcome: str,
        execution_status: str,
        is_valid: bool,
    ) -> None:
        conn = self._connection()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO chained_experiment_runs (
                        chain_id, study_id, block_id, base_task_id, run_id,
                        auth_attempt_id, experiment_username,
                        auth_attack_variant, intensity_level, mfa_mode,
                        binding_profile, network_scenario, topology_id,
                        repetition, sampled_parameters, factor_state,
                        authentication_succeeded,
                        expected_authentication_success,
                        authentication_latency_ms, authentication_metrics,
                        network_stage_status, network_result, resource_metrics,
                        pcap_evidence, chain_outcome, execution_status, is_valid,
                        completed_at
                    ) VALUES (
                        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s::jsonb, %s::jsonb, %s, %s,
                        %s, %s::jsonb, %s, %s::jsonb, %s::jsonb, %s::jsonb,
                        %s, %s, %s, CURRENT_TIMESTAMP
                    )
                    ON CONFLICT (chain_id) DO UPDATE SET
                        run_id=EXCLUDED.run_id,
                        auth_attempt_id=EXCLUDED.auth_attempt_id,
                        experiment_username=EXCLUDED.experiment_username,
                        factor_state=EXCLUDED.factor_state,
                        authentication_succeeded=EXCLUDED.authentication_succeeded,
                        expected_authentication_success=EXCLUDED.expected_authentication_success,
                        authentication_latency_ms=EXCLUDED.authentication_latency_ms,
                        authentication_metrics=EXCLUDED.authentication_metrics,
                        network_stage_status=EXCLUDED.network_stage_status,
                        network_result=EXCLUDED.network_result,
                        resource_metrics=EXCLUDED.resource_metrics,
                        pcap_evidence=EXCLUDED.pcap_evidence,
                        chain_outcome=EXCLUDED.chain_outcome,
                        execution_status=EXCLUDED.execution_status,
                        is_valid=EXCLUDED.is_valid,
                        started_at=CURRENT_TIMESTAMP,
                        completed_at=CURRENT_TIMESTAMP
                    WHERE chained_experiment_runs.execution_status <> 'completed'
                       OR chained_experiment_runs.is_valid IS NOT TRUE
                    """,
                    (
                        task.chain_id,
                        study_id,
                        task.block_id,
                        task.base_task_id,
                        authentication["run_id"],
                        authentication["attempt_id"],
                        username,
                        task.auth_plan.attack_variant,
                        task.intensity,
                        task.policy,
                        task.binding_profile,
                        task.network_scenario,
                        task.topology_id,
                        task.repetition,
                        _json(task.network_parameters),
                        _json(authentication["factor_state"]),
                        bool(authentication["success"]),
                        bool(authentication["expected_success"]),
                        float(authentication["latency_ms"]),
                        _json(authentication.get("resource_metrics") or {}),
                        network_stage_status,
                        _json(network_result),
                        _json(resource_metrics),
                        _json(pcap_evidence),
                        chain_outcome,
                        execution_status,
                        bool(is_valid),
                    ),
                )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            self._release(conn)

    def progress(self, study_id: str, topology_id: str, expected: int) -> Dict[str, int]:
        conn = self._connection()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT
                        COUNT(*),
                        COUNT(*) FILTER (
                            WHERE execution_status='completed' AND is_valid IS TRUE
                        ),
                        COUNT(*) FILTER (WHERE execution_status='technical_error'),
                        COUNT(*) FILTER (WHERE network_stage_status='not_admitted'),
                        COUNT(*) FILTER (
                            WHERE network_stage_status IN (
                                'completed', 'external_threat_controlled'
                            )
                        )
                    FROM chained_experiment_runs
                    WHERE study_id=%s AND topology_id=%s
                    """,
                    (study_id, topology_id),
                )
                observed, valid, technical, stopped, admitted = [
                    int(value or 0) for value in cur.fetchone()
                ]
            return {
                "expected": int(expected),
                "observed": observed,
                "valid": valid,
                "technical_errors": technical,
                "blocked_at_authentication": stopped,
                "admitted_to_network": admitted,
            }
        finally:
            self._release(conn)
