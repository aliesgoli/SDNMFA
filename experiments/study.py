"""Study-level provenance, progress, and resume bookkeeping."""

from __future__ import annotations

import json
import uuid
from typing import Any, Dict, Iterable

from config.experiment_protocol import (
    BINDING_ORDER,
    DISPLAY_SCENARIO_ORDER,
    IMPLEMENTATION_REVISION,
    INTENSITY_ORDER,
    POLICY_ORDER,
    PROTOCOL_ID,
)
from experiments.chained_protocol import (
    CHAIN_AUTH_ATTACK_ORDER,
    CHAIN_PROTOCOL_ID,
    expected_chained_runs_per_topology,
)


THESIS_TOPOLOGIES = ("star-small", "tree-medium", "partial-mesh-medium")


def deterministic_study_id(
    *, base_seed: int, repetitions: int, topologies: Iterable[str] = THESIS_TOPOLOGIES
) -> str:
    key = "%s|%s|%s|%s|%s" % (
        PROTOCOL_ID,
        IMPLEMENTATION_REVISION,
        int(base_seed),
        int(repetitions),
        ",".join(topologies),
    )
    return str(uuid.uuid5(uuid.NAMESPACE_URL, key))


class StudyStore:
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

    def register(
        self,
        *,
        base_seed: int,
        repetitions: int,
        topologies: Iterable[str] = THESIS_TOPOLOGIES,
    ) -> str:
        topology_list = tuple(topologies)
        study_id = deterministic_study_id(
            base_seed=base_seed,
            repetitions=repetitions,
            topologies=topology_list,
        )
        design = {
            "authentication_policies": list(POLICY_ORDER),
            "network_bindings": list(BINDING_ORDER),
            "network_scenarios": list(DISPLAY_SCENARIO_ORDER),
            "intensity_levels": list(INTENSITY_ORDER),
            "repetitions": int(repetitions),
            "expected_network_runs_per_topology": (
                len(POLICY_ORDER)
                * len(BINDING_ORDER)
                * len(DISPLAY_SCENARIO_ORDER)
                * len(INTENSITY_ORDER)
                * int(repetitions)
            ),
            "chained_protocol_id": CHAIN_PROTOCOL_ID,
            "chained_authentication_attacks": list(CHAIN_AUTH_ATTACK_ORDER),
            "expected_chained_runs_per_topology": (
                expected_chained_runs_per_topology(int(repetitions))
            ),
            "laboratory_scope": "localhost_and_mininet_only",
        }
        conn = self._connection()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO thesis_studies (
                        study_id, protocol_id, implementation_revision, base_seed,
                        repetitions, expected_topologies, design_config, status
                    ) VALUES (%s, %s, %s, %s, %s, %s::jsonb, %s::jsonb, 'planned')
                    ON CONFLICT (study_id) DO UPDATE SET
                        design_config=EXCLUDED.design_config,
                        expected_topologies=EXCLUDED.expected_topologies
                    """,
                    (
                        study_id, PROTOCOL_ID, IMPLEMENTATION_REVISION,
                        int(base_seed), int(repetitions),
                        json.dumps(list(topology_list)), json.dumps(design, sort_keys=True),
                    ),
                )
            conn.commit()
            return study_id
        except Exception:
            conn.rollback()
            raise
        finally:
            self._release(conn)

    def start_topology(self, study_id: str, topology_id: str, repetitions: int) -> str:
        execution_id = str(
            uuid.uuid5(uuid.NAMESPACE_URL, "%s|%s" % (study_id, topology_id))
        )
        expected = (
            len(POLICY_ORDER)
            * len(BINDING_ORDER)
            * len(DISPLAY_SCENARIO_ORDER)
            * len(INTENSITY_ORDER)
            * int(repetitions)
        )
        conn = self._connection()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO topology_executions (
                        execution_id, study_id, topology_id, status,
                        expected_network_runs, started_at
                    ) VALUES (%s, %s, %s, 'running', %s, CURRENT_TIMESTAMP)
                    ON CONFLICT (study_id, topology_id) DO UPDATE SET
                        status='running',
                        expected_network_runs=EXCLUDED.expected_network_runs,
                        started_at=COALESCE(topology_executions.started_at, CURRENT_TIMESTAMP)
                    RETURNING execution_id
                    """,
                    (execution_id, study_id, topology_id, expected),
                )
                result = str(cur.fetchone()[0])
                cur.execute(
                    "UPDATE thesis_studies SET status='running' WHERE study_id=%s",
                    (study_id,),
                )
            conn.commit()
            return result
        except Exception:
            conn.rollback()
            raise
        finally:
            self._release(conn)

    def refresh_topology(self, study_id: str, topology_id: str) -> Dict[str, Any]:
        conn = self._connection()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT COUNT(*), COUNT(*) FILTER (WHERE r.is_valid IS TRUE)
                    FROM experiment_runs r
                    JOIN experiment_campaigns c ON c.campaign_id=r.campaign_id
                    WHERE c.study_id=%s AND r.topology_id=%s
                      AND r.execution_status='completed'
                    """,
                    (study_id, topology_id),
                )
                completed, valid = [int(value or 0) for value in cur.fetchone()]
                cur.execute(
                    """
                    UPDATE topology_executions
                    SET completed_network_runs=%s, valid_network_runs=%s,
                        status=CASE WHEN %s >= expected_network_runs
                            THEN 'completed' ELSE 'interrupted' END,
                        completed_at=CASE WHEN %s >= expected_network_runs
                            THEN CURRENT_TIMESTAMP ELSE completed_at END
                    WHERE study_id=%s AND topology_id=%s
                    RETURNING expected_network_runs, status, auth_study_completed
                    """,
                    (completed, valid, completed, completed, study_id, topology_id),
                )
                expected, status, auth_done = cur.fetchone()
                cur.execute(
                    """
                    SELECT COUNT(*) FILTER (WHERE status='completed'), COUNT(*)
                    FROM topology_executions WHERE study_id=%s
                    """,
                    (study_id,),
                )
                finished_topologies, observed_topologies = cur.fetchone()
                if int(finished_topologies) == len(THESIS_TOPOLOGIES):
                    cur.execute(
                        """
                        UPDATE thesis_studies SET status='completed',
                            completed_at=CURRENT_TIMESTAMP WHERE study_id=%s
                        """,
                        (study_id,),
                    )
            conn.commit()
            return {
                "study_id": study_id,
                "topology_id": topology_id,
                "completed_network_runs": completed,
                "valid_network_runs": valid,
                "expected_network_runs": int(expected),
                "status": str(status),
                "auth_study_completed": bool(auth_done),
                "completed_topology_count": int(finished_topologies),
                "observed_topology_count": int(observed_topologies),
            }
        except Exception:
            conn.rollback()
            raise
        finally:
            self._release(conn)

    def authentication_study_exists(self, study_id: str) -> bool:
        from experiments.authentication_protocol import build_authentication_plan

        expected = len(build_authentication_plan(
            base_seed=0, repetitions=self.study_repetitions(study_id), user_count=500
        ))
        conn = self._connection()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT COUNT(*)
                    FROM authentication_experiment_logs
                    WHERE study_id=%s
                    """,
                    (study_id,),
                )
                return int(cur.fetchone()[0] or 0) >= expected
        finally:
            self._release(conn)

    def study_repetitions(self, study_id: str) -> int:
        conn = self._connection()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT repetitions FROM thesis_studies WHERE study_id=%s",
                    (study_id,),
                )
                row = cur.fetchone()
            if not row:
                raise RuntimeError("Unknown thesis study: %s" % study_id)
            return int(row[0])
        finally:
            self._release(conn)

    def mark_authentication_complete(self, study_id: str, topology_id: str) -> None:
        conn = self._connection()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE topology_executions SET auth_study_completed=TRUE
                    WHERE study_id=%s AND topology_id=%s
                    """,
                    (study_id, topology_id),
                )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            self._release(conn)
