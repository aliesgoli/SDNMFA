"""System Evaluation and Performance Analysis

Creates evaluation reports from auth_logs and attack_logs.
"""

import os
import sys
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional

from psycopg2.extras import RealDictCursor as DictCursor
import matplotlib

matplotlib.use('Agg')
import matplotlib.pyplot as plt

project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Single source of truth for DB connection: database/db_config.py (reads .env)
from database.db_config import get_db_connection, release_db_connection

REPORTS_DIR = os.path.join(project_root, 'reports_view')
EVALUATION_DIR = os.path.join(REPORTS_DIR, 'evaluations')
CHARTS_DIR = os.path.join(EVALUATION_DIR, 'charts')
FILES_DIR = os.path.join(EVALUATION_DIR, 'files')

os.makedirs(REPORTS_DIR, exist_ok=True)
os.makedirs(EVALUATION_DIR, exist_ok=True)
os.makedirs(CHARTS_DIR, exist_ok=True)
os.makedirs(FILES_DIR, exist_ok=True)

plt.rcParams['figure.figsize'] = (7.2, 3.6)
plt.rcParams['font.size'] = 9
plt.rcParams['axes.titlesize'] = 11
plt.rcParams['axes.labelsize'] = 9
plt.rcParams['xtick.labelsize'] = 8
plt.rcParams['ytick.labelsize'] = 8
plt.rcParams['legend.fontsize'] = 8


class SystemEvaluator:
    def __init__(self):
        self.conn = None
        self.last_connect_error = None
        self.fig_manager = None
        self.current_stats = None
        self.report_timestamp = None
        self.generated_files = {
            'excel': None,
            'pdf': None
        }

    def connect(self) -> bool:
        # Prefer the project's pooled connection (keeps settings consistent),
        # but fall back to a direct connection for robustness.
        self.last_connect_error = None
        try:
            self.conn = get_db_connection()
        except Exception as e:
            self.conn = None
            self.last_connect_error = str(e)

        if self.conn is None and get_fallback_connection is not None:
            try:
                self.conn = get_fallback_connection()
            except Exception as e:
                self.conn = None
                # Keep the last error if pool did not provide one
                self.last_connect_error = self.last_connect_error or str(e)

        return self.conn is not None

    def disconnect(self):
        if not self.conn:
            return

        # If connection came from pool, release; otherwise close.
        try:
            release_db_connection(self.conn)
        except Exception:
            try:
                self.conn.close()
            except Exception:
                pass
            self.conn = None

    def get_evaluation_statistics(self, days: int = 7) -> Dict[str, Any]:
        """Collect evaluation statistics (schema-flexible).

        Fixes:
        - `since` was previously referenced without being defined.
        - Some DBs have different timestamp column names (created_at/start_time/timestamp/event_time).
          We detect them at runtime to avoid `column does not exist` crashes.
        - Detection/auth queries are now consistently filtered to the requested time window.
        """

        def _table_columns(table: str) -> set:
            try:
                with self.conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT column_name
                        FROM information_schema.columns
                        WHERE table_schema = 'public' AND table_name = %s
                        """,
                        (table,),
                    )
                    return {r[0] for r in cur.fetchall()}
            except Exception:
                return set()

        def _pick_time_col(cols: set, candidates: List[str]) -> Optional[str]:
            for c in candidates:
                if c in cols:
                    return c
            return None

        def _safe_int(x, default=0):
            try:
                return int(x)
            except Exception:
                return default

        since_dt = datetime.now() - timedelta(days=days)

        stats: Dict[str, Any] = {
            "period_days": days,
            "since": since_dt.strftime("%Y-%m-%d %H:%M:%S"),
        }

        attack_cols = _table_columns("attack_logs")
        auth_cols = _table_columns("auth_logs")
        user_cols = _table_columns("users")

        attack_time_col = _pick_time_col(attack_cols, ["created_at", "start_time", "timestamp"])
        auth_time_col = _pick_time_col(auth_cols, ["created_at", "timestamp", "event_time"])
        user_time_col = _pick_time_col(user_cols, ["created_at", "timestamp", "registered_at"])

        # -------------------------
        # Attack / security metrics
        # -------------------------
        try:
            if not attack_time_col:
                raise RuntimeError("attack_logs has no recognized timestamp column")

            with self.conn.cursor(cursor_factory=DictCursor) as cur:
                cur.execute(
                    f"""
                    SELECT
                        COUNT(*) AS total_attacks,
                        SUM(CASE WHEN success = TRUE THEN 1 ELSE 0 END) AS successful_attacks,
                        SUM(CASE WHEN success = FALSE THEN 1 ELSE 0 END) AS blocked_attacks
                    FROM attack_logs
                    WHERE {attack_time_col} >= NOW() - INTERVAL %s
                    """,
                    (f"{days} days",),
                )
                sec = cur.fetchone() or {}

            total_attacks = _safe_int(sec.get("total_attacks"))
            successful_attacks = _safe_int(sec.get("successful_attacks"))
            blocked_attacks = _safe_int(sec.get("blocked_attacks"))

            detection_rate = (blocked_attacks / total_attacks * 100.0) if total_attacks else 0.0

            stats["security"] = {
                "total_attacks": total_attacks,
                "successful_attacks": successful_attacks,
                "blocked_attacks": blocked_attacks,
                "detection_rate": round(detection_rate, 2),
            }

            # Attack types breakdown (for charts/table)
            with self.conn.cursor(cursor_factory=DictCursor) as cur:
                cur.execute(
                    f"""
                    SELECT attack_type,
                           COUNT(*) AS total,
                           SUM(CASE WHEN success = TRUE THEN 1 ELSE 0 END) AS success
                    FROM attack_logs
                    WHERE {attack_time_col} >= NOW() - INTERVAL %s
                    GROUP BY attack_type
                    ORDER BY total DESC
                    """,
                    (f"{days} days",),
                )
                rows = cur.fetchall() or []

            stats["security"]["attack_types"] = [
                {
                    "attack_type": r.get("attack_type") or "unknown",
                    "total": _safe_int(r.get("total")),
                    "success": _safe_int(r.get("success")),
                    "success_rate": round((_safe_int(r.get("success")) / _safe_int(r.get("total")) * 100.0) if _safe_int(r.get("total")) else 0.0, 2),
                }
                for r in rows
            ]

            # Used by the HTML report (avoid KeyError even when there is no data)
            stats["security"]["attack_types_count"] = len(stats["security"]["attack_types"])

            # Backwards/forwards compatibility key expected by the HTML report + charts.
            # detection_by_type is a list with per-attack detection (blocked) rate.
            stats["security"]["detection_by_type"] = [
                {
                    "attack_type": a["attack_type"],
                    "type": a["attack_type"],
                    "total": a["total"],
                    "blocked": max(a["total"] - a["success"], 0),
                    "detection_rate": round(((a["total"] - a["success"]) / a["total"] * 100.0) if a["total"] else 0.0, 2),
                }
                for a in stats["security"]["attack_types"]
            ]

        except Exception as e:
            print(f"⚠️ Error in attack/security query: {e}")
            stats["security"] = {
                "total_attacks": 0,
                "successful_attacks": 0,
                "blocked_attacks": 0,
                "attack_success_rate": 0.0,
                "detection_rate": 0.0,
                "attack_types_count": 0,
                "attack_types": [],
                "detection_by_type": [],
            }

        # -------------------------
        # Auth / performance metrics
        # -------------------------
        try:
            if not auth_time_col:
                raise RuntimeError("auth_logs has no recognized timestamp column")

            with self.conn.cursor(cursor_factory=DictCursor) as cur:
                cur.execute(
                    f"""
                    SELECT
                        COUNT(*) AS total_auth,
                        SUM(CASE WHEN success = TRUE THEN 1 ELSE 0 END) AS successful_auth,
                        SUM(CASE WHEN success = FALSE THEN 1 ELSE 0 END) AS failed_auth
                    FROM auth_logs
                    WHERE {auth_time_col} >= NOW() - INTERVAL %s
                    """,
                    (f"{days} days",),
                )
                auth = cur.fetchone() or {}

            total_auth = _safe_int(auth.get("total_auth"))
            successful_auth = _safe_int(auth.get("successful_auth"))
            failed_auth = _safe_int(auth.get("failed_auth"))
            auth_success_rate = (successful_auth / total_auth * 100.0) if total_auth else 0.0

            # Auth response times are optional (some schemas don't track it).
            # We normalize to **seconds** to match the report thresholds.
            avg_auth_time = None
            dur_unit = None
            if "duration_ms" in auth_cols or "duration_seconds" in auth_cols:
                dur_col = "duration_ms" if "duration_ms" in auth_cols else "duration_seconds"
                dur_unit = "ms" if dur_col == "duration_ms" else "s"
                with self.conn.cursor() as cur:
                    cur.execute(
                        f"""
                        SELECT AVG({dur_col}) FROM auth_logs
                        WHERE {auth_time_col} >= NOW() - INTERVAL %s
                        """,
                        (f"{days} days",),
                    )
                    avg_auth_time = cur.fetchone()[0]

            # Convert ms->s if needed
            avg_auth_time_seconds = None
            if avg_auth_time is not None:
                try:
                    avg_auth_time_seconds = float(avg_auth_time)
                    if dur_unit == "ms":
                        avg_auth_time_seconds = avg_auth_time_seconds / 1000.0
                except Exception:
                    avg_auth_time_seconds = None

            stats["auth"] = {
                "total_auth": total_auth,
                "successful_auth": successful_auth,
                "failed_auth": failed_auth,
                "success_rate": round(auth_success_rate, 2),
                # legacy/raw value (may be ms or seconds depending on schema)
                "avg_auth_time": float(avg_auth_time) if avg_auth_time is not None else None,
                # preferred normalized metric
                "avg_auth_time_seconds": avg_auth_time_seconds,
            }

        except Exception as e:
            print(f"⚠️ Error in auth query: {e}")
            stats["auth"] = {
                "total_auth": 0,
                "successful_auth": 0,
                "failed_auth": 0,
                "success_rate": 0.0,
                "avg_auth_time": None,
                "avg_auth_time_seconds": None,
            }

        # -------------------------
        # User metrics
        # -------------------------
        try:
            if user_cols:
                with self.conn.cursor() as cur:
                    cur.execute("SELECT COUNT(*) FROM users")
                    total_users = cur.fetchone()[0] or 0

                active_users = None
                if user_time_col:
                    with self.conn.cursor() as cur:
                        cur.execute(
                            f"""
                            SELECT COUNT(*) FROM users
                            WHERE {user_time_col} >= NOW() - INTERVAL %s
                            """,
                            (f"{days} days",),
                        )
                        active_users = cur.fetchone()[0]

                stats["users"] = {
                    "total_users": int(total_users),
                    "new_users_period": int(active_users) if active_users is not None else None,
                }
            else:
                stats["users"] = {"total_users": 0, "new_users_period": None}
        except Exception as e:
            print(f"⚠️ Error in user query: {e}")
            stats["users"] = {"total_users": 0, "new_users_period": None}

        # -------------------------
        # Active days metric
        # -------------------------
        try:
            if not attack_time_col:
                raise RuntimeError("attack_logs has no recognized timestamp column")

            with self.conn.cursor() as cur:
                cur.execute(
                    f"""
                    SELECT COUNT(DISTINCT DATE({attack_time_col})) AS active_days
                    FROM attack_logs
                    WHERE {attack_time_col} >= NOW() - INTERVAL %s
                    """,
                    (f"{days} days",),
                )
                active_days = cur.fetchone()[0] or 0

            stats["active_days"] = int(active_days)

        except Exception as e:
            print(f"⚠️ Error in active days query: {e}")
            stats["active_days"] = 0

        # ------------------------------------------------------------
        # Derived scores (always present)
        # ------------------------------------------------------------
        # Security is primarily measured by how often attacks are blocked.
        attack_overall = (stats.get('security', {})
                          .get('attacks', {})
                          .get('overall', {}))
        attack_success_rate = float(attack_overall.get('success_rate') or 0.0)
        attack_blocked_rate = max(0.0, min(1.0, 1.0 - attack_success_rate))
        security_score = round(attack_blocked_rate * 100.0, 2)

        # Performance is based on authentication success rate (proxy for UX + availability).
        auth_success_rate = float(stats.get('auth', {}).get('success_rate') or 0.0)
        performance_score = round(max(0.0, min(1.0, auth_success_rate)) * 100.0, 2)

        # Reliability is based on how many distinct days the system was active in the period.
        active_days = int(stats.get('active_days') or 0)
        reliability_score = round(min(1.0, active_days / max(1, int(days))) * 100.0, 2)

        overall_score = round(
            (0.50 * security_score) + (0.30 * performance_score) + (0.20 * reliability_score),
            2
        )

        def _grade(score: float) -> str:
            if score >= 90:
                return 'A (Excellent)'
            if score >= 80:
                return 'B (Good)'
            if score >= 70:
                return 'C (Fair)'
            if score >= 60:
                return 'D (Weak)'
            return 'F (Poor)'

        # Persist breakdowns in a consistent shape for report builders
        stats.setdefault('security', {})
        stats.setdefault('performance', {})
        stats.setdefault('reliability', {})

        stats['security']['score'] = security_score
        stats['security']['grade'] = _grade(security_score)

        stats['performance']['score'] = performance_score
        stats['performance']['grade'] = _grade(performance_score)

        # Populate the detailed performance metrics expected by the HTML/CSV
        # report builders. These may not exist in older DB schemas, so we
        # always provide safe defaults to avoid KeyError.
        auth = stats.get('auth', {}) or {}
        stats['performance']['avg_auth_response_time'] = round(
            float(auth.get('avg_auth_time_seconds') or 0.0), 3
        )
        stats['performance']['auth_success_rate'] = float(auth.get('success_rate') or 0.0)
        stats['performance']['total_auth_attempts'] = int(auth.get('total_auth') or 0)
        stats['performance']['failed_auth_attempts'] = int(auth.get('failed_auth') or 0)

        stats['reliability']['score'] = reliability_score
        stats['reliability']['grade'] = _grade(reliability_score)

        # Populate detailed reliability metrics expected by the HTML/CSV builders.
        # These are optional in older schemas, so we always provide safe defaults.
        users = stats.get('users', {}) or {}
        total_users = int(users.get('total_users') or 0)

        # Try to detect biometric coverage if a biometric template table exists.
        users_with_biometric = 0
        try:
            with self.conn.cursor() as cur:
                cur.execute(
                    "SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name=%s)",
                    ("biometric_templates",),
                )
                has_bio = bool(cur.fetchone()[0])
            if has_bio:
                with self.conn.cursor() as cur:
                    cur.execute("SELECT COUNT(DISTINCT username) FROM biometric_templates")
                    users_with_biometric = int(cur.fetchone()[0] or 0)
        except Exception:
            users_with_biometric = 0

        biometric_coverage = (users_with_biometric / total_users * 100.0) if total_users else 0.0
        system_uptime_ratio = round(min(1.0, (active_days / max(1, int(days)))) * 100.0, 2)

        stats['reliability']['biometric_coverage'] = round(float(biometric_coverage), 2)
        stats['reliability']['system_uptime_ratio'] = float(system_uptime_ratio)
        stats['reliability']['total_users'] = total_users
        stats['reliability']['users_with_biometric'] = users_with_biometric
        stats['reliability']['active_days'] = active_days


        stats['overall_score'] = overall_score
        stats['overall_grade'] = _grade(overall_score)

        return stats

    def generate_evaluation_charts(self, stats: Dict[str, Any]) -> List[str]:
        if not stats:
            return []

        chart_files = []

        try:
            fig, ax = plt.subplots(figsize=(7.2, 3.6))
            fig.canvas.manager.set_window_title('System Evaluation Scores')

            categories = ['Overall', 'Security', 'Performance', 'Reliability']
            scores = [
                stats['overall_score'],
                stats['security']['score'],
                stats['performance']['score'],
                stats['reliability']['score']
            ]
            colors = ['#3498db', '#e74c3c', '#2ecc71', '#f39c12']

            bars = ax.bar(categories, scores, color=colors, alpha=0.8, width=0.6)

            ax.set_ylabel('Score (0-100)', fontweight='bold', fontsize=9)
            ax.set_title('System Evaluation Scores', fontweight='bold', fontsize=10)
            ax.set_ylim(0, 110)
            ax.grid(True, alpha=0.3, axis='y')

            for bar, score in zip(bars, scores):
                height = bar.get_height()
                ax.text(bar.get_x() + bar.get_width() / 2., height + 3,
                        f'{score}', ha='center', va='bottom', fontweight='bold', fontsize=9)

            plt.tight_layout()
            chart_file = os.path.join(CHARTS_DIR, 'evaluation_scores.png')
            plt.savefig(chart_file, dpi=150, bbox_inches='tight')
            chart_files.append('charts/evaluation_scores.png')
            print(f"✅ Chart saved: {chart_file}")
            plt.show(block=False)

            if stats['security']['detection_by_type']:
                fig, ax = plt.subplots(figsize=(7.2, 3.6))
                fig.canvas.manager.set_window_title('Attack Detection Rates')

                # Key name compatibility: the query returns 'attack_type', while some
                # older report code referenced 'type'. Support both.
                types = [
                    (item.get('attack_type') or item.get('type') or 'unknown')
                    for item in stats['security']['detection_by_type']
                ]
                detection_rates = [
                    float(item.get('detection_rate', 0.0) or 0.0)
                    for item in stats['security']['detection_by_type']
                ]

                bars = ax.bar(types, detection_rates, color='#e74c3c', alpha=0.8, width=0.6)

                ax.set_ylabel('Detection Rate (%)', fontweight='bold', fontsize=9)
                ax.set_title('Attack Detection Rates by Type', fontweight='bold', fontsize=10)
                ax.set_ylim(0, 110)

                plt.xticks(rotation=45, ha='right', fontsize=8)
                ax.grid(True, alpha=0.3, axis='y')

                for bar, rate in zip(bars, detection_rates):
                    height = bar.get_height()
                    ax.text(bar.get_x() + bar.get_width() / 2., height + 3,
                            f'{rate}%', ha='center', va='bottom', fontweight='bold', fontsize=8)

                plt.tight_layout()
                chart_file = os.path.join(CHARTS_DIR, 'detection_rates.png')
                plt.savefig(chart_file, dpi=150, bbox_inches='tight')
                chart_files.append('charts/detection_rates.png')
                print(f"✅ Chart saved: {chart_file}")
                plt.show(block=False)

            fig, ax = plt.subplots(figsize=(3.2, 3.2))
            fig.canvas.manager.set_window_title('System Health Distribution')

            metrics = ['Security', 'Performance', 'Reliability']
            scores = [
                stats['security']['score'],
                stats['performance']['score'],
                stats['reliability']['score']
            ]
            colors = ['#e74c3c', '#2ecc71', '#3498db']

            wedges, texts, autotexts = ax.pie(scores, labels=metrics, colors=colors,
                                              autopct='%1.1f%%', startangle=90,
                                              textprops={'fontsize': 8, 'fontweight': 'bold'})

            for autotext in autotexts:
                autotext.set_color('white')
                autotext.set_fontweight('bold')

            ax.set_title('⚖️ System Health Distribution', fontsize=9, fontweight='bold')

            plt.tight_layout()
            chart_file = os.path.join(CHARTS_DIR, 'system_health.png')
            plt.savefig(chart_file, dpi=150, bbox_inches='tight')
            chart_files.append('charts/system_health.png')
            print(f"✅ Chart saved: {chart_file}")
            plt.show(block=False)

            plt.pause(0.1)
            return chart_files

        except Exception as e:
            print(f"❌ Error generating charts: {e}")
            return chart_files

    def generate_excel_export(self, stats: Dict[str, Any]) -> str:
        try:
            import xlsxwriter

            timestamp = self.report_timestamp or datetime.now().strftime('%Y%m%d_%H%M%S')
            excel_file = os.path.join(FILES_DIR, f'system_evaluation_{timestamp}.xlsx')

            workbook = xlsxwriter.Workbook(excel_file)

            title_format = workbook.add_format({'bold': True, 'font_size': 14})
            header_format = workbook.add_format({'bold': True, 'bg_color': '#667eea', 'font_color': 'white'})
            data_format = workbook.add_format({'num_format': '#,##0'})

            summary_sheet = workbook.add_worksheet('Summary')
            summary_sheet.set_column('A:B', 20)

            summary_sheet.write('A1', 'SDN MFA System Evaluation Report', title_format)
            summary_sheet.write('A2', f'Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')
            summary_sheet.write('A3', f'Evaluation Period: {stats["period_days"]} days')

            summary_sheet.write('A5', 'OVERALL RATING', header_format)
            summary_data = [
                ['Overall Score', stats['overall_score']],
                ['Overall Grade', stats['overall_grade']],
                ['Security Score', stats['security']['score']],
                ['Performance Score', stats['performance']['score']],
                ['Reliability Score', stats['reliability']['score']]
            ]

            for i, (label, value) in enumerate(summary_data, 6):
                summary_sheet.write(f'A{i}', label)
                summary_sheet.write(f'B{i}', value, data_format if isinstance(value, (int, float)) else None)

            if stats['security']['detection_by_type']:
                type_sheet = workbook.add_worksheet('Detection Rates')
                type_sheet.set_column('A:A', 25)
                type_sheet.set_column('B:D', 15)

                headers = ['Attack Type', 'Total Attacks', 'Blocked Attacks', 'Detection Rate']
                for col, header in enumerate(headers):
                    type_sheet.write(0, col, header, header_format)

                for row, item in enumerate(stats['security']['detection_by_type'], 1):
                    type_sheet.write(row, 0, (item.get('attack_type') or item.get('type') or 'unknown'))
                    type_sheet.write(row, 1, item['total'], data_format)
                    type_sheet.write(row, 2, item['blocked'], data_format)
                    type_sheet.write(row, 3, f'{item["detection_rate"]}%')

            workbook.close()
            relative_path = f'files/system_evaluation_{timestamp}.xlsx'
            self.generated_files['excel'] = relative_path
            print(f"✅ Excel file generated: {excel_file}")
            return relative_path

        except ImportError:
            return "error:xlsxwriter"
        except Exception as e:
            return f"error:{str(e)}"

    def generate_pdf_export(self, stats: Dict[str, Any]) -> str:
        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib import colors
            from reportlab.lib.units import inch

            timestamp = self.report_timestamp or datetime.now().strftime('%Y%m%d_%H%M%S')
            pdf_file = os.path.join(FILES_DIR, f'system_evaluation_{timestamp}.pdf')

            doc = SimpleDocTemplate(pdf_file, pagesize=A4)
            story = []

            styles = getSampleStyleSheet()
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=styles['Heading1'],
                fontSize=16,
                spaceAfter=30,
                textColor=colors.HexColor('#2c3e50'),
                alignment=1
            )

            title = Paragraph('SDN MFA System Evaluation Report', title_style)
            story.append(title)
            story.append(Spacer(1, 20))

            info_text = f'Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")} | Evaluation Period: {stats["period_days"]} days'
            story.append(Paragraph(info_text, styles['Normal']))
            story.append(Spacer(1, 30))

            story.append(Paragraph('Overall Rating', styles['Heading2']))

            summary_data = [
                ['Overall Score', f"{stats['overall_score']}/100"],
                ['Overall Grade', stats['overall_grade']],
                ['Security Score', f"{stats['security']['score']}/100"],
                ['Performance Score', f"{stats['performance']['score']}/100"],
                ['Reliability Score', f"{stats['reliability']['score']}/100"]
            ]

            summary_table = Table(summary_data, colWidths=[2.5 * inch, 2 * inch])
            summary_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#667eea')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ('BACKGROUND', (0, 1), (-1, -1), colors.white),
                ('GRID', (0, 0), (-1, -1), 1, colors.grey),
            ]))
            story.append(summary_table)

            if stats['security']['detection_by_type']:
                story.append(Spacer(1, 20))
                story.append(Paragraph('Detection Rates by Attack Type', styles['Heading2']))

                type_data = [['Attack Type', 'Total', 'Blocked', 'Detection Rate']]
                for item in stats['security']['detection_by_type']:
                    type_data.append([
                        (item.get('attack_type') or item.get('type') or 'unknown'),
                        str(item['total']),
                        str(item['blocked']),
                        f'{item["detection_rate"]}%'
                    ])

                type_table = Table(type_data, colWidths=[1.5 * inch, 0.8 * inch, 0.8 * inch, 1 * inch])
                type_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#667eea')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 10),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.white),
                    ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                    ('FONTSIZE', (0, 1), (-1, -1), 9),
                    ('GRID', (0, 0), (-1, -1), 1, colors.grey),
                ]))
                story.append(type_table)

            doc.build(story)
            relative_path = f'files/system_evaluation_{timestamp}.pdf'
            self.generated_files['pdf'] = relative_path
            print(f"✅ PDF file generated: {pdf_file}")
            return relative_path

        except ImportError:
            return "error:reportlab"
        except Exception as e:
            return f"error:{str(e)}"

    def generate_evaluation_report(self, stats: Dict[str, Any], chart_files: List[str],
                                   output_file: str = None) -> str:
        if not output_file:
            self.report_timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_file = os.path.join(EVALUATION_DIR, f'system_evaluation_{self.report_timestamp}.html')

        self.current_stats = stats

        detection_by_type_csv = ""
        if stats.get('security', {}).get('detection_by_type'):
            for item in stats['security']['detection_by_type']:
                atype = item.get('attack_type') or item.get('type') or 'unknown'
                detection_by_type_csv += (
                    f'csvContent += "{atype},{item.get("total", 0)},{item.get("blocked", 0)},{item.get("detection_rate", 0)}%\\\\n";\n'
                )

        excel_filename = self.generated_files['excel'].split('/')[-1] if self.generated_files['excel'] else ''
        pdf_filename = self.generated_files['pdf'].split('/')[-1] if self.generated_files['pdf'] else ''

        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🛡️ SDN MFA System Evaluation Report</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            color: #333;
            min-height: 100vh;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }}
        .header h1 {{
            font-size: 2em;
            margin-bottom: 10px;
        }}
        .action-buttons {{
            display: flex;
            justify-content: center;
            flex-wrap: wrap;
            gap: 10px;
            margin-top: 20px;
        }}
        .btn {{
            display: inline-flex;
            align-items: center;
            gap: 5px;
            padding: 10px 16px;
            background: #667eea;
            color: white;
            border: none;
            border-radius: 8px;
            text-decoration: none;
            transition: all 0.3s;
            font-size: 0.9em;
            cursor: pointer;
            font-family: inherit;
        }}
        .btn:hover {{
            background: #764ba2;
            transform: translateY(-2px);
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            padding: 30px;
            background: #f8f9fa;
        }}
        .stat-card {{
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            text-align: center;
            transition: transform 0.3s;
        }}
        .stat-card:hover {{
            transform: translateY(-5px);
        }}
        .stat-value {{
            font-size: 2em;
            font-weight: bold;
            color: #667eea;
            margin: 10px 0;
        }}
        .section {{
            padding: 30px;
        }}
        .section-title {{
            font-size: 1.6em;
            color: #667eea;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 3px solid #667eea;
        }}
        .chart-container {{
            margin: 20px 0;
            text-align: center;
        }}
        .chart-container img {{
            max-width: 80%;
            height: auto;
            border-radius: 10px;
            box-shadow: 0 4px 8px rgba(0,0,0,0.1);
            cursor: pointer;
            transition: transform 0.3s;
        }}
        .chart-container img:hover {{
            transform: scale(1.02);
        }}
        .data-table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
            background: white;
            border-radius: 10px;
            overflow: hidden;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }}
        .data-table th {{
            background: #667eea;
            color: white;
            padding: 12px;
            text-align: left;
        }}
        .data-table td {{
            padding: 10px 12px;
            border-bottom: 1px solid #e0e0e0;
        }}
        .data-table tr:hover {{
            background: #f5f5f5;
        }}
        .excellent-badge {{
            background: #2ecc71;
            color: white;
            padding: 4px 8px;
            border-radius: 5px;
            font-weight: bold;
        }}
        .good-badge {{
            background: #3498db;
            color: white;
            padding: 4px 8px;
            border-radius: 5px;
            font-weight: bold;
        }}
        .average-badge {{
            background: #f39c12;
            color: white;
            padding: 4px 8px;
            border-radius: 5px;
            font-weight: bold;
        }}
        .poor-badge {{
            background: #e74c3c;
            color: white;
            padding: 4px 8px;
            border-radius: 5px;
            font-weight: bold;
        }}
        .modal {{
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.8);
            z-index: 1000;
            justify-content: center;
            align-items: center;
        }}
        .modal img {{
            max-width: 90%;
            max-height: 90%;
            border-radius: 10px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ SDN MFA System Evaluation Report</h1>
            <p>📅 Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p>⏰ Evaluation Period: {stats['period_days']} days</p>

            <div class="action-buttons">
                <button class="btn" onclick="printReport()">🖨️ Print</button>
                <button class="btn" onclick="exportToCSV()">📊 CSV</button>
                {'<button class="btn" onclick="downloadExcel()">📈 Excel</button>' if self.generated_files['excel'] and not self.generated_files['excel'].startswith('error:') else ''}
                {'<button class="btn" onclick="downloadPDF()">📄 PDF</button>' if self.generated_files['pdf'] and not self.generated_files['pdf'].startswith('error:') else ''}
            </div>
        </div>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-label">Overall Score</div>
                <div class="stat-value">{stats['overall_score']}/100</div>
                <span class="{self._get_badge_class(stats['overall_score'])}">{stats['overall_grade']}</span>
            </div>
            <div class="stat-card">
                <div class="stat-label">Security Score</div>
                <div class="stat-value" style="color: #e74c3c;">{stats['security']['score']}/100</div>
                <span class="{self._get_badge_class(stats['security']['score'])}">{stats['security']['grade']}</span>
            </div>
            <div class="stat-card">
                <div class="stat-label">Performance Score</div>
                <div class="stat-value" style="color: #f39c12;">{stats['performance']['score']}/100</div>
                <span class="{self._get_badge_class(stats['performance']['score'])}">{stats['performance']['grade']}</span>
            </div>
            <div class="stat-card">
                <div class="stat-label">Reliability Score</div>
                <div class="stat-value" style="color: #3498db;">{stats['reliability']['score']}/100</div>
                <span class="{self._get_badge_class(stats['reliability']['score'])}">{stats['reliability']['grade']}</span>
            </div>
        </div>

        <div class="section">
            <h2 class="section-title">📊 System Evaluation Charts</h2>
"""

        for chart_file in chart_files:
            html += f"""
            <div class="chart-container">
                <img src="{chart_file}" alt="Chart" onclick="openModal(this.src)">
            </div>
"""

        html += f"""
            <h3 style="margin-top: 40px; color: #667eea;">🛡️ Security Evaluation</h3>
            <table class="data-table">
                <thead>
                    <tr>
                        <th>Metric</th>
                        <th>Value</th>
                        <th>Score</th>
                        <th>Grade</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td><strong>Total Attacks</strong></td>
                        <td>{stats['security']['total_attacks']:,}</td>
                        <td>-</td>
                        <td>-</td>
                    </tr>
                    <tr>
                        <td><strong>Blocked Attacks</strong></td>
                        <td>{stats['security']['blocked_attacks']:,}</td>
                        <td>-</td>
                        <td>-</td>
                    </tr>
                    <tr>
                        <td><strong>Detection Rate</strong></td>
                        <td>{stats['security']['detection_rate']:.1f}%</td>
                        <td>-</td>
                        <td>-</td>
                    </tr>
                    <tr>
                        <td><strong>Attack Types</strong></td>
                        <td>{stats['security']['attack_types_count']}</td>
                        <td>-</td>
                        <td>-</td>
                    </tr>
                    <tr>
                        <td><strong>Security Score</strong></td>
                        <td>{stats['security']['score']}/100</td>
                        <td>{stats['security']['score']}</td>
                        <td><span class="{self._get_badge_class(stats['security']['score'])}">{stats['security']['grade']}</span></td>
                    </tr>
                </tbody>
            </table>
"""

        if stats['security']['detection_by_type']:
            html += f"""
            <h4 style="margin-top: 20px; color: #e74c3c;">🎯 Detection Rates by Attack Type</h4>
            <table class="data-table">
                <thead>
                    <tr>
                        <th>Attack Type</th>
                        <th>Total Attacks</th>
                        <th>Blocked Attacks</th>
                        <th>Detection Rate</th>
                    </tr>
                </thead>
                <tbody>
"""
            for item in stats['security']['detection_by_type']:
                badge_class = "excellent-badge" if item['detection_rate'] >= 90 else "good-badge" if item['detection_rate'] >= 70 else "average-badge" if item['detection_rate'] >= 50 else "poor-badge"
                html += f"""
                    <tr>
                        <td><strong>{(item.get('attack_type') or item.get('type') or 'unknown')}</strong></td>
                        <td>{item['total']}</td>
                        <td><span class="{badge_class}">{item['blocked']}</span></td>
                        <td>{item['detection_rate']}%</td>
                    </tr>
"""
            html += """
                </tbody>
            </table>
"""

        html += f"""
            <h3 style="margin-top: 40px; color: #667eea;">⚡ Performance Evaluation</h3>
            <table class="data-table">
                <thead>
                    <tr>
                        <th>Metric</th>
                        <th>Value</th>
                        <th>Score</th>
                        <th>Grade</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td><strong>Avg Auth Response Time</strong></td>
                        <td>{stats.get('performance', {}).get('avg_auth_response_time', 0)}s</td>
                        <td>-</td>
                        <td>-</td>
                    </tr>
                    <tr>
                        <td><strong>Auth Success Rate</strong></td>
                        <td>{stats.get('performance', {}).get('auth_success_rate', 0.0):.1f}%</td>
                        <td>-</td>
                        <td>-</td>
                    </tr>
                    <tr>
                        <td><strong>Total Auth Attempts</strong></td>
                        <td>{int(stats.get('performance', {}).get('total_auth_attempts', 0)):,}</td>
                        <td>-</td>
                        <td>-</td>
                    </tr>
                    <tr>
                        <td><strong>Failed Auth Attempts</strong></td>
                        <td>{int(stats.get('performance', {}).get('failed_auth_attempts', 0)):,}</td>
                        <td>-</td>
                        <td>-</td>
                    </tr>
                    <tr>
                        <td><strong>Performance Score</strong></td>
                        <td>{stats['performance']['score']}/100</td>
                        <td>{stats['performance']['score']}</td>
                        <td><span class="{self._get_badge_class(stats['performance']['score'])}">{stats['performance']['grade']}</span></td>
                    </tr>
                </tbody>
            </table>
"""

        html += f"""
            <h3 style="margin-top: 40px; color: #667eea;">🔒 Reliability Evaluation</h3>
            <table class="data-table">
                <thead>
                    <tr>
                        <th>Metric</th>
                        <th>Value</th>
                        <th>Score</th>
                        <th>Grade</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td><strong>Biometric Coverage</strong></td>
                        <td>{stats['reliability']['biometric_coverage']:.1f}%</td>
                        <td>-</td>
                        <td>-</td>
                    </tr>
                    <tr>
                        <td><strong>System Uptime Ratio</strong></td>
                        <td>{stats['reliability']['system_uptime_ratio']:.1f}%</td>
                        <td>-</td>
                        <td>-</td>
                    </tr>
                    <tr>
                        <td><strong>Total Users</strong></td>
                        <td>{stats['reliability']['total_users']:,}</td>
                        <td>-</td>
                        <td>-</td>
                    </tr>
                    <tr>
                        <td><strong>Users with Biometric</strong></td>
                        <td>{stats['reliability']['users_with_biometric']:,}</td>
                        <td>-</td>
                        <td>-</td>
                    </tr>
                    <tr>
                        <td><strong>Active Days</strong></td>
                        <td>{stats['reliability']['active_days']}</td>
                        <td>-</td>
                        <td>-</td>
                    </tr>
                    <tr>
                        <td><strong>Reliability Score</strong></td>
                        <td>{stats['reliability']['score']}/100</td>
                        <td>{stats['reliability']['score']}</td>
                        <td><span class="{self._get_badge_class(stats['reliability']['score'])}">{stats['reliability']['grade']}</span></td>
                    </tr>
                </tbody>
            </table>
"""

        recommendations = self._generate_recommendations(stats)
        if recommendations:
            html += """
            <div style="background: #fff3cd; border-radius: 10px; padding: 20px; margin: 20px 0;">
                <h3 style="color: #856404; margin-bottom: 15px;">💡 Recommendations for Improvement</h3>
                <ul style="list-style-type: none; padding: 0;">
"""
            for recommendation in recommendations:
                html += f"""
                    <li style="padding: 8px 0; border-bottom: 1px solid #ffeaa7; color: #856404;">{recommendation}</li>
"""
            html += """
                </ul>
            </div>
"""

        html += f"""
        </div>
    </div>

    <div class="modal" id="imageModal" onclick="closeModal()">
        <img id="modalImage" src="" alt="Enlarged view">
    </div>

    <script>
        function printReport() {{
            window.print();
        }}

        function openModal(src) {{
            document.getElementById('modalImage').src = src;
            document.getElementById('imageModal').style.display = 'flex';
        }}

        function closeModal() {{
            document.getElementById('imageModal').style.display = 'none';
        }}

        function downloadExcel() {{
            window.location.href = '{self.generated_files['excel']}';
        }}

        function downloadPDF() {{
            window.location.href = '{self.generated_files['pdf']}';
        }}

        function exportToCSV() {{
            let csvContent = "SDN MFA System Evaluation Report\\\\n";
            csvContent += "Generated: " + new Date().toLocaleString() + "\\\\n";
            csvContent += "Evaluation Period: {stats['period_days']} days\\\\n\\\\n";

            csvContent += "OVERALL RATING\\\\n";
            csvContent += "Overall Score,{stats['overall_score']}\\\\n";
            csvContent += "Overall Grade,{stats['overall_grade']}\\\\n";
            csvContent += "Security Score,{stats['security']['score']}\\\\n";
            csvContent += "Performance Score,{stats['performance']['score']}\\\\n";
            csvContent += "Reliability Score,{stats['reliability']['score']}\\\\n\\\\n";

            csvContent += "SECURITY EVALUATION\\\\n";
            csvContent += "Total Attacks,{stats['security']['total_attacks']}\\\\n";
            csvContent += "Blocked Attacks,{stats['security']['blocked_attacks']}\\\\n";
            csvContent += "Detection Rate,{stats['security']['detection_rate']:.1f}%\\\\n";
            csvContent += "Attack Types,{stats['security']['attack_types_count']}\\\\n";
            csvContent += "Security Grade,{stats['security']['grade']}\\\\n\\\\n";

	            csvContent += "PERFORMANCE EVALUATION\\\\n";
	            csvContent += "Avg Auth Response Time,{stats.get('performance', {}).get('avg_auth_response_time', 0)}s\\\\n";
	            csvContent += "Auth Success Rate,{stats.get('performance', {}).get('auth_success_rate', 0.0):.1f}%\\\\n";
	            csvContent += "Total Auth Attempts,{int(stats.get('performance', {}).get('total_auth_attempts', 0))}\\\\n";
	            csvContent += "Failed Auth Attempts,{int(stats.get('performance', {}).get('failed_auth_attempts', 0))}\\\\n";
	            csvContent += "Performance Grade,{stats.get('performance', {}).get('grade', '')}\\\\n\\\\n";

            csvContent += "RELIABILITY EVALUATION\\\\n";
            csvContent += "Biometric Coverage,{stats['reliability']['biometric_coverage']:.1f}%\\\\n";
            csvContent += "System Uptime Ratio,{stats['reliability']['system_uptime_ratio']:.1f}%\\\\n";
            csvContent += "Total Users,{stats['reliability']['total_users']}\\\\n";
            csvContent += "Users with Biometric,{stats['reliability']['users_with_biometric']}\\\\n";
            csvContent += "Active Days,{stats['reliability']['active_days']}\\\\n";
            csvContent += "Reliability Grade,{stats['reliability']['grade']}\\\\n\\\\n";

            if ({len(stats['security']['detection_by_type'])} > 0) {{
                csvContent += "DETECTION RATES BY ATTACK TYPE\\\\n";
                csvContent += "Attack Type,Total Attacks,Blocked Attacks,Detection Rate\\\\n";
                {detection_by_type_csv}
            }}

            const blob = new Blob([csvContent], {{ type: 'text/csv;charset=utf-8;' }});
            const link = document.createElement('a');
            const url = URL.createObjectURL(blob);
            link.setAttribute('href', url);
            link.setAttribute('download', 'system_evaluation_' + new Date().toISOString().slice(0, 10) + '.csv');
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
        }}
    </script>
</body>
</html>
"""

        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html)

        print(f"✅ Report generated: {output_file}")
        return output_file

    def _calculate_security_score(self, blocked_attacks: int, total_attacks: int,
                                  failed_auth: int, total_auth: int,
                                  detection_rates: List[Dict]) -> float:
        if total_attacks == 0 and total_auth == 0:
            return 100.0

        detection_score = (blocked_attacks / total_attacks * 100) if total_attacks > 0 else 100
        prevention_score = (failed_auth / total_auth * 100) if total_auth > 0 else 100

        diversity_bonus = min(10, len(detection_rates) * 2)

        total_score = (detection_score * 0.6) + (prevention_score * 0.4) + diversity_bonus
        return round(min(100, max(0, total_score)), 2)

    def _calculate_performance_score(self, avg_auth_time: float) -> float:
        if avg_auth_time <= 1.0:
            return 100.0
        elif avg_auth_time <= 3.0:
            return 90.0 - (avg_auth_time - 1.0) * 10
        elif avg_auth_time <= 5.0:
            return 70.0 - (avg_auth_time - 3.0) * 15
        else:
            return max(0, 40.0 - (avg_auth_time - 5.0) * 5)

    def _calculate_reliability_score(self, biometric_coverage: float, uptime_ratio: float,
                                     failed_auth: int, total_auth: int) -> float:
        error_rate = (failed_auth / total_auth * 100) if total_auth > 0 else 0
        error_score = max(0, 100 - error_rate * 2)

        total_score = (
                biometric_coverage * 0.3 +
                uptime_ratio * 0.4 +
                error_score * 0.3
        )
        return round(min(100, total_score), 2)

    def _get_grade(self, score: float) -> str:
        if score >= 90:
            return "A+ (Excellent)"
        elif score >= 80:
            return "A (Very Good)"
        elif score >= 70:
            return "B (Good)"
        elif score >= 60:
            return "C (Average)"
        elif score >= 50:
            return "D (Poor)"
        else:
            return "F (Failed)"

    def _get_badge_class(self, score: float) -> str:
        if score >= 90:
            return "excellent-badge"
        elif score >= 80:
            return "excellent-badge"
        elif score >= 70:
            return "good-badge"
        elif score >= 60:
            return "average-badge"
        elif score >= 50:
            return "average-badge"
        else:
            return "poor-badge"

    def _generate_recommendations(self, stats: Dict[str, Any]) -> List[str]:
        recommendations = []

        if stats['security']['score'] < 80:
            recommendations.append("🔒 Improve attack detection mechanisms and update security rules")
        if stats['security']['detection_rate'] < 85:
            recommendations.append("🛡️ Enhance IDS/IPS rules and consider additional security layers")

        if stats['performance']['score'] < 80:
            recommendations.append("⚡ Optimize authentication processes and database queries")
        if float(stats.get('performance', {}).get('avg_auth_response_time', 0.0)) > 3.0:
            recommendations.append("⏱️ Implement connection pooling and cache frequently accessed data")

        if stats['reliability']['score'] < 80:
            recommendations.append("🔄 Increase system monitoring and implement automated recovery")
        if stats['reliability']['biometric_coverage'] < 90:
            recommendations.append("👤 Encourage users to enroll biometric authentication")

        if not recommendations:
            recommendations.append("✅ System is performing well. Continue current maintenance practices")

        return recommendations[:5]


def main():
    print("\n" + "=" * 70)
    print("🛡️  System Evaluation and Performance Analysis ".center(70, "="))
    print("=" * 70)

    evaluator = SystemEvaluator()

    if not evaluator.connect():
        print("\n❌ Database connection failed")
        if evaluator.last_connect_error:
            print(f"   ↳ {evaluator.last_connect_error}")
        return

    print("\n📊 Analyzing system performance and security...")

    days = input("\n⏰ Enter evaluation period in days [7]: ").strip()
    days = int(days) if days.isdigit() else 7

    stats = evaluator.get_evaluation_statistics(days)

    if not stats:
        print(f"\n⚠️ No evaluation data found for the last {days} days")
        evaluator.disconnect()
        return

    print(f"\n🎯 System Overall Score: {stats['overall_score']}/100 ({stats['overall_grade']})")

    print("\n📈 Generating Excel file...")
    excel_file = evaluator.generate_excel_export(stats)

    print("\n📄 Generating PDF file...")
    pdf_file = evaluator.generate_pdf_export(stats)

    print("\n📊 Generating interactive charts...")
    chart_files = evaluator.generate_evaluation_charts(stats)

    if chart_files:
        print(f"✅ Generated {len(chart_files)} charts")

    print("\n📋 Generating comprehensive evaluation report...")
    report_file = evaluator.generate_evaluation_report(stats, chart_files)

    if report_file:
        print(f"\n{'=' * 70}")
        print("✅ Evaluation Complete ".center(70, "="))
        print(f"{'=' * 70}")
        print(f"\n📄 HTML Report: {report_file}")
        print(f"📈 Excel File: {excel_file}")
        print(f"📊 PDF File: {pdf_file}")
        print(f"\n🌐 Open the HTML file in your browser to view the report")

        input("\n⏎ Press Enter to close charts and exit...")
        plt.close('all')

    evaluator.disconnect()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n⏹️  Evaluation interrupted by user")
        plt.close('all')
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback

        traceback.print_exc()