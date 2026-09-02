"""Thesis-quality static figures for the multi-campaign SDN-MFA report.

Every figure is exported as a 300 dpi PNG for convenient review and as SVG
and PDF for lossless use in a dissertation.  Figures deliberately preserve
missing/non-evaluable cells as N/A; technical errors are never plotted as a
zero security or availability rate.
"""

from __future__ import annotations

import csv
import json
import math
import os
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Sequence, Tuple

os.environ.setdefault("MPLBACKEND", "Agg")
os.environ.setdefault("MPLCONFIGDIR", "/tmp/sdnmfa_matplotlib_cache")
import matplotlib.pyplot as plt

try:
    import arabic_reshaper
    from bidi.algorithm import get_display as bidi_display
except ImportError:  # pragma: no cover - enforced by project preflight
    arabic_reshaper = None
    bidi_display = None

from config.experiment_protocol import (
    AUTH_SCENARIO_ORDER,
    AUTH_SCENARIO_SPECS,
    INTENSITY_ORDER,
    POLICY_ORDER,
    POLICY_SPECS,
    SCENARIO_SPECS,
)


POLICY_COLORS = {
    "password_only": "#334155",
    "password_otp": "#2563eb",
    "password_biometric": "#d97706",
    "password_otp_biometric": "#059669",
}
POLICY_MARKERS = {
    "password_only": "o",
    "password_otp": "s",
    "password_biometric": "D",
    "password_otp_biometric": "^",
}
SCENARIO_COLORS = {
    "unauthorized_access": "#1d4ed8",
    "ip_spoofing": "#7c3aed",
    "ip_mac_spoofing": "#c026d3",
    "arp_mitm": "#dc2626",
    "dos_udp_flood": "#0f766e",
    "ddos_udp_flood": "#ea580c",
}
PERSIAN_SCENARIOS = {
    "unauthorized_access": "دسترسی مستقیم بدون مجوز",
    "ip_spoofing": "جعل نشانی مبدأ IP",
    "ip_mac_spoofing": "جعل هم‌زمان IP و MAC",
    "arp_mitm": "مسموم‌سازی ARP و مرد میانی",
    "dos_udp_flood": "سیلاب UDP تک‌مبدأ",
    "ddos_udp_flood": "سیلاب UDP چندمبدأ",
}
PERSIAN_POLICIES = {
    "password_only": "فقط گذرواژه",
    "password_otp": "گذرواژه + OTP",
    "password_biometric": "گذرواژه + بایومتریک شبیه‌سازی‌شده",
    "password_otp_biometric": "احراز هویت کامل چندعاملی",
}
PERSIAN_INTENSITIES = {"low": "کم", "medium": "متوسط", "high": "زیاد"}
PERSIAN_AUTH = {
    "valid_factors": "عوامل معتبر کاربر",
    "password_compromised": "فقط گذرواژه در دسترس",
    "password_and_otp_compromised": "گذرواژه و OTP در دسترس",
    "password_and_biometric_compromised": "گذرواژه و بایومتریک در دسترس",
    "all_factors_compromised": "همه عوامل در دسترس",
}


def _shape(value: Any, persian: bool) -> str:
    text = str(value)
    if not persian:
        return text
    if arabic_reshaper is None or bidi_display is None:
        raise RuntimeError(
            "Persian charts require arabic-reshaper and python-bidi. "
            "Run the report with ./venv/bin/python."
        )
    return bidi_display(arabic_reshaper.reshape(text), base_dir="R")


def _scenario_label(key: Any, persian: bool) -> str:
    value = str(key)
    if persian:
        return PERSIAN_SCENARIOS.get(value, value)
    return str(SCENARIO_SPECS.get(value, {}).get("display_name", value))


def _policy_label(key: Any, persian: bool) -> str:
    value = str(key)
    if persian:
        return PERSIAN_POLICIES.get(value, value)
    return str(POLICY_SPECS.get(value, {}).get("label", value))


def _intensity_label(key: Any, persian: bool) -> str:
    value = str(key)
    return PERSIAN_INTENSITIES.get(value, value) if persian else value.title()


def _style() -> None:
    plt.rcParams.update(
        {
            "font.family": "DejaVu Sans",
            "font.size": 10.5,
            "axes.titlesize": 13,
            "axes.labelsize": 11,
            "axes.edgecolor": "#94a3b8",
            "axes.spines.top": False,
            "axes.spines.right": False,
            "axes.grid": True,
            "grid.alpha": 0.18,
            "figure.facecolor": "white",
            "axes.facecolor": "white",
            "savefig.facecolor": "white",
        }
    )


def _finite(value: Any) -> bool:
    try:
        return math.isfinite(float(value))
    except (TypeError, ValueError, OverflowError):
        return False


def _error(values: Sequence[float], lows: Sequence[Any], highs: Sequence[Any]) -> List[List[float]]:
    lower: List[float] = []
    upper: List[float] = []
    for value, low, high in zip(values, lows, highs):
        lower.append(max(0.0, value - float(low)) if _finite(low) else 0.0)
        upper.append(max(0.0, float(high) - value) if _finite(high) else 0.0)
    return [lower, upper]


def _no_data(axis: Any, persian: bool, message: str | None = None) -> None:
    text = message or ("دادهٔ قابل‌ارزیابی موجود نیست" if persian else "No evaluable data")
    axis.text(
        0.5,
        0.5,
        _shape(text, persian),
        transform=axis.transAxes,
        ha="center",
        va="center",
        color="#64748b",
        fontsize=12,
        fontweight="bold",
    )
    axis.set_xticks([])
    axis.set_yticks([])
    axis.grid(False)


def _save_formats(fig: Any, chart_dir: Path, slug: str) -> Tuple[Dict[str, str], List[Path]]:
    paths: Dict[str, str] = {}
    files: List[Path] = []
    for extension in ("png", "svg", "pdf"):
        path = chart_dir / (slug + "." + extension)
        options = {"bbox_inches": "tight"}
        if extension == "png":
            options["dpi"] = 300
        fig.savefig(path, **options)
        paths[extension] = "assets/charts/%s" % path.name
        files.append(path)
    plt.close(fig)
    return paths, files


def save_aggregate_charts(
    summary: Mapping[str, Any],
    chart_dir: Path,
    data_dir: Path,
    *,
    persian: bool = False,
) -> Tuple[Dict[str, Dict[str, str]], List[Path]]:
    """Create aggregate figures, their vector versions, and a caption manifest."""
    if persian:
        _shape("کنترل نوشتار فارسی", True)
    _style()
    chart_dir.mkdir(parents=True, exist_ok=True)
    data_dir.mkdir(parents=True, exist_ok=True)
    charts: Dict[str, Dict[str, str]] = {}
    generated: List[Path] = []
    manifest: List[Dict[str, Any]] = []

    def register(
        slug: str,
        fig: Any,
        *,
        title_fa: str,
        title_en: str,
        caption_fa: str,
        caption_en: str,
        data_source: str,
        population: str,
        uncertainty: str,
        exclusions: str,
    ) -> None:
        paths, files = _save_formats(fig, chart_dir, slug)
        generated.extend(files)
        title = title_fa if persian else title_en
        caption = caption_fa if persian else caption_en
        charts[slug] = {**paths, "title": title, "caption": caption}
        manifest.append(
            {
                "figure_id": slug,
                "title": title,
                "caption": caption,
                "population": population,
                "uncertainty": uncertainty,
                "exclusions": exclusions,
                "data_source": data_source,
                **paths,
            }
        )

    # Primary comparison: controlled partial-factor compromise resistance.
    factor_resistance_rows = list(
        summary.get("factor_compromise_resistance_rows") or []
    )
    fig, axis = plt.subplots(figsize=(13.2, 6.7))
    if factor_resistance_rows:
        rows_by_policy = {
            str(row.get("policy")): row for row in factor_resistance_rows
        }
        rows = [rows_by_policy[p] for p in POLICY_ORDER if p in rows_by_policy]
        labels = [
            _shape(_policy_label(row.get("policy"), persian), persian)
            for row in rows
        ]
        values = [float(row.get("resistance_percent") or 0.0) for row in rows]
        y = list(range(len(rows)))
        colors = [POLICY_COLORS[str(row.get("policy"))] for row in rows]
        bars = axis.barh(y, values, color=colors, height=0.58)
        axis.set_yticks(y, labels)
        axis.invert_yaxis()
        axis.set_xlim(0, 108)
        axis.set_xlabel(
            _shape(
                "درصد تلاش‌های مسدودشده در سه وضعیت افشای جزئی عوامل"
                if persian
                else "Blocked attempts across three partial-factor compromise states (%)",
                persian,
            )
        )
        for bar, row, value in zip(bars, rows, values):
            state_text = "%s/%s" % (
                int(row.get("fully_resisted_state_n") or 0),
                int(row.get("compromise_state_n") or 0),
            )
            label = "%.1f%%  ·  %s" % (value, state_text)
            axis.text(
                min(value + 1.2, 101.0),
                bar.get_y() + bar.get_height() / 2,
                label,
                va="center",
                fontweight="bold",
                color="#0f172a",
            )
        axis.axvline(100, color="#0f172a", linewidth=0.8, alpha=0.25)
    else:
        _no_data(axis, persian)
    axis.set_title(
        _shape(
            "مقایسه امنیت سیاست‌های MFA در افشای جزئی عوامل"
            if persian
            else "MFA policy security under partial-factor compromise",
            persian,
        ),
        fontweight="bold",
    )
    fig.tight_layout()
    register(
        "factor_compromise_resistance",
        fig,
        title_fa="مقاومت سیاست‌های MFA در افشای جزئی عوامل",
        title_en="MFA resistance to partial-factor compromise",
        caption_fa=(
            "در سه وضعیت کنترل‌شده—افشای فقط گذرواژه، گذرواژه+OTP و "
            "گذرواژه+بایومتریک شبیه‌سازی‌شده—Full MFA تنها سیاستی بود که "
            "همه تلاش‌ها را رد کرد. این آزمون شبیه‌سازی افشای عوامل است، نه آزمون فیشینگ میدانی."
        ),
        caption_en=(
            "Across three controlled states—password only, password+OTP, and "
            "password+simulated biometric—Full MFA was the only policy to reject "
            "every attempt. This is a factor-compromise simulation, not a field phishing test."
        ),
        data_source="data/aggregate_factor_compromise_resistance.csv",
        population="valid_controlled_partial_factor_compromise_observations",
        uncertainty="wilson_95_interval_available_in_backing_csv",
        exclusions="valid_factor_control_and_all_factors_compromised_positive_control",
    )

    # Mutually exclusive evidence-quality classes.
    quality_rows = list(summary.get("quality_rows") or [])
    if not quality_rows:
        quality_rows = [
            {
                "scenario": row.get("scenario"),
                "recorded_n": row.get("recorded_n", 0),
                "valid_evaluable_n": row.get("valid_n", 0),
                "technical_error_n": row.get("technical_error_n", 0),
                "incomplete_n": row.get("incomplete_n", 0),
                "invalid_nontechnical_n": row.get("invalid_nontechnical_n", 0),
                "excluded_campaign_evidence_n": row.get(
                    "excluded_campaign_evidence_n", 0
                ),
            }
            for row in summary.get("scenario_rows", [])
        ]
    fig, axis = plt.subplots(figsize=(13.2, 6.4))
    labels = [_shape(_scenario_label(row.get("scenario"), persian), persian) for row in quality_rows]
    y = list(range(len(labels)))
    left = [0.0] * len(labels)
    quality_series = (
        ("valid_evaluable_n", "معتبر و قابل‌ارزیابی", "Valid and evaluable", "#059669"),
        ("technical_error_n", "خطای فنی", "Technical error", "#dc2626"),
        ("incomplete_n", "ناتمام", "Incomplete", "#d97706"),
        ("invalid_nontechnical_n", "نامعتبر دیگر", "Other invalid", "#64748b"),
        ("excluded_campaign_evidence_n", "حذف به علت شواهد", "Excluded evidence", "#7c3aed"),
    )
    for field, label_fa, label_en, color in quality_series:
        values = [float(row.get(field) or 0) for row in quality_rows]
        axis.barh(y, values, left=left, color=color, label=_shape(label_fa if persian else label_en, persian))
        left = [base + value for base, value in zip(left, values)]
    for index, total in enumerate(left):
        axis.text(total + max(left or [1]) * 0.01, index, "n=%s" % int(total), va="center", color="#334155")
    axis.set_yticks(y, labels)
    axis.invert_yaxis()
    axis.set_xlabel(_shape("تعداد وظایف" if persian else "Task count", persian))
    axis.set_title(_shape("کیفیت و قابلیت استفاده از شواهد به تفکیک سناریو" if persian else "Evidence quality and usability by scenario", persian))
    axis.legend(ncol=3, frameon=False, loc="lower center", bbox_to_anchor=(0.5, -0.22))
    fig.tight_layout()
    register(
        "evidence_quality",
        fig,
        title_fa="کیفیت داده به تفکیک سناریو",
        title_en="Evidence quality by scenario",
        caption_fa="طبقه‌بندی‌های مانعةالجمعِ تمام وظایف ثبت‌شده. خطاهای فنی و داده‌های حذف‌شده وارد مخرج نرخ امنیتی نشده‌اند.",
        caption_en="Mutually exclusive classes for all recorded tasks. Technical errors and excluded evidence do not enter security-rate denominators.",
        data_source="data/aggregate_data_quality.csv",
        population="all_recorded_tasks",
        uncertainty="not_applicable_counts",
        exclusions="none_from_quality_counts",
    )

    # 2. Scenario forest plot. Missing rates remain visibly N/A.
    scenario_rows = list(summary.get("scenario_rows") or [])
    fig, axis = plt.subplots(figsize=(12.4, 7.0))
    labels = [_shape(_scenario_label(row.get("scenario"), persian), persian) for row in scenario_rows]
    y = list(range(len(scenario_rows)))
    for index, row in enumerate(scenario_rows):
        value = row.get("resistance_percent")
        if _finite(value):
            point = float(value)
            low = row.get("resistance_ci95_low")
            high = row.get("resistance_ci95_high")
            axis.errorbar(
                [point], [index],
                xerr=_error([point], [low], [high]),
                fmt="o", markersize=8, capsize=5, linewidth=2.2,
                color=SCENARIO_COLORS.get(str(row.get("scenario")), "#2563eb"),
            )
            axis.text(min(103.0, point + 1.3), index, "n=%s" % int(row.get("valid_n") or 0), va="center", fontsize=9)
        else:
            axis.scatter([50], [index], marker="x", s=85, color="#dc2626", linewidths=2.4)
            label = "N/A · tech=%s" % int(row.get("technical_error_n") or 0)
            axis.text(52, index, label, va="center", color="#b91c1c", fontweight="bold")
    axis.axvline(50, color="#cbd5e1", linewidth=1, linestyle="--")
    axis.set_yticks(y, labels)
    axis.invert_yaxis()
    axis.set_xlim(0, 110)
    axis.set_xlabel(_shape("پیامد مقاوم یا حفظ خدمت (درصد)" if persian else "Resisted or service-preserved outcome (%)", persian))
    axis.set_title(_shape("نرخ توصیفی هر سناریو با بازه اطمینان ۹۵٪ Wilson" if persian else "Scenario-level descriptive rate with 95% Wilson interval", persian))
    fig.tight_layout()
    register(
        "scenario_forest",
        fig,
        title_fa="Forest plot مقاومت و تداوم خدمت",
        title_en="Forest plot of resistance and service continuity",
        caption_fa="نرخ و بازه Wilson فقط از وظایف معتبر محاسبه شده است. N/A به معنی نبود دادهٔ قابل‌ارزیابی است، نه مقاومت صفر.",
        caption_en="Rates and Wilson intervals use valid tasks only. N/A denotes no evaluable observations, not zero resistance.",
        data_source="data/aggregate_scenarios.csv",
        population="valid_evaluable_tasks_by_scenario",
        uncertainty="task_level_wilson_95_descriptive_not_block_adjusted",
        exclusions="technical_incomplete_invalid_and_campaign_evidence_excluded",
    )

    # 3. Connected observed intensity points; no fitted/smoothed curve.
    response_rows = list(summary.get("scenario_intensity_policy_rows") or [])
    scenario_keys = [str(row.get("scenario")) for row in scenario_rows]
    fig, axes = plt.subplots(2, 3, figsize=(17.2, 9.5), sharex=True, sharey=True)
    for axis, scenario in zip(axes.flat, scenario_keys):
        any_evaluable = False
        for policy in POLICY_ORDER:
            matches = {
                str(row.get("intensity")): row
                for row in response_rows
                if str(row.get("scenario")) == scenario and str(row.get("policy")) == policy
            }
            xs: List[int] = []
            values: List[float] = []
            lows: List[Any] = []
            highs: List[Any] = []
            for index, intensity in enumerate(INTENSITY_ORDER):
                row = matches.get(intensity)
                if row is None or not _finite(row.get("resistance_percent")):
                    continue
                any_evaluable = True
                xs.append(index)
                values.append(float(row["resistance_percent"]))
                lows.append(row.get("resistance_ci95_low"))
                highs.append(row.get("resistance_ci95_high"))
            if values:
                axis.errorbar(
                    xs, values, yerr=_error(values, lows, highs),
                    marker=POLICY_MARKERS[policy], markersize=6.5,
                    linewidth=2.0, capsize=3,
                    color=POLICY_COLORS[policy], label=_shape(_policy_label(policy, persian), persian),
                )
        axis.set_title(_shape(_scenario_label(scenario, persian), persian), fontweight="bold")
        axis.set_xticks(range(len(INTENSITY_ORDER)), [_shape(_intensity_label(item, persian), persian) for item in INTENSITY_ORDER])
        axis.set_ylim(-4, 108)
        if not any_evaluable:
            tech = next((row.get("technical_error_n", 0) for row in scenario_rows if str(row.get("scenario")) == scenario), 0)
            _no_data(axis, persian, "N/A — %s خطای فنی" % tech if persian else "N/A — %s technical errors" % tech)
    for axis in axes[:, 0]:
        axis.set_ylabel(_shape("پیامد مقاوم/پایدار (%)" if persian else "Resisted/preserved outcome (%)", persian))
    for axis in axes[-1, :]:
        axis.set_xlabel(_shape("شدت تعریف‌شده" if persian else "Declared intensity", persian))
    handles, legend_labels = axes.flat[0].get_legend_handles_labels()
    if handles:
        fig.legend(handles, legend_labels, ncol=4, frameon=False, loc="lower center", bbox_to_anchor=(0.5, -0.01))
    fig.suptitle(_shape("منحنی شدت–پاسخ مشاهده‌شده؛ نقاط به‌صورت خطی متصل‌اند و برازش نشده‌اند" if persian else "Observed intensity–response curves; connected points, no fitted model", persian), fontsize=16, fontweight="bold")
    fig.tight_layout(rect=(0, 0.05, 1, 0.96))
    register(
        "intensity_response",
        fig,
        title_fa="منحنی شدت–پاسخ به تفکیک سناریو و سیاست",
        title_en="Intensity–response curves by scenario and policy",
        caption_fa="سه نقطهٔ کم، متوسط و زیاد فقط برای خوانایی به هم متصل شده‌اند؛ هیچ مدل هموار یا روند پیوسته برازش نشده است. بازه‌ها Wilson و توصیفی‌اند.",
        caption_en="Low, medium, and high observations are connected for readability only; no continuous or smoothed model is fitted. Intervals are descriptive Wilson intervals.",
        data_source="data/aggregate_scenario_intensity_policy.csv",
        population="valid_evaluable_tasks_within_scenario_intensity_policy",
        uncertainty="task_level_wilson_95_descriptive_not_block_adjusted",
        exclusions="non_evaluable_cells_rendered_as_na",
    )

    # 4. Paired-block outcome/comparability profile.
    block_rows = list(summary.get("block_summary_rows") or [])
    fig, axes = plt.subplots(2, 3, figsize=(16.8, 9.0), sharey=True)
    categories = (
        ("unanimous_resisted_block_n", "همگی مقاوم", "All resisted", "#059669"),
        ("unanimous_adverse_block_n", "همگی نامطلوب", "All adverse", "#dc2626"),
        ("mixed_policy_outcome_block_n", "مختلط", "Mixed", "#d97706"),
        ("not_comparable_block_n", "غیرقابل‌مقایسه", "Not comparable", "#94a3b8"),
    )
    for axis, scenario in zip(axes.flat, scenario_keys):
        rows = {str(row.get("intensity")): row for row in block_rows if str(row.get("scenario")) == scenario}
        bottoms = [0.0] * len(INTENSITY_ORDER)
        for field, label_fa, label_en, color in categories:
            values = [float(rows.get(level, {}).get(field, 0) or 0) for level in INTENSITY_ORDER]
            axis.bar(range(len(INTENSITY_ORDER)), values, bottom=bottoms, color=color, label=_shape(label_fa if persian else label_en, persian))
            bottoms = [base + value for base, value in zip(bottoms, values)]
        axis.set_title(_shape(_scenario_label(scenario, persian), persian), fontweight="bold")
        axis.set_xticks(range(len(INTENSITY_ORDER)), [_shape(_intensity_label(level, persian), persian) for level in INTENSITY_ORDER])
    for axis in axes[:, 0]:
        axis.set_ylabel(_shape("تعداد بلوک sample_id" if persian else "sample_id blocks", persian))
    handles, legend_labels = axes.flat[0].get_legend_handles_labels()
    if handles:
        fig.legend(handles, legend_labels, ncol=4, frameon=False, loc="lower center", bbox_to_anchor=(0.5, -0.01))
    fig.suptitle(_shape("پیامد و قابلیت مقایسه در بلوک‌های جفت‌شده" if persian else "Outcome and comparability of paired blocks", persian), fontsize=16, fontweight="bold")
    fig.tight_layout(rect=(0, 0.05, 1, 0.96))
    register(
        "paired_blocks",
        fig,
        title_fa="ساختار بلوک‌های جفت‌شده",
        title_en="Paired-block structure",
        caption_fa="هر بلوک یک sample_id مشترک برای چهار سیاست است. بلوک غیرقابل‌مقایسه از تحلیل زوجی کنار گذاشته می‌شود.",
        caption_en="Each block is one sample_id shared by four policies. Non-comparable blocks are excluded from paired analysis.",
        data_source="data/aggregate_block_summary.csv",
        population="all_sample_id_blocks",
        uncertainty="not_applicable_counts",
        exclusions="none_from_block_quality_counts",
    )

    # 5. Controlled factor-availability verifier heatmap.
    verifier_rows = list(summary.get("software_verifier_conformance_rows") or [])
    auth_scenarios = [
        scenario for scenario in AUTH_SCENARIO_ORDER
        if any(str(row.get("scenario")) == scenario for row in verifier_rows)
    ]
    fig, axis = plt.subplots(figsize=(13.2, 7.2))
    if auth_scenarios and verifier_rows:
        matrix: List[List[float]] = []
        counts: List[List[int]] = []
        for scenario in auth_scenarios:
            matrix_row: List[float] = []
            count_row: List[int] = []
            for policy in POLICY_ORDER:
                match = next((row for row in verifier_rows if str(row.get("scenario")) == scenario and str(row.get("policy")) == policy), None)
                matrix_row.append(float(match.get("authentication_success_percent")) if match and _finite(match.get("authentication_success_percent")) else float("nan"))
                count_row.append(int(match.get("observation_n") or 0) if match else 0)
            matrix.append(matrix_row)
            counts.append(count_row)
        image = axis.imshow(matrix, cmap="RdYlGn", vmin=0, vmax=100, aspect="auto")
        axis.set_xticks(range(len(POLICY_ORDER)), [_shape(_policy_label(policy, persian), persian) for policy in POLICY_ORDER], rotation=12)
        axis.set_yticks(range(len(auth_scenarios)), [_shape(PERSIAN_AUTH.get(scenario, scenario) if persian else AUTH_SCENARIO_SPECS.get(scenario, {}).get("label", scenario), persian) for scenario in auth_scenarios])
        for row_index, values in enumerate(matrix):
            for column_index, value in enumerate(values):
                label = "N/A" if not _finite(value) else "%.0f%%\nn=%s" % (value, counts[row_index][column_index])
                axis.text(column_index, row_index, label, ha="center", va="center", fontweight="bold", color="#0f172a", fontsize=9)
        fig.colorbar(image, ax=axis, label=_shape("موفقیت راستی‌آزمایی (%)" if persian else "Verifier success (%)", persian))
    else:
        _no_data(axis, persian)
    axis.set_title(_shape("انطباق راستی‌آزمای نرم‌افزاری در شرایط کنترل‌شدهٔ عوامل" if persian else "Software verifier conformance under controlled factor availability", persian))
    fig.tight_layout()
    register(
        "factor_conformance",
        fig,
        title_fa="Heatmap دسترس‌پذیری عوامل MFA",
        title_en="MFA factor-availability heatmap",
        caption_fa="این شکل فقط منطق راستی‌آزمای نرم‌افزاری را می‌سنجد؛ آزمون حسگر زیستی، FAR/FRR/EER یا تشخیص زنده‌بودن نیست.",
        caption_en="This figure measures software verifier logic only; it is not a biometric sensor, FAR/FRR/EER, or liveness evaluation.",
        data_source="data/aggregate_software_verifier_conformance.csv",
        population="valid_campaign_software_verifier_observations",
        uncertainty="cell_percentages_counts_shown",
        exclusions="campaigns_with_invalid_authentication_evidence",
    )

    # 6. Valid-factor authentication latency and CPU-equivalent cost.
    valid_factor_rows = [row for row in verifier_rows if str(row.get("scenario")) == "valid_factors"]
    fig, axes = plt.subplots(1, 2, figsize=(15.8, 6.2))
    cost_specs = (
        ("mean_latency_ms", "ci95_latency_low_ms", "ci95_latency_high_ms", "تأخیر راستی‌آزمایی (ms)", "Verifier latency (ms)"),
        ("mean_cpu_percent", "ci95_cpu_low_percent", "ci95_cpu_high_percent", "CPU معادل دیواری (%)", "Wall-normalized CPU equivalent (%)"),
    )
    for axis, (value_key, low_key, high_key, label_fa, label_en) in zip(axes, cost_specs):
        plotted = False
        for index, policy in enumerate(POLICY_ORDER):
            row = next((item for item in valid_factor_rows if str(item.get("policy")) == policy), None)
            if row is None or not _finite(row.get(value_key)):
                continue
            plotted = True
            value = float(row[value_key])
            axis.errorbar([index], [value], yerr=_error([value], [row.get(low_key)], [row.get(high_key)]), fmt=POLICY_MARKERS[policy], markersize=9, capsize=5, linewidth=2.2, color=POLICY_COLORS[policy])
            axis.text(index, value, "  n=%s" % int(row.get("observation_n") or 0), va="bottom", fontsize=8)
        axis.set_xticks(range(len(POLICY_ORDER)), [_shape(_policy_label(policy, persian), persian) for policy in POLICY_ORDER], rotation=14)
        axis.set_ylabel(_shape(label_fa if persian else label_en, persian))
        if not plotted:
            _no_data(axis, persian)
    axes[0].set_title(_shape("تأخیر با بازه اطمینان t برابر ۹۵٪" if persian else "Latency with 95% t interval", persian))
    axes[1].set_title(_shape("هزینه CPU با بازه اطمینان t برابر ۹۵٪" if persian else "CPU cost with 95% t interval", persian))
    fig.suptitle(_shape("هزینه راستی‌آزمایی MFA در حالت عوامل معتبر" if persian else "MFA verifier cost when required factors are valid", persian), fontsize=16, fontweight="bold")
    fig.tight_layout(rect=(0, 0, 1, 0.94))
    register(
        "authentication_cost",
        fig,
        title_fa="تأخیر و هزینه CPU در MFA",
        title_en="MFA latency and CPU cost",
        caption_fa="نقطه میانگین و میله بازه اطمینان t برابر ۹۵٪ است. CPU مقدار معادل نرمال‌شده با زمان دیواری است و مصرف پایدار سامانه تلقی نمی‌شود.",
        caption_en="Points are means and whiskers are 95% t intervals. CPU is a wall-normalized equivalent, not sustained system utilization.",
        data_source="data/aggregate_software_verifier_conformance.csv",
        population="valid_factors_software_verifier_observations",
        uncertainty="student_t_95_interval",
        exclusions="invalid_authentication_evidence_and_non_valid_factor_conditions",
    )

    # 7. Block-adjusted availability phases for flood scenarios.
    availability_rows = list(summary.get("availability_phase_rows") or [])
    flood_scenarios = [scenario for scenario in ("dos_udp_flood", "ddos_udp_flood") if any(str(row.get("scenario")) == scenario for row in availability_rows)]
    fig, axes = plt.subplots(1, 2, figsize=(15.8, 6.4), sharey=True)
    for axis_index, axis in enumerate(axes):
        if axis_index >= len(flood_scenarios):
            _no_data(axis, persian)
            continue
        scenario = flood_scenarios[axis_index]
        plotted = False
        for intensity, color, marker in zip(INTENSITY_ORDER, ("#38bdf8", "#2563eb", "#7c3aed"), ("o", "s", "^")):
            rows = {str(row.get("phase")): row for row in availability_rows if str(row.get("scenario")) == scenario and str(row.get("intensity")) == intensity}
            values: List[float] = []
            lows: List[Any] = []
            highs: List[Any] = []
            xs: List[int] = []
            for index, phase in enumerate(("baseline", "during", "recovery")):
                row = rows.get(phase)
                if row is None or not _finite(row.get("mean_availability_percent")):
                    continue
                xs.append(index)
                values.append(float(row["mean_availability_percent"]))
                lows.append(row.get("ci95_availability_low_percent"))
                highs.append(row.get("ci95_availability_high_percent"))
            if values:
                plotted = True
                axis.errorbar(xs, values, yerr=_error(values, lows, highs), color=color, marker=marker, markersize=7, capsize=4, linewidth=2.3, label=_shape(_intensity_label(intensity, persian), persian))
        axis.set_xticks(range(3), [_shape(value, persian) for value in (("پیش از حمله", "حین حمله", "بازیابی") if persian else ("Baseline", "During", "Recovery"))])
        axis.set_ylim(-4, 108)
        axis.set_title(_shape(_scenario_label(scenario, persian), persian), fontweight="bold")
        axis.set_ylabel(_shape("دسترس‌پذیری سرویس (%)" if persian else "Service availability (%)", persian))
        if plotted:
            axis.legend(frameon=False)
        else:
            _no_data(axis, persian)
    fig.suptitle(_shape("منحنی دسترس‌پذیری قبل، حین و پس از سیلاب" if persian else "Service availability before, during, and after flooding", persian), fontsize=16, fontweight="bold")
    fig.tight_layout(rect=(0, 0, 1, 0.94))
    register(
        "availability_phases",
        fig,
        title_fa="منحنی دسترس‌پذیری DoS/DDoS",
        title_en="DoS/DDoS service-availability curve",
        caption_fa="واحد تحلیل، میانگین چهار سیاست در هر بلوک sample_id است؛ نقطه میانگین بلوک‌ها و میله بازه اطمینان t برابر ۹۵٪ است.",
        caption_en="The analysis unit is the four-policy mean within each sample_id block; points are block means with 95% t intervals.",
        data_source="data/aggregate_availability_phases.csv",
        population="comparable_sample_id_block_means",
        uncertainty="student_t_95_interval_across_blocks",
        exclusions="non_comparable_blocks",
    )

    # 8. Block-adjusted network latency and controller CPU across intensity.
    metric_rows = list(summary.get("block_metric_rows") or [])
    fig, axes = plt.subplots(1, 2, figsize=(16.2, 6.6))
    metric_specs = (
        ("legitimate_http_p95_latency_ms", "میانگین P95 تأخیر HTTP مجاز (ms)", "Mean legitimate HTTP p95 latency (ms)"),
        ("controller_cpu_p95_percent", "میانگین P95 پردازنده کنترلر (%)", "Mean controller CPU p95 (%)"),
    )
    for axis, (metric, label_fa, label_en) in zip(axes, metric_specs):
        plotted = False
        for scenario in scenario_keys:
            matches = {str(row.get("intensity")): row for row in metric_rows if str(row.get("scenario")) == scenario and str(row.get("metric")) == metric}
            xs: List[int] = []
            values: List[float] = []
            lows: List[Any] = []
            highs: List[Any] = []
            for index, intensity in enumerate(INTENSITY_ORDER):
                row = matches.get(intensity)
                if row is None or not _finite(row.get("mean")):
                    continue
                xs.append(index)
                values.append(float(row["mean"]))
                lows.append(row.get("ci95_low"))
                highs.append(row.get("ci95_high"))
            if values:
                plotted = True
                axis.errorbar(xs, values, yerr=_error(values, lows, highs), color=SCENARIO_COLORS.get(scenario, "#64748b"), marker="o", linewidth=2, capsize=3, label=_shape(_scenario_label(scenario, persian), persian))
        axis.set_xticks(range(len(INTENSITY_ORDER)), [_shape(_intensity_label(level, persian), persian) for level in INTENSITY_ORDER])
        axis.set_xlabel(_shape("شدت تعریف‌شده" if persian else "Declared intensity", persian))
        axis.set_ylabel(_shape(label_fa if persian else label_en, persian))
        if not plotted:
            _no_data(axis, persian)
    handles, legend_labels = axes[0].get_legend_handles_labels()
    if handles:
        fig.legend(handles, legend_labels, ncol=3, frameon=False, loc="lower center", bbox_to_anchor=(0.5, -0.01))
    fig.suptitle(_shape("نمایه کارایی شبکه و کنترلر بر پایه بلوک‌های قابل‌مقایسه" if persian else "Network and controller performance over comparable blocks", persian), fontsize=16, fontweight="bold")
    fig.tight_layout(rect=(0, 0.08, 1, 0.94))
    register(
        "network_performance",
        fig,
        title_fa="نمایه تأخیر شبکه و CPU کنترلر",
        title_en="Network latency and controller CPU profile",
        caption_fa="هر مقدار ابتدا در چهار سیاست همان بلوک میانگین‌گیری و سپس بین بلوک‌ها خلاصه شده است؛ تأخیر، میانگین P95های اجرای معتبر است و pooled p95 نیست.",
        caption_en="Each value is first averaged across four policies within a block and then summarized across blocks; latency is a mean of valid run-level p95 values, not a pooled p95.",
        data_source="data/aggregate_block_metrics.csv",
        population="comparable_sample_id_block_means",
        uncertainty="student_t_95_interval_across_blocks",
        exclusions="non_comparable_blocks_and_missing_metrics",
    )

    # 9. Controller footprint and delivered-load diagnostics.
    fig, axes = plt.subplots(2, 2, figsize=(16.4, 10.0))
    resource_specs = (
        ("controller_rss_p95_mib", "RSS P95 کنترلر (MiB)", "Controller RSS p95 (MiB)"),
        ("system_cpu_p95_percent", "CPU P95 کل سامانه (%)", "System CPU p95 (%)"),
        ("rate_achievement_percent", "تحقق نرخ بار (%)", "Offered-rate achievement (%)"),
        ("packet_delivery_percent", "تحویل بسته UDP (%)", "UDP packet delivery (%)"),
    )
    for axis, (metric, label_fa, label_en) in zip(axes.flat, resource_specs):
        plotted = False
        for scenario in scenario_keys:
            matches = {
                str(row.get("intensity")): row
                for row in metric_rows
                if str(row.get("scenario")) == scenario
                and str(row.get("metric")) == metric
            }
            xs: List[int] = []
            values: List[float] = []
            lows: List[Any] = []
            highs: List[Any] = []
            for index, intensity in enumerate(INTENSITY_ORDER):
                row = matches.get(intensity)
                if row is None or not _finite(row.get("mean")):
                    continue
                xs.append(index)
                values.append(float(row["mean"]))
                lows.append(row.get("ci95_low"))
                highs.append(row.get("ci95_high"))
            if values:
                plotted = True
                axis.errorbar(
                    xs,
                    values,
                    yerr=_error(values, lows, highs),
                    color=SCENARIO_COLORS.get(scenario, "#64748b"),
                    marker="o",
                    linewidth=2,
                    capsize=3,
                    label=_shape(_scenario_label(scenario, persian), persian),
                )
        axis.set_xticks(
            range(len(INTENSITY_ORDER)),
            [_shape(_intensity_label(level, persian), persian) for level in INTENSITY_ORDER],
        )
        axis.set_xlabel(_shape("شدت تعریف‌شده" if persian else "Declared intensity", persian))
        axis.set_ylabel(_shape(label_fa if persian else label_en, persian))
        axis.set_title(_shape(label_fa if persian else label_en, persian))
        if metric in {"rate_achievement_percent", "packet_delivery_percent"}:
            axis.set_ylim(-4, 108)
        if not plotted:
            _no_data(axis, persian)
    handles, legend_labels = axes.flat[0].get_legend_handles_labels()
    if handles:
        fig.legend(
            handles,
            legend_labels,
            ncol=3,
            frameon=False,
            loc="lower center",
            bbox_to_anchor=(0.5, -0.01),
        )
    fig.suptitle(
        _shape(
            "مصرف منابع کنترلر و تحقق بار شبکه در بلوک‌های معتبر"
            if persian
            else "Controller footprint and delivered-load diagnostics over valid blocks",
            persian,
        ),
        fontsize=16,
        fontweight="bold",
    )
    fig.tight_layout(rect=(0, 0.06, 1, 0.95))
    register(
        "resource_and_load",
        fig,
        title_fa="مصرف حافظه/CPU و تحقق بار",
        title_en="Resource footprint and delivered load",
        caption_fa="مقادیر ابتدا در چهار سیاست هر بلوک میانگین‌گیری شده‌اند. نرخ تحقق بار، صحت مولد ترافیک را نشان می‌دهد و درصد تحویل بسته، اثر ازدحام را؛ این دو معیار نتیجه احراز هویت نیستند.",
        caption_en="Values are first averaged across four policies within each block. Rate achievement validates the traffic generator and packet delivery describes congestion; neither is an authentication outcome.",
        data_source="data/aggregate_block_metrics.csv",
        population="comparable_sample_id_block_means_with_recorded_metric",
        uncertainty="student_t_95_interval_across_blocks",
        exclusions="non_comparable_blocks_and_missing_metrics",
    )

    # 10. Technical-error Pareto; the no-error state remains explicit.
    error_rows = list(summary.get("technical_error_rows") or [])
    if not error_rows:
        error_rows = [
            {
                "scenario": row.get("scenario"),
                "error_type": "unspecified_technical_error",
                "task_n": row.get("technical_error_n", 0),
                "affected_block_n": None,
            }
            for row in scenario_rows
            if int(row.get("technical_error_n") or 0) > 0
        ]
    error_rows.sort(key=lambda row: int(row.get("task_n") or 0), reverse=True)
    fig, axis = plt.subplots(figsize=(13.0, 6.5))
    if error_rows:
        labels = [
            _shape("%s\n%s" % (_scenario_label(row.get("scenario"), persian), row.get("error_type")), persian)
            for row in error_rows
        ]
        values = [int(row.get("task_n") or 0) for row in error_rows]
        positions = list(range(len(values)))
        bars = axis.barh(positions, values, color="#dc2626")
        axis.set_yticks(positions, labels)
        axis.invert_yaxis()
        for bar, row, value in zip(bars, error_rows, values):
            blocks = row.get("affected_block_n")
            suffix = "" if blocks is None else " · %s blocks" % blocks
            axis.text(value + max(values or [1]) * 0.015, bar.get_y() + bar.get_height() / 2, "%s tasks%s" % (value, suffix), va="center", color="#7f1d1d", fontweight="bold")
        axis.set_xlabel(_shape("تعداد وظایف" if persian else "Task count", persian))
    else:
        _no_data(axis, persian, "هیچ خطای فنی ثبت نشده است" if persian else "No technical errors recorded")
    axis.set_title(_shape("تجزیه خطاهای فنی؛ خطا نتیجه امنیتی محسوب نمی‌شود" if persian else "Technical-error breakdown; errors are not security outcomes", persian))
    fig.tight_layout()
    register(
        "technical_errors",
        fig,
        title_fa="نمودار پارتو خطاهای فنی",
        title_en="Technical-error Pareto chart",
        caption_fa="تعداد وظایف و بلوک‌های درگیر برای هر نوع خطا. این موارد N/A هستند و به موفقیت یا شکست دفاع تبدیل نشده‌اند.",
        caption_en="Task and affected-block counts by error type. These observations are N/A and are not converted into defense successes or failures.",
        data_source="data/aggregate_technical_errors.csv",
        population="all_technical_error_tasks",
        uncertainty="not_applicable_counts",
        exclusions="none",
    )

    manifest_fields = [
        "figure_id", "title", "caption", "population", "uncertainty",
        "exclusions", "data_source", "png", "svg", "pdf",
    ]
    csv_path = data_dir / "chart_manifest.csv"
    with csv_path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=manifest_fields)
        writer.writeheader()
        writer.writerows(manifest)
    json_path = data_dir / "chart_manifest.json"
    json_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "figure_n": len(manifest),
                "figures": manifest,
                "scientific_note": (
                    "ROC/AUC/EER are intentionally absent because the recorded software "
                    "biometric verifier has no continuous score or threshold sweep."
                ),
            },
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    generated.extend([csv_path, json_path])
    return charts, generated
