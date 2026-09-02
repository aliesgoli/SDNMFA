"""Bilingual executive dashboard for an SDN-MFA multi-campaign report."""

from __future__ import annotations

import html
from typing import Any, Dict, Iterable, Mapping, Sequence

from config.experiment_protocol import POLICY_ORDER, POLICY_SPECS, SCENARIO_SPECS


PERSIAN_SCENARIOS = {
    "unauthorized_access": "دسترسی مستقیم بدون مجوز",
    "ip_spoofing": "جعل نشانی مبدأ IP",
    "ip_mac_spoofing": "جعل هم‌زمان IP و MAC",
    "arp_mitm": "مسموم‌سازی ARP و حمله مرد میانی",
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


def _e(value: Any) -> str:
    return html.escape(str(value))


def _scenario_label(value: Any, persian: bool) -> str:
    key = str(value)
    if persian:
        return PERSIAN_SCENARIOS.get(key, key)
    return str(SCENARIO_SPECS.get(key, {}).get("display_name", key))


def _policy_label(value: Any, persian: bool) -> str:
    key = str(value)
    if persian:
        return PERSIAN_POLICIES.get(key, key)
    return str(POLICY_SPECS.get(key, {}).get("label", key))


def _intensity_label(value: Any, persian: bool) -> str:
    key = str(value)
    return PERSIAN_INTENSITIES.get(key, key) if persian else key.title()


def _yes(value: Any, persian: bool) -> str:
    if persian:
        return "بله" if value else "خیر"
    return "yes" if value else "no"


def _percent(value: Any) -> str:
    try:
        return "%.1f%%" % float(value)
    except (TypeError, ValueError, OverflowError):
        return "N/A"


def _interval(value: Any, low: Any, high: Any, unit: str = "") -> str:
    try:
        point = float(value)
    except (TypeError, ValueError, OverflowError):
        return "N/A"
    try:
        return "%.2f%s [%.2f–%.2f]" % (point, unit, float(low), float(high))
    except (TypeError, ValueError, OverflowError):
        return "%.2f%s" % (point, unit)


def _rate_interval(row: Mapping[str, Any]) -> str:
    value = row.get("resistance_percent")
    if value is None:
        return "N/A"
    return _interval(
        value,
        row.get("resistance_ci95_low"),
        row.get("resistance_ci95_high"),
        "%",
    )


def _table(headers: Sequence[str], rows: Iterable[Sequence[Any]], persian: bool) -> str:
    body = list(rows)
    if not body:
        return '<div class="empty">%s</div>' % _e(
            "داده‌ای ثبت نشده است" if persian else "No recorded data"
        )
    heading = "".join("<th>%s</th>" % _e(value) for value in headers)
    rendered = "".join(
        "<tr>%s</tr>"
        % "".join("<td>%s</td>" % _e(value) for value in row)
        for row in body
    )
    return (
        '<div class="table-scroll"><table><thead><tr>%s</tr></thead>'
        "<tbody>%s</tbody></table></div>" % (heading, rendered)
    )


def _validation_failures(summary: Mapping[str, Any]) -> list[str]:
    stored = summary.get("scientific_validation")
    if isinstance(stored, Mapping) and isinstance(stored.get("failure_codes"), list):
        return [str(value) for value in stored["failure_codes"]]
    failures = []
    if not summary.get("complete", False):
        failures.append("suite_incomplete")
    if int(summary.get("technical_error_task_n") or 0):
        failures.append("technical_errors_present")
    if int(summary.get("incomplete_task_n") or 0):
        failures.append("tasks_incomplete")
    if int(summary.get("invalid_nontechnical_task_n") or 0):
        failures.append("invalid_tasks_present")
    if not summary.get("all_manifest_integrity_valid", False):
        failures.append("manifest_integrity_invalid")
    if not summary.get("all_authentication_evidence_complete", False):
        failures.append("authentication_evidence_incomplete")
    if summary.get("evidence_integrity_valid") is False:
        failures.append("artifact_integrity_invalid")
    return failures


def render_aggregate_dashboard(
    summary: Mapping[str, Any],
    *,
    persian: bool = False,
    charts: Mapping[str, Mapping[str, str]] | None = None,
) -> str:
    charts = dict(charts or {})
    language = "fa" if persian else "en"
    direction = "rtl" if persian else "ltr"
    scenario_rows = list(summary.get("scenario_rows") or [])
    campaign_rows = list(summary.get("campaign_rows") or [])
    policy_rows = list(summary.get("policy_rows") or [])
    block_rows = list(summary.get("block_rows") or [])
    block_summary_rows = list(summary.get("block_summary_rows") or [])
    detail_rows = list(summary.get("scenario_intensity_policy_rows") or [])
    verifier_rows = list(summary.get("software_verifier_conformance_rows") or [])
    factor_resistance_rows = list(
        summary.get("factor_compromise_resistance_rows") or []
    )
    technical_rows = list(summary.get("technical_error_rows") or [])
    failures = _validation_failures(summary)
    scientific_ready = not failures

    planned = sum(int(row.get("planned_n") or 0) for row in campaign_rows)
    recorded = int(summary.get("recorded_task_n") or 0)
    valid = int(summary.get("valid_task_n") or 0)
    technical = int(summary.get("technical_error_task_n") or 0)
    comparable_blocks = sum(
        int(row.get("comparable_valid_block_n") or 0) for row in block_summary_rows
    )
    total_blocks = len(block_rows) or sum(
        int(row.get("block_n") or 0) for row in block_summary_rows
    )
    scenario_n = len({str(row.get("scenario")) for row in scenario_rows})
    policy_n = len({str(row.get("policy")) for row in policy_rows}) or len(POLICY_ORDER)
    intensity_n = len(
        {str(row.get("intensity")) for row in summary.get("scenario_intensity_rows", [])}
    )
    repetitions = sorted(
        {str(row.get("repetitions")) for row in campaign_rows if row.get("repetitions") is not None}
    )
    topologies = sorted({str(row.get("topology_id")) for row in campaign_rows if row.get("topology_id")})
    bindings = sorted({str(row.get("binding_profile")) for row in campaign_rows if row.get("binding_profile")})
    seeds = sorted({str(row.get("seed")) for row in campaign_rows if row.get("seed") is not None})
    protocols = sorted({str(row.get("protocol_id")) for row in campaign_rows if row.get("protocol_id")})
    release_label = str(summary.get("release_label") or "v2")
    auth_observations = sum(int(row.get("observation_n") or 0) for row in verifier_rows)
    pcap_expected = sum(int(row.get("pcap_expected_n") or 0) for row in campaign_rows)
    pcap_verified = sum(int(row.get("pcap_verified_n") or 0) for row in campaign_rows)

    if persian:
        title = "گزارش جامع ارزیابی سامانه SDN-MFA"
        subtitle = "معماری احراز هویت چندعاملی، اعمال مجوز در شبکه تعریف‌شده با نرم‌افزار و شواهد آزمایشگاهی"
        status_title = (
            "کنترل‌های درونی این اجرای آزمایش با موفقیت عبور کرده‌اند"
            if scientific_ready
            else "مجموعه داده هنوز برای نتیجه‌گیری نهایی پایان‌نامه آماده نیست"
        )
        status_detail = (
            "تکمیل اجرا، اعتبار رکوردها، شواهد احراز هویت و تمامیت فایل‌ها تأیید شده است؛ دامنه تعمیم همچنان به طراحی آزمایش محدود است."
            if scientific_ready
            else "گزارش تولید شده است، اما خطا یا نقص زیر باید پیش از استناد نهایی برطرف و آزمایش مربوط تکرار شود."
        )
        failure_labels = {
            "suite_incomplete": "حداقل یک کارزار از نظر علمی کامل نیست",
            "technical_errors_present": "%s وظیفه دارای خطای فنی است" % technical,
            "tasks_incomplete": "وظایف ناتمام وجود دارد",
            "invalid_tasks_present": "رکورد نامعتبر غیرفنی وجود دارد",
            "manifest_integrity_invalid": "تمامیت مانیفست تأیید نشده است",
            "authentication_evidence_incomplete": "شواهد احراز هویت کامل نیست",
            "artifact_integrity_invalid": "تمامیت artifactها تأیید نشده است",
        }
        section_system = "سامانه در یک نگاه"
        primary_title = "نتیجه اصلی مقایسه سیاست‌های MFA"
        primary_subtitle = "مقاومت در سه وضعیت کنترل‌شده افشای جزئی عوامل؛ مستقل از اعمال شبکه"
        primary_takeaway = (
            "Full MFA تنها سیاستی بود که هر سه وضعیت افشای جزئی عوامل را کاملاً مسدود کرد. "
            "اگر همه عوامل پیاده‌سازی‌شده افشا شوند، هیچ‌یک از چهار سیاست مقاوم نیست."
        )
        section_design = "طرح آزمایش و دامنه شواهد"
        section_findings = "نتیجه هر سناریو در یک نگاه"
        section_charts = "نمودارهای علمی و قابل استفاده در پایان‌نامه"
        section_tables = "جداول شواهد و ممیزی"
        system_note = (
            "عامل‌ها هویت کاربر را می‌سنجند؛ پس از احراز موفق، کنترلر یک مجوز کوتاه‌عمر با اتصال IP، MAC و پورت ورودی ثبت می‌کند. "
            "Ryu/OpenFlow دسترسی به سرویس محافظت‌شده را اعمال و همه اجراها در PostgreSQL، PCAP و بسته شواهد ثبت می‌شوند."
        )
        no_difference = (
            "در داده معتبر فعلی، تفاوت مشاهده‌شده‌ای میان چهار سیاست در پیامد شبکه‌ای وجود ندارد. این موضوع با اتصال شبکه یکسان سازگار است، "
            "اما هم‌ارزی سیاست‌ها یا بی‌فایده بودن عامل اضافی را اثبات نمی‌کند."
        )
        verifier_warning = (
            "بایومتریک این نسخه یک نمونه نرم‌افزاری با تطبیق دقیق است. بنابراین ROC، AUC، FAR، FRR، EER، آستانه تشابه و تشخیص زنده‌بودن "
            "از این داده قابل استنتاج نیست. منحنی‌های این گزارش، شدت–پاسخ شبکه و دسترس‌پذیری‌اند، نه ROC بایومتریک."
        )
        evidence_warning = (
            "اعتبار checksum نشان می‌دهد فایل ثبت‌شده دستکاری یا مفقود نشده است؛ این شاخص به‌تنهایی موفقیت حمله یا دفاع را ثابت نمی‌کند. "
            "نرخ‌ها فقط از وظایف معتبر و قابل‌ارزیابی محاسبه شده‌اند و هیچ خطای فنی به صفر یا موفقیت دفاع تبدیل نشده است."
        )
    else:
        title = "Comprehensive SDN-MFA Evaluation Report"
        subtitle = "Multi-factor authentication architecture, software-defined enforcement, and reproducible laboratory evidence"
        status_title = (
            "Internal validation controls passed for this experiment run"
            if scientific_ready
            else "The dataset is not yet ready for final thesis inference"
        )
        status_detail = (
            "Execution completeness, record validity, authentication evidence, and artifact integrity passed; generalization remains bounded by the experimental design."
            if scientific_ready
            else "The report was generated, but the condition(s) below require correction and a repeat experiment before final citation."
        )
        failure_labels = {
            "suite_incomplete": "At least one campaign is scientifically incomplete",
            "technical_errors_present": "%s tasks contain technical errors" % technical,
            "tasks_incomplete": "Incomplete tasks are present",
            "invalid_tasks_present": "Non-technical invalid records are present",
            "manifest_integrity_invalid": "Manifest integrity is not verified",
            "authentication_evidence_incomplete": "Authentication evidence is incomplete",
            "artifact_integrity_invalid": "Artifact integrity is not verified",
        }
        section_system = "System at a glance"
        primary_title = "Primary MFA policy comparison"
        primary_subtitle = "Resistance across three controlled partial-factor compromise states, independent of network enforcement"
        primary_takeaway = (
            "Full MFA was the only policy that completely blocked all three partial-factor compromise states. "
            "No policy resists the positive control in which every implemented factor is available."
        )
        section_design = "Experimental design and evidence scope"
        section_findings = "Scenario findings at a glance"
        section_charts = "Thesis-ready scientific figures"
        section_tables = "Evidence and audit tables"
        system_note = (
            "The factors verify user identity. After successful MFA, the controller records a short-lived authorization bound to source IP, MAC, and ingress port. "
            "Ryu/OpenFlow enforces access to the protected service; PostgreSQL, PCAP, and evidence exports preserve each observation."
        )
        no_difference = (
            "No observed difference appears among the four policies in the currently valid network outcomes. This is consistent with the common network binding, "
            "but it does not establish policy equivalence or make additional factors redundant."
        )
        verifier_warning = (
            "The biometric factor is an exact-match software sample. Consequently, ROC, AUC, FAR, FRR, EER, similarity thresholds, and liveness cannot be inferred. "
            "The curves in this report are network intensity–response and availability curves, not biometric ROC curves."
        )
        evidence_warning = (
            "Checksum validity shows that recorded artifacts are present and unchanged; it does not by itself prove attack or defense success. Rates use valid, evaluable tasks only; "
            "technical errors remain separate and none is converted into a zero or a successful defense outcome."
        )

    failure_list = "".join(
        "<li>%s</li>" % _e(failure_labels.get(code, code)) for code in failures
    )
    status_html = (
        '<section class="status %s"><div class="status-icon">%s</div><div><h2>%s</h2><p>%s</p>%s</div></section>'
        % (
            "pass" if scientific_ready else "fail",
            "✓" if scientific_ready else "!",
            _e(status_title),
            _e(status_detail),
            "" if not failure_list else "<ul>%s</ul>" % failure_list,
        )
    )

    resistance_by_policy = {
        str(row.get("policy")): row for row in factor_resistance_rows
    }
    comparison_cards = "".join(
        '<article class="comparison-card %s"><h3>%s</h3><strong>%s</strong>'
        '<p>%s</p><small>%s</small></article>'
        % (
            "full" if policy == "password_otp_biometric" else "",
            _e(_policy_label(policy, persian)),
            _e(
                "%s/%s"
                % (
                    int(resistance_by_policy.get(policy, {}).get("fully_resisted_state_n") or 0),
                    int(resistance_by_policy.get(policy, {}).get("compromise_state_n") or 0),
                )
            ),
            _e(
                "وضعیت افشای جزئی کاملاً مسدودشده"
                if persian
                else "partial-compromise states fully resisted"
            ),
            _e(
                "%s · %s/%s"
                % (
                    _percent(resistance_by_policy.get(policy, {}).get("resistance_percent")),
                    int(resistance_by_policy.get(policy, {}).get("blocked_authentication_n") or 0),
                    int(resistance_by_policy.get(policy, {}).get("observation_n") or 0),
                )
            ),
        )
        for policy in POLICY_ORDER
    )

    factors = {
        "password_only": ("P",),
        "password_otp": ("P", "O"),
        "password_biometric": ("P", "B"),
        "password_otp_biometric": ("P", "O", "B"),
    }
    policy_cards = "".join(
        '<article class="policy"><div class="factor-row">%s</div><h3>%s</h3><p>%s</p></article>'
        % (
            "".join('<span class="factor %s">%s</span>' % (letter.lower(), letter) for letter in factors[policy]),
            _e(_policy_label(policy, persian)),
            _e(
                (
                    "دروازه احراز هویت نرم‌افزاری؛ پس از موفقیت، همان اتصال شبکه کنترل‌شده اعمال می‌شود."
                    if persian
                    else "Software authentication gate; after success, the same controlled network binding is enforced."
                )
            ),
        )
        for policy in POLICY_ORDER
    )

    flow_nodes = (
        (("کاربر / عامل آزمایش", "Client / experiment operator"), ("ورودی گذرواژه، OTP و نمونه شبیه‌سازی‌شده", "Password, OTP, and simulated-sample input")),
        (("راستی‌آزمای MFA", "MFA verifier"), ("کنترل عوامل لازم مطابق یکی از چهار سیاست", "Required-factor verification under one of four policies")),
        (("مجوز کوتاه‌عمر", "Short-lived authorization"), ("اتصال IP + MAC + پورت ورودی و زمان انقضا", "IP + MAC + ingress-port binding with expiry")),
        (("کنترلر Ryu / OpenFlow", "Ryu / OpenFlow controller"), ("تصمیم allow/deny و ثبت رخدادهای رد", "Allow/deny decision and denial-event recording")),
        (("شبکه Mininet", "Mininet network"), ("توپولوژی چندسوئیچی و سرویس HTTP محافظت‌شده", "Multi-switch topology and protected HTTP service")),
        (("شواهد بازتولیدپذیر", "Reproducible evidence"), ("PostgreSQL، مانیفست، نمونه منابع، PCAP و گزارش", "PostgreSQL, manifest, resources, PCAP, and report")),
    )
    flow_html = "".join(
        '<article class="flow-node"><span class="step">%s</span><h3>%s</h3><p>%s</p></article>'
        % (index, _e(labels[0] if persian else labels[1]), _e(descriptions[0] if persian else descriptions[1]))
        for index, (labels, descriptions) in enumerate(flow_nodes, start=1)
    )

    design_cards = (
        (("سناریو", "Scenarios"), scenario_n),
        (("سطح شدت", "Intensity levels"), intensity_n or 3),
        (("سیاست MFA", "MFA policies"), policy_n),
        (("تکرار در هر شدت", "Repetitions per intensity"), ", ".join(repetitions) or "N/A"),
        (("وظیفه برنامه‌ریزی‌شده", "Planned tasks"), planned or recorded),
        (("بلوک جفت‌شده", "Paired blocks"), total_blocks),
        (("مشاهده معتبر", "Valid observations"), "%s / %s" % (valid, recorded)),
        (("بلوک قابل‌مقایسه", "Comparable blocks"), "%s / %s" % (comparable_blocks, total_blocks)),
        (("مشاهده راستی‌آزما", "Verifier observations"), auth_observations),
        (("PCAP تأییدشده", "Verified PCAP"), "%s / %s" % (pcap_verified, pcap_expected) if pcap_expected else "N/A"),
    )
    design_html = "".join(
        '<div class="metric"><small>%s</small><strong>%s</strong></div>'
        % (_e(label[0] if persian else label[1]), _e(value))
        for label, value in design_cards
    )

    scenario_cards = []
    for row in scenario_rows:
        valid_n = int(row.get("valid_n") or 0)
        tech_n = int(row.get("technical_error_n") or 0)
        adverse_n = int(row.get("adverse_outcome_n") or 0)
        if valid_n == 0:
            state = "na"
            value = "N/A"
            explanation = (
                "%s خطای فنی؛ نتیجه امنیتی محاسبه نشده است" % tech_n
                if persian
                else "%s technical errors; no security rate computed" % tech_n
            )
        else:
            value = _percent(row.get("resistance_percent"))
            state = "good" if adverse_n == 0 else "warn"
            explanation = (
                "%s مقاوم/پایدار، %s نامطلوب، n=%s" % (row.get("resisted_n", 0), adverse_n, valid_n)
                if persian
                else "%s resisted/preserved, %s adverse, n=%s" % (row.get("resisted_n", 0), adverse_n, valid_n)
            )
        scenario_cards.append(
            '<article class="scenario %s"><div class="scenario-top"><h3>%s</h3><strong>%s</strong></div><p>%s</p><small>95%% CI: %s</small></article>'
            % (state, _e(_scenario_label(row.get("scenario"), persian)), _e(value), _e(explanation), _e(_rate_interval(row)))
        )
    scenario_html = "".join(scenario_cards)

    chart_order = (
        "factor_compromise_resistance",
        "factor_conformance",
        "authentication_cost",
        "evidence_quality",
        "scenario_forest",
        "intensity_response",
        "paired_blocks",
        "availability_phases",
        "network_performance",
        "resource_and_load",
        "technical_errors",
    )
    figure_html = []
    for slug in chart_order:
        chart = charts.get(slug)
        if not chart:
            continue
        figure_html.append(
            '<figure class="figure %s"><a href="%s" target="_blank" rel="noopener"><img src="%s" alt="%s" loading="lazy"></a>'
            '<figcaption><h3>%s</h3><p>%s</p><div class="downloads"><a href="%s">PNG 300dpi</a><a href="%s">SVG</a><a href="%s">PDF</a></div></figcaption></figure>'
            % (
                "wide" if slug in {"factor_compromise_resistance", "intensity_response", "paired_blocks"} else "",
                _e(chart.get("png", "")),
                _e(chart.get("png", "")),
                _e(chart.get("title", slug)),
                _e(chart.get("title", slug)),
                _e(chart.get("caption", "")),
                _e(chart.get("png", "")),
                _e(chart.get("svg", "")),
                _e(chart.get("pdf", "")),
            )
        )
    if figure_html:
        charts_html = '<div class="figure-grid">%s</div>' % "".join(figure_html)
    else:
        charts_html = '<div class="empty">%s</div>' % _e(
            "نمودارها در این فراخوانی تولید نشده‌اند." if persian else "Charts were not generated for this invocation."
        )

    campaign_table = _table(
        (
            ("کارزار", "سناریو", "وضعیت اجرا", "برنامه", "ثبت", "معتبر", "خطای فنی", "کامل علمی", "نتیجه قابل ارزیابی", "تمامیت شواهد")
            if persian
            else ("Campaign", "Scenario", "Execution status", "Planned", "Recorded", "Valid", "Technical", "Scientifically complete", "Outcome evaluable", "Evidence integrity")
        ),
        (
            (
                row.get("campaign_id"),
                _scenario_label(row.get("scenario"), persian),
                row.get("status"),
                row.get("planned_n"),
                row.get("recorded_n"),
                row.get("valid_n"),
                row.get("technical_error_n"),
                _yes(row.get("strictly_complete", row.get("campaign_complete")), persian),
                _yes(row.get("outcome_evaluable", int(row.get("valid_n") or 0) > 0), persian),
                _yes(row.get("evidence_integrity_valid", True), persian),
            )
            for row in campaign_rows
        ),
        persian,
    )
    scenario_table = _table(
        (
            ("سناریو", "کارزار", "بلوک", "ثبت", "معتبر", "خطای فنی", "مقاوم/پایدار", "نامطلوب", "نرخ و CI ۹۵٪")
            if persian
            else ("Scenario", "Campaigns", "Blocks", "Recorded", "Valid", "Technical", "Resisted/preserved", "Adverse", "Rate and 95% CI")
        ),
        (
            (
                _scenario_label(row.get("scenario"), persian),
                row.get("campaign_n"),
                row.get("block_n"),
                row.get("recorded_n"),
                row.get("valid_n"),
                row.get("technical_error_n"),
                row.get("resisted_n"),
                row.get("adverse_outcome_n"),
                _rate_interval(row),
            )
            for row in scenario_rows
        ),
        persian,
    )
    detail_table = _table(
        (
            ("سناریو", "شدت", "سیاست", "ثبت", "معتبر", "خطای فنی", "مقاوم", "نامطلوب", "نرخ")
            if persian
            else ("Scenario", "Intensity", "Policy", "Recorded", "Valid", "Technical", "Resisted", "Adverse", "Rate")
        ),
        (
            (
                _scenario_label(row.get("scenario"), persian),
                _intensity_label(row.get("intensity"), persian),
                _policy_label(row.get("policy"), persian),
                row.get("recorded_n"),
                row.get("valid_n"),
                row.get("technical_error_n"),
                row.get("resisted_n"),
                row.get("adverse_outcome_n"),
                _percent(row.get("resistance_percent")),
            )
            for row in detail_rows
        ),
        persian,
    )
    block_table = _table(
        (
            ("سناریو", "شدت", "بلوک", "کامل", "قابل‌مقایسه", "غیرقابل‌مقایسه", "همگی مقاوم", "همگی نامطلوب", "مختلط")
            if persian
            else ("Scenario", "Intensity", "Blocks", "Complete", "Comparable", "Not comparable", "All resisted", "All adverse", "Mixed")
        ),
        (
            (
                _scenario_label(row.get("scenario"), persian),
                _intensity_label(row.get("intensity"), persian),
                row.get("block_n"),
                row.get("complete_recorded_block_n"),
                row.get("comparable_valid_block_n"),
                row.get("not_comparable_block_n"),
                row.get("unanimous_resisted_block_n"),
                row.get("unanimous_adverse_block_n"),
                row.get("mixed_policy_outcome_block_n"),
            )
            for row in block_summary_rows
        ),
        persian,
    )
    verifier_table = _table(
        (
            ("وضعیت عوامل", "سیاست", "مشاهده", "موفق", "درصد موفقیت", "میانگین تأخیر [CI ۹۵٪]", "میانگین CPU [CI ۹۵٪]")
            if persian
            else ("Factor condition", "Policy", "Observations", "Succeeded", "Success rate", "Mean latency [95% CI]", "Mean CPU [95% CI]")
        ),
        (
            (
                PERSIAN_AUTH.get(str(row.get("scenario")), row.get("scenario_label")) if persian else row.get("scenario_label"),
                _policy_label(row.get("policy"), persian),
                row.get("observation_n"),
                row.get("authentication_success_n"),
                _percent(row.get("authentication_success_percent")),
                _interval(row.get("mean_latency_ms"), row.get("ci95_latency_low_ms"), row.get("ci95_latency_high_ms"), " ms"),
                _interval(row.get("mean_cpu_percent"), row.get("ci95_cpu_low_percent"), row.get("ci95_cpu_high_percent"), "%"),
            )
            for row in verifier_rows
        ),
        persian,
    )
    factor_resistance_table = _table(
        (
            ("سیاست", "وضعیت‌های بررسی‌شده", "مقاومت کامل", "تلاش", "مسدود", "موفق", "نرخ مقاومت و CI ۹۵٪")
            if persian
            else ("Policy", "States evaluated", "Fully resisted", "Attempts", "Blocked", "Succeeded", "Resistance and 95% CI")
        ),
        (
            (
                _policy_label(row.get("policy"), persian),
                row.get("compromise_state_n"),
                row.get("fully_resisted_state_n"),
                row.get("observation_n"),
                row.get("blocked_authentication_n"),
                row.get("successful_authentication_n"),
                _rate_interval(row),
            )
            for row in factor_resistance_rows
        ),
        persian,
    )
    error_table = _table(
        (
            ("سناریو", "نوع خطا", "وظیفه", "بلوک درگیر", "کارزار")
            if persian
            else ("Scenario", "Error type", "Tasks", "Affected blocks", "Campaigns")
        ),
        (
            (
                _scenario_label(row.get("scenario"), persian),
                row.get("error_type"),
                row.get("task_n"),
                row.get("affected_block_n"),
                row.get("campaign_n"),
            )
            for row in technical_rows
        ),
        persian,
    )

    metadata = " · ".join(
        filter(
            None,
            (
                str(summary.get("aggregate_id") or ""),
                "protocol=%s" % ",".join(protocols) if protocols else "",
                "release=%s" % release_label,
                "topology=%s" % ",".join(topologies) if topologies else "",
                "binding=%s" % ",".join(bindings) if bindings else "",
                "seed=%s" % ",".join(seeds) if seeds else "",
            ),
        )
    )

    return """<!doctype html>
<html lang="%s" dir="%s"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>%s</title><style>
:root{--navy:#081d35;--navy2:#123b65;--blue:#2563eb;--teal:#0f766e;--green:#059669;--amber:#d97706;--red:#dc2626;--violet:#7c3aed;--ink:#172033;--muted:#64748b;--line:#d9e3ef;--paper:#eef3f8;--white:#fff}
*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;background:var(--paper);color:var(--ink);font-family:Segoe UI,Tahoma,Arial,sans-serif;line-height:1.55}.page{max-width:1540px;margin:auto;padding:20px}
.hero{position:relative;overflow:hidden;background:radial-gradient(circle at 85%% 10%%,#2c6aa3 0,#173f6b 28%%,#081d35 72%%);color:#fff;border-radius:24px;padding:34px 38px;box-shadow:0 18px 50px #081d3530}.hero:after{content:"";position:absolute;width:320px;height:320px;border:1px solid #ffffff18;border-radius:50%%;inset-inline-end:-90px;top:-150px;box-shadow:0 0 0 48px #ffffff08,0 0 0 96px #ffffff06}.eyebrow{text-transform:uppercase;letter-spacing:.14em;font-size:11px;color:#93c5fd;font-weight:800}.hero h1{position:relative;z-index:1;font-size:clamp(27px,3vw,46px);line-height:1.15;margin:8px 0}.hero p{position:relative;z-index:1;max-width:980px;margin:0;color:#dbeafe;font-size:16px}.meta{position:relative;z-index:1;margin-top:15px;font:12px ui-monospace,SFMono-Regular,Consolas,monospace;color:#bfdbfe;overflow-wrap:anywhere}
.status{display:grid;grid-template-columns:54px 1fr;gap:16px;margin:18px 0;padding:18px 22px;border-radius:17px;border:1px solid}.status.pass{background:#ecfdf5;border-color:#86efac}.status.fail{background:#fff1f2;border-color:#fda4af}.status-icon{display:grid;place-items:center;width:48px;height:48px;border-radius:50%%;font-size:27px;font-weight:900;color:#fff}.pass .status-icon{background:var(--green)}.fail .status-icon{background:var(--red)}.status h2{margin:0;color:var(--ink);font-size:19px}.status p{margin:3px 0}.status ul{margin:7px 0 0;padding-inline-start:21px;color:#991b1b;font-weight:650}
.executive{background:#fff;border:1px solid var(--line);border-radius:20px;padding:24px;margin-top:18px;box-shadow:0 6px 24px #081d350c}.section-head{display:flex;align-items:end;justify-content:space-between;gap:12px;margin:28px 0 13px}.section-head h2{margin:0;color:var(--navy);font-size:25px}.section-head p{margin:0;color:var(--muted);font-size:13px}
.comparison-hero{background:linear-gradient(135deg,#ecfdf5,#f0f9ff);border:1px solid #86efac;border-radius:20px;padding:24px;margin-top:18px}.comparison-hero h2{margin:0;color:var(--navy);font-size:25px}.comparison-hero>p{margin:4px 0 16px;color:var(--muted)}.comparison-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px}.comparison-card{background:#fff;border:1px solid var(--line);border-top:5px solid #64748b;border-radius:15px;padding:16px}.comparison-card.full{border-top-color:var(--green);box-shadow:0 8px 26px #05966918}.comparison-card h3{margin:0;color:var(--navy);font-size:14px}.comparison-card strong{display:block;font-size:32px;color:var(--navy);margin:6px 0 0}.comparison-card p{margin:0;color:#475569;font-size:12px}.comparison-card small{display:block;margin-top:8px;color:var(--muted)}.comparison-takeaway{margin-top:15px;padding:13px 15px;background:#064e3b;color:#ecfdf5;border-radius:12px;font-weight:700}
.flow{display:grid;grid-template-columns:repeat(6,minmax(0,1fr));gap:10px;position:relative}.flow:before{content:"";position:absolute;top:24px;inset-inline:6%%;height:3px;background:linear-gradient(90deg,#60a5fa,#34d399);z-index:0}.flow-node{position:relative;z-index:1;background:#f8fbff;border:1px solid #cfe0f3;border-radius:15px;padding:13px 12px;min-height:150px}.step{display:grid;place-items:center;width:28px;height:28px;border-radius:50%%;background:var(--navy2);color:white;font-weight:800;margin-bottom:12px}.flow-node h3{font-size:14px;margin:0 0 6px;color:var(--navy)}.flow-node p{font-size:12px;color:var(--muted);margin:0}.system-note,.science-note{margin:14px 0 0;border-inline-start:5px solid var(--blue);padding:13px 15px;background:#eff6ff;border-radius:10px}.science-note.warn{border-inline-start-color:var(--amber);background:#fff7ed}.science-note.limit{border-inline-start-color:var(--violet);background:#f5f3ff}
.policies{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin-top:14px}.policy{border:1px solid var(--line);border-radius:15px;padding:14px;background:#fff}.policy h3{font-size:14px;margin:10px 0 6px;color:var(--navy)}.policy p{font-size:11.5px;color:var(--muted);margin:0}.factor-row{display:flex;gap:6px}.factor{display:grid;place-items:center;width:31px;height:31px;border-radius:9px;color:white;font-weight:900}.factor.p{background:#334155}.factor.o{background:#2563eb}.factor.b{background:#d97706}
.metrics{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:10px}.metric{background:#fff;border:1px solid var(--line);border-radius:14px;padding:14px}.metric small{display:block;color:var(--muted);font-weight:650;font-size:11.5px}.metric strong{display:block;color:var(--navy);font-size:23px;margin-top:3px}.protocol-strip{margin-top:12px;padding:12px 15px;background:#0f2744;color:#dbeafe;border-radius:12px;font:12px ui-monospace,SFMono-Regular,Consolas,monospace;overflow-wrap:anywhere}
.scenario-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px}.scenario{background:#fff;border:1px solid var(--line);border-top:5px solid var(--green);border-radius:14px;padding:14px}.scenario.warn{border-top-color:var(--amber)}.scenario.na{border-top-color:var(--red);background:#fffafb}.scenario-top{display:flex;justify-content:space-between;align-items:start;gap:12px}.scenario h3{margin:0;color:var(--navy);font-size:14px}.scenario strong{font-size:24px;color:var(--green)}.scenario.warn strong{color:var(--amber)}.scenario.na strong{color:var(--red)}.scenario p{font-size:12px;margin:8px 0;color:#475569}.scenario small{color:var(--muted)}
.finding-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:13px}.finding{background:#fff;border:1px solid var(--line);border-radius:14px;padding:15px}.finding h3{margin:0 0 6px;color:var(--navy);font-size:15px}.finding p{margin:0;color:#475569;font-size:13px}
.figure-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:16px}.figure{margin:0;background:#fff;border:1px solid var(--line);border-radius:17px;overflow:hidden;box-shadow:0 6px 22px #081d350b}.figure.wide{grid-column:1/-1}.figure>a{display:block;background:#f8fafc;border-bottom:1px solid var(--line)}.figure img{display:block;width:100%%;height:auto}.figure figcaption{padding:15px 17px}.figure h3{margin:0 0 5px;color:var(--navy);font-size:16px}.figure p{margin:0;color:#475569;font-size:12.5px}.downloads{display:flex;gap:8px;margin-top:10px}.downloads a{color:var(--blue);background:#eff6ff;text-decoration:none;border-radius:8px;padding:5px 9px;font-size:11px;font-weight:700}
.audit details{background:#fff;border:1px solid var(--line);border-radius:13px;margin:10px 0;overflow:hidden}.audit summary{cursor:pointer;padding:14px 16px;color:var(--navy);font-weight:750;background:#f8fafc}.table-scroll{max-height:480px;overflow:auto}table{width:100%%;border-collapse:collapse;min-width:900px}th{position:sticky;top:0;background:var(--navy);color:white;text-align:start;z-index:1}th,td{padding:10px 11px;border-bottom:1px solid var(--line);font-size:11.5px}tr:nth-child(even) td{background:#f8fafc}.empty{padding:18px;color:var(--muted);background:#fff;border:1px dashed #cbd5e1;border-radius:13px}.footer{padding:28px 4px;color:var(--muted);font-size:11.5px}.structured{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;overflow-wrap:anywhere}
@media(max-width:1100px){.flow{grid-template-columns:repeat(3,1fr)}.flow:before{display:none}.metrics{grid-template-columns:repeat(2,1fr)}.scenario-grid,.comparison-grid{grid-template-columns:repeat(2,1fr)}}
@media(max-width:720px){.page{padding:10px}.hero{padding:25px 20px;border-radius:17px}.flow,.policies,.scenario-grid,.comparison-grid,.finding-grid,.figure-grid{grid-template-columns:1fr}.figure.wide{grid-column:auto}.status{grid-template-columns:1fr}.metrics{grid-template-columns:repeat(2,1fr)}}
@media print{@page{size:A4;margin:12mm}body{background:#fff}.page{max-width:none;padding:0}.hero,.executive,.figure{box-shadow:none}.hero{border-radius:10px}.status{break-inside:avoid}.executive{break-after:page}.figure{break-inside:avoid;page-break-inside:avoid}.figure-grid{display:block}.figure{margin:0 0 14mm}.downloads{display:none}.audit details{break-inside:avoid}.audit details:not([open])>*:not(summary){display:block}.table-scroll{max-height:none;overflow:visible}th{position:static}}
</style></head><body><main class="page">
<header class="hero"><div class="eyebrow">SDN-MFA · RELEASE V2 · THESIS EVIDENCE</div><h1>%s</h1><p>%s</p><div class="meta">%s</div></header>
%s
<section class="comparison-hero"><h2>%s</h2><p>%s</p><div class="comparison-grid">%s</div><div class="comparison-takeaway">%s</div></section>
<section class="executive"><div class="section-head"><div><h2>%s</h2><p>%s</p></div></div><div class="flow">%s</div><div class="system-note">%s</div><div class="policies">%s</div></section>
<div class="section-head"><div><h2>%s</h2><p>%s</p></div></div><section class="metrics">%s</section><div class="protocol-strip">%s</div>
<div class="section-head"><div><h2>%s</h2><p>%s</p></div></div><section class="scenario-grid">%s</section>
<section class="finding-grid"><article class="finding"><h3>%s</h3><p>%s</p></article><article class="finding"><h3>%s</h3><p>%s</p></article></section>
<div class="science-note">%s</div><div class="science-note warn"><strong>%s</strong><br>%s</div><div class="science-note limit"><strong>%s</strong><br>%s</div>
<div class="section-head"><div><h2>%s</h2><p>%s</p></div></div>%s
<div class="section-head"><div><h2>%s</h2><p>%s</p></div></div><section class="audit">
<details open><summary>%s</summary>%s</details><details open><summary>%s</summary>%s</details><details open><summary>%s</summary>%s</details><details><summary>%s</summary>%s</details><details><summary>%s</summary>%s</details><details><summary>%s</summary>%s</details><details><summary>%s</summary>%s</details>
</section><footer class="footer">%s</footer></main></body></html>""" % (
        language, direction, _e(title), _e(title), _e(subtitle), _e(metadata),
        status_html,
        _e(primary_title), _e(primary_subtitle), comparison_cards, _e(primary_takeaway),
        _e(section_system), _e("مسیر تصمیم، اعمال و ثبت شواهد" if persian else "Decision, enforcement, and evidence path"), flow_html, _e(system_note), policy_cards,
        _e(section_design), _e("طرح متوازن ۶ × ۳ × ۵ × ۴ با ورودی‌های جفت‌شده" if persian else "Balanced 6 × 3 × 5 × 4 design with paired inputs"), design_html, _e(metadata),
        _e(section_findings), _e("N/A هرگز به صفر تبدیل نشده است" if persian else "N/A is never converted into zero"), scenario_html,
        _e("برداشت شبکه‌ای" if persian else "Network interpretation"), _e(no_difference),
        _e("حد اعتبار بایومتریک" if persian else "Biometric validity boundary"), _e(verifier_warning),
        _e(evidence_warning),
        _e("محدودیت مقایسه سیاست‌ها" if persian else "Policy-comparison limitation"), _e(no_difference),
        _e("مرز علمی نمودار curve" if persian else "Scientific boundary for curve figures"), _e(verifier_warning),
        _e(section_charts), _e("همراه با PNG 300dpi و نسخه برداری SVG/PDF و caption روش‌شناختی" if persian else "Includes 300 dpi PNG, vector SVG/PDF, and methodological captions"), charts_html,
        _e(section_tables), _e("جزئیات کامل بدون شلوغ‌کردن صفحه نخست" if persian else "Complete detail without crowding the executive page"),
        _e("اعتبار و تکمیل کارزارها" if persian else "Campaign validity and completion"), campaign_table,
        _e("مقایسه امنیت MFA در افشای جزئی عوامل" if persian else "MFA security under partial-factor compromise"), factor_resistance_table,
        _e("خلاصه سناریوها" if persian else "Scenario summary"), scenario_table,
        _e("سناریو × شدت × سیاست" if persian else "Scenario × intensity × policy"), detail_table,
        _e("بلوک‌های جفت‌شده" if persian else "Paired blocks"), block_table,
        _e("Software verifier conformance" if not persian else "انطباق راستی‌آزمای نرم‌افزاری"), verifier_table,
        _e("خطاهای فنی" if persian else "Technical errors"), error_table,
        _e("فایل‌های داده ساخت‌یافته در data/، فهرست شکل‌ها در data/chart_manifest.* و نسخه‌های برداری در assets/charts/ قرار دارند." if persian else "Structured data files are under data/, the figure registry is data/chart_manifest.*, and vector figures are under assets/charts/.")
    )
