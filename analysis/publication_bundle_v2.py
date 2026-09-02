"""English PDF and bilingual HTML publication outputs for SDN-MFA-V2."""

from __future__ import annotations

import html
from pathlib import Path
from typing import Any, Dict


def _percent(value: Any) -> str:
    return "N/A" if value is None else "%.1f%%" % (100.0 * float(value))


CHART_DESCRIPTIONS = {
    "network": (
        "Each heatmap cell contains 180 valid observations: four MFA policies, "
        "three topologies, three intensities, and five repetitions. Values are "
        "attack-blocking percentages, so higher is better. Network identifiers "
        "remain post-admission binding attributes rather than authentication factors.",
        "هر خانه نقشه حرارتی شامل ۱۸۰ مشاهده معتبر است. مقدارها درصد مسدودسازی "
        "حمله‌اند و مقدار بیشتر بهتر است. شناسه‌های شبکه عامل احراز هویت نیستند و "
        "پس از ورود برای اتصال نشست به شبکه به‌کار می‌روند.",
    ),
    "auth": (
        "The vertical axis is attacker authentication success, so lower is better. "
        "Each displayed policy-attack cell contains 15 valid observations (three "
        "intensities by five repetitions). The descriptive table uses all 13 "
        "non-control attack variants, or 195 observations per policy.",
        "محور عمودی درصد موفقیت مهاجم است و مقدار کمتر بهتر است. هر خانه نمایش‌داده‌شده "
        "۱۵ مشاهده معتبر دارد. جدول توصیفی هر ۱۳ گونه حمله غیرکنترلی و ۱۹۵ مشاهده "
        "برای هر سیاست را به‌کار می‌گیرد.",
    ),
    "availability": (
        "Each point summarizes 80 valid runs (four MFA policies by four bindings by "
        "five repetitions). Error bars are sample standard deviations. Volumetric "
        "DoS and DDoS outcomes are interpreted separately from session admission.",
        "هر نقطه میانگین ۸۰ اجرای معتبر و میله خطا انحراف معیار نمونه است. پیامدهای "
        "حجمی DoS و DDoS جدا از پذیرش نشست تفسیر می‌شوند.",
    ),
    "ecdf": (
        "The ECDF contains 210 latency observations per policy. The horizontal axis "
        "is end-to-end latency in milliseconds and the vertical axis is the cumulative "
        "percentage; a left-shifted curve indicates lower latency.",
        "ECDF برای هر سیاست ۲۱۰ مشاهده دارد. محور افقی تأخیر انتها‌به‌انتها برحسب "
        "میلی‌ثانیه و محور عمودی درصد تجمعی است؛ منحنی چپ‌تر نشان‌دهنده تأخیر کمتر است.",
    ),
    "biometric": (
        "ROC and FAR/FRR use 30 software-simulated genuine scores and 30 impostor "
        "scores. ROC axes are percentages; cosine-similarity threshold is a unitless "
        "number from -1 to 1. An EER of 0.00% describes this simulated score set only "
        "and does not establish physical-sensor accuracy or liveness.",
        "ROC و FAR/FRR از ۳۰ امتیاز واقعی شبیه‌سازی‌شده و ۳۰ امتیاز مهاجم ساخته شده‌اند. "
        "محورهای ROC درصد و آستانه شباهت کسینوسی عددی بدون واحد است. EER صفر فقط به "
        "این مجموعه نرم‌افزاری مربوط است و دقت حسگر یا liveness را اثبات نمی‌کند.",
    ),
    "recovery": (
        "Each point summarizes 240 valid runs across three topologies, four policies, "
        "four bindings, and five repetitions. Availability during load and after load "
        "removal is kept separate from access-control success.",
        "هر نقطه میانگین ۲۴۰ اجرای معتبر در سه توپولوژی، چهار سیاست، چهار اتصال و پنج "
        "تکرار است. دسترس‌پذیری حین بار و پس از توقف آن جدا گزارش می‌شوند.",
    ),
    "chained": (
        "Each point contains 1,920 valid access chains: eight entry conditions, four "
        "bindings, four access scenarios, three topologies, and five repetitions. "
        "Lower is better. Password + OTP and Password + Biometric overlap exactly in "
        "this subset and are distinguished by line style and marker.",
        "هر نقطه شامل ۱۹۲۰ زنجیره دسترسی معتبر است و مقدار کمتر بهتر است. منحنی‌های "
        "Password+OTP و Password+Biometric در این زیرمجموعه دقیقاً هم‌پوشان‌اند و با "
        "سبک خط و نشانگر متفاوت مشخص شده‌اند.",
    ),
}


def _build_english_pdf(
    *,
    data: Dict[str, Any],
    summary: Dict[str, Any],
    charts: Dict[str, Dict[str, str]],
    target: Path,
) -> None:
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER, TA_LEFT
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    from reportlab.platypus import (
        Image,
        PageBreak,
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )

    regular = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
    bold = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
    pdfmetrics.registerFont(TTFont("ReportEN", regular))
    pdfmetrics.registerFont(TTFont("ReportENBold", bold))
    styles = getSampleStyleSheet()
    title = ParagraphStyle(
        "TitleEN", parent=styles["Title"], fontName="ReportENBold",
        fontSize=23, leading=31, alignment=TA_CENTER,
        textColor=colors.HexColor("#123047"),
    )
    heading = ParagraphStyle(
        "HeadingEN", parent=styles["Heading2"], fontName="ReportENBold",
        fontSize=15, leading=21, alignment=TA_LEFT,
        textColor=colors.HexColor("#0B7285"), spaceAfter=5 * mm,
    )
    body = ParagraphStyle(
        "BodyEN", parent=styles["BodyText"], fontName="ReportEN",
        fontSize=9.8, leading=16, textColor=colors.HexColor("#243B53"),
        spaceAfter=3 * mm,
    )

    def footer(canvas, doc):
        canvas.saveState()
        canvas.setStrokeColor(colors.HexColor("#CBD5E1"))
        canvas.line(18 * mm, 14 * mm, A4[0] - 18 * mm, 14 * mm)
        canvas.setFont("ReportEN", 8)
        canvas.setFillColor(colors.HexColor("#64748B"))
        canvas.drawString(
            18 * mm, 9 * mm,
            "SDN-MFA-V2 — %s" % data["study"]["data_status"],
        )
        canvas.drawRightString(A4[0] - 18 * mm, 9 * mm, str(doc.page))
        canvas.restoreState()

    document = SimpleDocTemplate(
        str(target), pagesize=A4, rightMargin=17 * mm, leftMargin=17 * mm,
        topMargin=18 * mm, bottomMargin=19 * mm,
        title="SDN-MFA-V2 Research Report",
    )
    story = [
        Spacer(1, 22 * mm),
        Paragraph(
            "End-to-End Evaluation of Multi-Factor Authentication and "
            "Software-Defined Network Access Control",
            title,
        ),
        Spacer(1, 8 * mm),
        Paragraph(
            "SDN-MFA-V2 — reproducible research protocol report", body
        ),
    ]
    meta = [
        ["Study ID", str(data["study"]["study_id"])],
        ["Protocol", str(data["study"]["protocol_id"])],
        ["Data status", str(data["study"]["data_status"])],
        ["Seed / repetitions", "%s / %s" % (
            data["study"].get("base_seed"), data["study"].get("repetitions")
        )],
    ]
    table = Table(meta, colWidths=[42 * mm, 120 * mm])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#E6F3F5")),
        ("FONTNAME", (0, 0), (-1, -1), "ReportEN"),
        ("FONTSIZE", (0, 0), (-1, -1), 8.7),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#CBD5E1")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story.extend([
        Spacer(1, 7 * mm), table, Spacer(1, 10 * mm),
        Paragraph(
            "The study separates authentication factors from post-admission "
            "IP/MAC/ingress binding. It also measures an end-to-end chain in "
            "which an authentication attack determines whether session-dependent "
            "network activity can proceed.",
            body,
        ),
        PageBreak(),
        Paragraph("Executive summary and data adequacy", heading),
    ])
    completeness = [
        ["Study component", "Valid", "Expected", "Completeness"],
        ["Independent network matrix", summary["valid_network_observations"], summary["expected_network_observations"], "%.1f%%" % summary["network_completeness_percent"]],
        ["Authentication verifier matrix", summary["valid_authentication_observations"], summary["expected_authentication_observations"], "%.1f%%" % summary["authentication_completeness_percent"]],
        ["End-to-end chained matrix", summary["valid_chained_observations"], summary["expected_chained_observations"], "%.1f%%" % summary["chained_completeness_percent"]],
    ]
    table = Table(completeness, colWidths=[62 * mm, 30 * mm, 35 * mm, 40 * mm])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#123047")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, -1), "ReportEN"),
        ("FONTSIZE", (0, 0), (-1, -1), 8.2),
        ("ALIGN", (1, 0), (-1, -1), "CENTER"),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#CBD5E1")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8FAFC")]),
    ]))
    story.extend([
        table, Spacer(1, 6 * mm),
        Paragraph(
            "Among valid access chains, %s were blocked at authentication, %s "
            "were contained after admission, and %s succeeded end to end. These "
            "mutually exclusive outcomes sum to 100%%. Availability degradation is reported "
            "separately because volumetric attacks do not require an application session."
            % (
                _percent(summary.get("chained_access_blocked_at_authentication_rate")),
                _percent(summary.get("chained_contained_after_admission_rate")),
                _percent(summary.get("chained_end_to_end_attack_success_rate")),
            ),
            body,
        ),
        PageBreak(),
    ])

    sections = [
        ("Independent network-binding effectiveness", "network"),
        ("Authentication resilience", "auth"),
        ("Availability by intensity and topology", "availability"),
        ("Authentication latency distribution", "ecdf"),
        ("Software-simulated biometric operating characteristics", "biometric"),
        ("Post-attack service recovery", "recovery"),
        ("End-to-end chained effectiveness", "chained"),
    ]
    for section_title, key in sections:
        story.extend([
            Paragraph(section_title, heading),
            Image(charts[key]["png"], width=165 * mm, height=76 * mm),
            Spacer(1, 3 * mm),
            Paragraph(CHART_DESCRIPTIONS[key][0], body),
            PageBreak(),
        ])

    policy_labels = {
        "password_only": "Password",
        "password_otp": "Password + OTP",
        "password_biometric": "Password + Biometric",
        "password_otp_biometric": "Full MFA",
    }
    policy_table = [[
        "Policy", "Attack success (n=195)", "95% CI",
        "Latency mean +/- SD (n=210), ms",
    ]]
    for policy in (
        "password_only", "password_otp", "password_biometric",
        "password_otp_biometric",
    ):
        row = summary["per_policy_authentication"][policy]
        ci = row["attacker_authentication_success_ci95"]
        policy_table.append([
            policy_labels[policy],
            _percent(row["attacker_authentication_success_rate"]),
            "%.1f-%.1f%%" % (100 * ci[0], 100 * ci[1]),
            "%.2f +/- %.2f" % (row["latency_mean_ms"], row["latency_std_ms"]),
        ])
    table = Table(policy_table, colWidths=[43*mm, 39*mm, 35*mm, 53*mm])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#123047")),
        ("TEXTCOLOR", (0,0), (-1,0), colors.white),
        ("FONTNAME", (0,0), (-1,-1), "ReportEN"),
        ("FONTSIZE", (0,0), (-1,-1), 7.6),
        ("ALIGN", (1,0), (-1,-1), "CENTER"),
        ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
        ("GRID", (0,0), (-1,-1), 0.4, colors.HexColor("#CBD5E1")),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.white, colors.HexColor("#F8FAFC")]),
    ]))
    story.extend([
        Paragraph("Descriptive statistics and paired comparisons", heading),
        table,
        Spacer(1, 5*mm),
    ])
    paired_table = [[
        "Comparison", "Pairs", "Comparator only", "Full only", "Exact p", "Holm p",
    ]]
    for row in summary["paired_authentication_comparisons"]:
        comparator = row["comparison"].split(" vs ", 1)[1]
        paired_table.append([
            "Full MFA vs %s" % policy_labels[comparator],
            row["paired_blocks"], row["comparator_success_full_failure"],
            row["full_success_comparator_failure"],
            "%.4g" % row["mcnemar_p_raw"], "%.4g" % row["mcnemar_p_holm"],
        ])
    table = Table(paired_table, colWidths=[50*mm, 18*mm, 29*mm, 23*mm, 25*mm, 25*mm])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#0B7285")),
        ("TEXTCOLOR", (0,0), (-1,0), colors.white),
        ("FONTNAME", (0,0), (-1,-1), "ReportEN"),
        ("FONTSIZE", (0,0), (-1,-1), 7.0),
        ("ALIGN", (1,0), (-1,-1), "CENTER"),
        ("GRID", (0,0), (-1,-1), 0.4, colors.HexColor("#CBD5E1")),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.white, colors.HexColor("#F8FAFC")]),
    ]))
    story.extend([table, Spacer(1, 4*mm)])
    binding_labels = {
        "ip_only": "IP", "ip_mac": "IP + MAC", "ip_port": "IP + Port",
    }
    binding_table = [[
        "Binding comparison", "Pairs", "Weaker only", "Strict only", "Exact p", "Holm p",
    ]]
    for row in summary["paired_network_binding_comparisons"]:
        comparator = row["comparison"].split(" vs ", 1)[1]
        binding_table.append([
            "IP + MAC + Port vs %s" % binding_labels[comparator],
            row["paired_blocks"], row["comparator_success_strict_failure"],
            row["strict_success_comparator_failure"],
            "%.4g" % row["mcnemar_p_raw"], "%.4g" % row["mcnemar_p_holm"],
        ])
    table = Table(binding_table, colWidths=[50*mm, 18*mm, 29*mm, 23*mm, 25*mm, 25*mm])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#2F5597")),
        ("TEXTCOLOR", (0,0), (-1,0), colors.white),
        ("FONTNAME", (0,0), (-1,-1), "ReportEN"),
        ("FONTSIZE", (0,0), (-1,-1), 7.0),
        ("ALIGN", (1,0), (-1,-1), "CENTER"),
        ("GRID", (0,0), (-1,-1), 0.4, colors.HexColor("#CBD5E1")),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.white, colors.HexColor("#F8FAFC")]),
    ]))
    story.extend([
        table,
        Spacer(1, 3*mm),
        Paragraph(
            "Rates and confidence limits are percentages; latency is measured in "
            "milliseconds. Exact and Holm-adjusted p-values are probabilities, not "
            "percentages. McNemar tests use complete paired blocks.",
            body,
        ),
        PageBreak(),
    ])

    story.extend([
        Paragraph("Method, interpretation, and reproducibility", heading),
        Paragraph(
            "The independent network design crosses four MFA policies, four "
            "network bindings, six network scenarios, three intensity levels, "
            "five repetitions, and three topologies. The verifier study contains "
            "14 controlled authentication variants. The chained validation crosses "
            "eight representative entry conditions with the complete network matrix.",
            body,
        ),
        Paragraph(
            "Technical failures are excluded from security-rate denominators and "
            "reported explicitly. Exact paired McNemar tests and Holm adjustment "
            "support within-block comparisons. Statistical significance is not "
            "presented as universal or production-level superiority.",
            body,
        ),
        Paragraph(
            "Software OTP and biometric factors are controlled laboratory "
            "implementations. Biometric replay without liveness remains a declared "
            "limitation. The report includes raw CSV data, a structured JSON "
            "summary, and publication figures in PNG, SVG, and PDF formats.",
            body,
        ),
    ])
    document.build(story, onFirstPage=footer, onLaterPages=footer)


def _dashboard_document(
    *,
    data: Dict[str, Any],
    summary: Dict[str, Any],
    charts: Dict[str, Dict[str, str]],
    default_language: str,
    pdf_en_name: str,
    pdf_fa_name: str,
) -> str:
    chart_cards = []
    titles = {
        "network": ("Network-binding matrix", "ماتریس اتصال شبکه"),
        "auth": ("Authentication resilience", "مقاومت احراز هویت"),
        "availability": ("Availability curves", "منحنی‌های دسترس‌پذیری"),
        "ecdf": ("Authentication latency ECDF", "توزیع تجمعی تأخیر احراز هویت"),
        "biometric": ("Biometric ROC / FAR / FRR", "منحنی‌های ROC، FAR و FRR بیومتریک"),
        "recovery": ("Service recovery", "بازیابی سرویس"),
        "chained": ("End-to-end chain", "زنجیره انتها‌به‌انتها"),
    }
    for key, (title_en, title_fa) in titles.items():
        png = Path(charts[key]["png"]).name
        svg = Path(charts[key]["svg"]).name
        pdf = Path(charts[key]["pdf"]).name
        chart_cards.append(
            """
            <article class="chart-card">
              <h3 class="en">%s</h3><h3 class="fa">%s</h3>
              <img src="charts/%s" alt="%s">
              <p class="en chart-note">%s</p>
              <p class="fa chart-note">%s</p>
              <div class="downloads">
                <a href="charts/%s" download>PNG</a>
                <a href="charts/%s" download>SVG</a>
                <a href="charts/%s" download>PDF</a>
              </div>
            </article>
            """ % tuple(map(html.escape, (
                title_en, title_fa, png, title_en,
                CHART_DESCRIPTIONS[key][0], CHART_DESCRIPTIONS[key][1],
                png, svg, pdf,
            )))
        )
    technical = (
        int(summary["technical_network_observations"])
        + int(summary["technical_authentication_observations"])
        + int(summary["technical_chained_observations"])
    )
    default_class = "fa-default" if default_language == "fa" else "en-default"
    return """<!doctype html>
<html lang="%s" class="%s">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>SDN-MFA-V2 Research Dashboard</title>
  <style>
    :root{--ink:#123047;--teal:#0b7285;--muted:#64748b;--line:#d9e2ec;--paper:#f8fafc;--white:#fff;--warn:#9a3412}
    *{box-sizing:border-box} body{margin:0;background:var(--paper);color:var(--ink);font-family:DejaVu Sans,Arial,sans-serif;line-height:1.55}
    header{background:linear-gradient(125deg,#123047,#0b7285);color:white;padding:48px max(24px,calc((100%% - 1180px)/2)) 38px}
    header h1{font-size:clamp(28px,4vw,48px);margin:0 0 10px} header p{max-width:850px;margin:0;opacity:.92}
    nav{display:flex;gap:8px;justify-content:flex-end;margin-bottom:20px} button{border:1px solid #ffffff70;background:#ffffff18;color:white;border-radius:999px;padding:8px 14px;cursor:pointer;font-weight:700}
    main{max-width:1180px;margin:auto;padding:28px 24px 60px}.meta{color:var(--muted);font-size:14px}
    .cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:14px;margin:24px 0}.card,.chart-card,.panel{background:white;border:1px solid var(--line);border-radius:14px;box-shadow:0 8px 24px #1230470c}
    .card{padding:18px}.card strong{display:block;font-size:28px;color:var(--teal)}.card span{color:var(--muted)}
    .warning{border-left:5px solid #ea580c;background:#fff7ed;padding:14px 18px;border-radius:10px;color:var(--warn);margin:16px 0}
    .panel{padding:22px;margin:18px 0}.charts{display:grid;grid-template-columns:repeat(auto-fit,minmax(430px,1fr));gap:18px}.chart-card{padding:18px}.chart-card img{width:100%%;height:auto;border-radius:8px;background:white}.chart-card h3{margin:0 0 12px}.chart-note{font-size:.9rem;line-height:1.75;color:var(--muted);margin:12px 0}
    .downloads{display:flex;gap:8px;margin-top:12px}.downloads a,.data-links a{color:var(--teal);text-decoration:none;font-weight:700;border:1px solid var(--line);border-radius:8px;padding:6px 10px}.data-links{display:flex;flex-wrap:wrap;gap:10px}
    .fa{display:none;direction:rtl;text-align:right}.fa-default .en{display:none}.fa-default .fa{display:block}.fa-default .downloads,.fa-default .data-links{direction:rtl}.en-default .en{display:block}.en-default .fa{display:none}
    footer{text-align:center;color:var(--muted);padding:25px}@media(max-width:600px){.charts{grid-template-columns:1fr}header{padding-top:24px}}
  </style>
</head>
<body>
<header>
  <nav><button onclick="setLanguage('en')">English</button><button onclick="setLanguage('fa')">فارسی</button></nav>
  <h1>SDN-MFA-V2</h1>
  <p class="en">Reproducible evaluation of authentication resilience, SDN network binding, topology, attack intensity, availability, and end-to-end attack chains.</p>
  <p class="fa">ارزیابی بازتولیدپذیر مقاومت احراز هویت، اتصال شبکه در SDN، توپولوژی، شدت حمله، دسترس‌پذیری و زنجیره حمله انتها‌به‌انتها.</p>
</header>
<main>
  <p class="meta">Study ID: %s · Status: %s</p>
  <section class="cards">
    <div class="card"><strong>%.1f%%</strong><span class="en">Valid network matrix</span><span class="fa">تکمیل معتبر ماتریس شبکه</span></div>
    <div class="card"><strong>%.1f%%</strong><span class="en">Valid verifier matrix</span><span class="fa">تکمیل معتبر ماتریس احراز هویت</span></div>
    <div class="card"><strong>%.1f%%</strong><span class="en">Valid chained matrix</span><span class="fa">تکمیل معتبر ماتریس زنجیره‌ای</span></div>
    <div class="card"><strong>%s</strong><span class="en">Technical errors</span><span class="fa">خطاهای فنی</span></div>
  </section>
  %s
  <section class="panel">
    <h2 class="en">Key end-to-end measures</h2><h2 class="fa">شاخص‌های کلیدی انتها‌به‌انتها</h2>
    <p class="en">Authentication stopped %s of valid session-dependent access chains; %s were contained after admission; and %s succeeded end to end. Availability degradation was %s and is interpreted independently of application authentication.</p>
    <p class="fa">احراز هویت در %s از زنجیره‌های معتبر وابسته به نشست حمله را متوقف کرد؛ %s پس از ورود مهار شدند؛ و %s انتها‌به‌انتها موفق بودند. افت دسترس‌پذیری %s ثبت شد و مستقل از احراز هویت برنامه تفسیر می‌شود.</p>
  </section>
  <section class="charts">%s</section>
  <section class="panel">
    <h2 class="en">Data and publication downloads</h2><h2 class="fa">دریافت داده‌ها و فایل‌های انتشار</h2>
    <div class="data-links">
      <a href="data/network_observations.csv" download>Network CSV</a>
      <a href="data/authentication_observations.csv" download>Authentication CSV</a>
      <a href="data/chained_observations.csv" download>Chained CSV</a>
      <a href="data/statistical_summary.json" download>Statistical JSON</a>
      <a href="%s" download>English PDF</a>
      <a href="%s" download>Persian PDF</a>
    </div>
  </section>
  <section class="panel">
    <h2 class="en">Interpretation boundary</h2><h2 class="fa">مرز تفسیر نتایج</h2>
    <p class="en">OTP and biometric factors are software laboratory implementations. The biometric model does not represent sensor acquisition or liveness. IP, MAC, and ingress port are independent network-binding attributes, not authentication factors. Only complete and technically valid observations enter security-rate denominators.</p>
    <p class="fa">عامل OTP و بیومتریک پیاده‌سازی نرم‌افزاری آزمایشگاهی هستند. مدل بیومتریک شامل دریافت حسگر یا تشخیص زنده‌بودن نیست. IP، MAC و پورت ورودی ویژگی‌های مستقل اتصال شبکه‌اند و عامل احراز هویت محسوب نمی‌شوند. فقط مشاهدات کامل و معتبر فنی وارد مخرج نرخ‌های امنیتی می‌شوند.</p>
  </section>
</main>
<footer>SDN-MFA-V2 · Reproducible research artifact</footer>
<script>function setLanguage(lang){document.documentElement.className=lang==='fa'?'fa-default':'en-default';document.documentElement.lang=lang;localStorage.setItem('sdnmfa-language',lang)}const saved=localStorage.getItem('sdnmfa-language');if(saved)setLanguage(saved);</script>
</body></html>""" % (
        default_language,
        default_class,
        html.escape(str(data["study"]["study_id"])),
        html.escape(str(data["study"]["data_status"])),
        float(summary["network_completeness_percent"]),
        float(summary["authentication_completeness_percent"]),
        float(summary["chained_completeness_percent"]),
        technical,
        (
            "<div class=\"warning\"><span class=\"en\">This is an incomplete report. Final claims require 100% valid completeness and zero technical errors.</span><span class=\"fa\">این گزارش ناقص است. استنتاج نهایی به تکمیل صددرصد داده‌های معتبر و نبود خطای فنی نیاز دارد.</span></div>"
            if data["study"]["data_status"].endswith("INCOMPLETE") else ""
        ),
        _percent(summary.get("chained_access_blocked_at_authentication_rate")),
        _percent(summary.get("chained_contained_after_admission_rate")),
        _percent(summary.get("chained_end_to_end_attack_success_rate")),
        _percent(summary.get("chained_availability_degradation_rate")),
        _percent(summary.get("chained_access_blocked_at_authentication_rate")),
        _percent(summary.get("chained_contained_after_admission_rate")),
        _percent(summary.get("chained_end_to_end_attack_success_rate")),
        _percent(summary.get("chained_availability_degradation_rate")),
        "".join(chart_cards),
        html.escape(pdf_en_name),
        html.escape(pdf_fa_name),
    )


def build_publication_bundle(
    *,
    data: Dict[str, Any],
    summary: Dict[str, Any],
    charts: Dict[str, Dict[str, str]],
    root: Path,
    strict: bool,
    demo: bool,
    pdf_fa_name: str,
) -> Dict[str, str]:
    label = "DEMO" if demo else ("final" if strict else "partial")
    pdf_en = root / ("SDN-MFA-V2-%s-report-EN.pdf" % label)
    _build_english_pdf(data=data, summary=summary, charts=charts, target=pdf_en)
    html_main = root / "index.html"
    html_en = root / "index-en.html"
    html_fa = root / "index-fa.html"
    html_main.write_text(
        _dashboard_document(
            data=data, summary=summary, charts=charts, default_language="en",
            pdf_en_name=pdf_en.name, pdf_fa_name=pdf_fa_name,
        ),
        encoding="utf-8",
    )
    html_en.write_text(html_main.read_text(encoding="utf-8"), encoding="utf-8")
    html_fa.write_text(
        _dashboard_document(
            data=data, summary=summary, charts=charts, default_language="fa",
            pdf_en_name=pdf_en.name, pdf_fa_name=pdf_fa_name,
        ),
        encoding="utf-8",
    )
    return {
        "pdf_en": str(pdf_en),
        "html": str(html_main),
        "html_en": str(html_en),
        "html_fa": str(html_fa),
    }
