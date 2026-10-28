"""
html_section.py — Security audit HTML component generator for report.py.

Generates dark-themed, XSS-safe HTML markup for:
  - Top security audit summary banner (Verdict, Risk Score gauge, Top Reasons, Coverage)
  - Inline method vulnerability banners and evidence traces
  - Class-level risk pills and archive-level findings
"""

from __future__ import annotations

import html
from typing import Any, Dict, List, Optional

from javadecompiler.security.models import Finding, ScanResult, Severity, Verdict


def get_severity_color(severity: str) -> str:
    s = severity.lower()
    if s == Severity.CRITICAL.value:
        return "#f85149"  # bright red
    elif s == Severity.HIGH.value:
        return "#db6d28"  # deep orange
    elif s == Severity.MEDIUM.value:
        return "#d29922"  # amber / yellow
    elif s == Severity.LOW.value:
        return "#58a6ff"  # blue
    return "#8b949e"  # gray


def get_verdict_badge(verdict: str) -> str:
    v = verdict.upper()
    if v == Verdict.CLEAN.value:
        bg = "#238636"
        text = "#ffffff"
    elif v == Verdict.REVIEW_RECOMMENDED.value:
        bg = "#9e6a03"
        text = "#ffffff"
    elif v == Verdict.VULNERABLE.value:
        bg = "#bd561d"
        text = "#ffffff"
    elif v in (Verdict.SUSPICIOUS.value, Verdict.LIKELY_MALICIOUS.value):
        bg = "#da3633"
        text = "#ffffff"
    else:
        bg = "#30363d"
        text = "#c9d1d9"

    return f'<span style="background: {bg}; color: {text}; font-weight: 700; padding: 4px 12px; border-radius: 6px; font-size: 13px; text-transform: uppercase; letter-spacing: 0.5px;">{html.escape(v)}</span>'


def render_security_styles() -> str:
    """Returns CSS styles dedicated to the Phase 4 security report section."""
    return """
        .sec-banner {
            background: linear-gradient(135deg, #1b1f27 0%, #161b22 100%);
            border: 1px solid #30363d;
            border-radius: 12px;
            padding: 24px;
            margin-bottom: 24px;
            box-shadow: 0 4px 16px rgba(0,0,0,0.3);
        }
        .sec-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            margin-top: 16px;
        }
        .sec-card {
            background: #21262d;
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 14px;
        }
        .sec-score {
            font-size: 28px;
            font-weight: 700;
            color: #58a6ff;
            font-family: var(--font-mono);
        }
        .sec-finding-card {
            background: #1c2128;
            border-left: 4px solid #d29922;
            border: 1px solid #30363d;
            border-left-width: 4px;
            border-radius: 6px;
            padding: 12px 16px;
            margin: 10px 0;
            font-size: 13px;
        }
        .sec-finding-critical { border-left-color: #f85149; }
        .sec-finding-high { border-left-color: #db6d28; }
        .sec-finding-medium { border-left-color: #d29922; }
        .sec-finding-low { border-left-color: #58a6ff; }
        .sec-finding-info { border-left-color: #8b949e; }
        .sec-badge {
            display: inline-block;
            font-size: 11px;
            font-weight: 700;
            padding: 2px 8px;
            border-radius: 4px;
            text-transform: uppercase;
            margin-right: 6px;
        }
        .sec-evidence-list {
            margin: 8px 0;
            padding-left: 18px;
            font-family: var(--font-mono);
            font-size: 11px;
            color: #8b949e;
        }
    """


def render_security_banner(scan_result: ScanResult) -> str:
    """Builds the security audit banner at the top of the HTML report."""
    verdict_badge = get_verdict_badge(scan_result.overallVerdict)
    score_color = get_severity_color(
        Severity.CRITICAL.value
        if scan_result.overallRiskScore >= 70
        else (Severity.HIGH.value if scan_result.overallRiskScore >= 40 else Severity.LOW.value)
    )

    reasons_html = "".join(f"<li>{html.escape(r)}</li>" for r in scan_result.topReasons)
    all_findings = scan_result.allFindings

    counts: Dict[str, int] = {}
    for f in all_findings:
        s = f.severity.lower()
        counts[s] = counts.get(s, 0) + 1

    pill_html = []
    for sev in (Severity.CRITICAL.value, Severity.HIGH.value, Severity.MEDIUM.value, Severity.LOW.value, Severity.INFO.value):
        cnt = counts.get(sev, 0)
        col = get_severity_color(sev)
        pill_html.append(f'<span class="sec-badge" style="background: {col}; color: #fff;">{sev.upper()}: {cnt}</span>')

    coverage_badge = (
        '<span style="background: #238636; color: #fff; padding: 2px 6px; border-radius: 4px; font-size: 11px;">FULL</span>'
        if scan_result.coverageStats.partialCoverageMethods == 0
        else f'<span style="background: #d29922; color: #000; padding: 2px 6px; border-radius: 4px; font-size: 11px;">PARTIAL ({scan_result.coverageStats.partialCoverageMethods})</span>'
    )

    jar_findings_html = ""
    if scan_result.jarFindings:
        items = []
        for jf in scan_result.jarFindings:
            col = get_severity_color(jf.severity)
            items.append(
                f'<div style="margin-top: 6px;">'
                f'<span class="sec-badge" style="background: {col}; color: #fff;">{html.escape(jf.severity.upper())}</span> '
                f'<strong>{html.escape(jf.ruleId)}:</strong> {html.escape(jf.title)} '
                f'<span style="color: #8b949e;">({html.escape(jf.description)})</span>'
                f'</div>'
            )
        jar_findings_html = f'<div style="margin-top: 14px; border-top: 1px solid #30363d; padding-top: 10px;"><strong>Archive & Manifest Findings:</strong>{"".join(items)}</div>'

    return f"""
    <section class="sec-banner">
        <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px;">
            <div>
                <h2 style="font-size: 20px; color: #fff; display: flex; align-items: center; gap: 10px;">
                    Security Auditing & Behavioral Analysis
                    <span style="font-size: 11px; background: #388bfd33; color: #58a6ff; border: 1px solid #388bfd66; padding: 2px 8px; border-radius: 12px;">Phase 4</span>
                </h2>
                <div style="margin-top: 6px;">{"".join(pill_html)}</div>
            </div>
            <div>
                {verdict_badge}
            </div>
        </div>

        <div class="sec-grid">
            <div class="sec-card">
                <span style="font-size: 11px; color: #8b949e; text-transform: uppercase;">OVERALL RISK SCORE</span>
                <div class="sec-score" style="color: {score_color};">{scan_result.overallRiskScore:.1f} <span style="font-size: 14px; color: #8b949e;">/ 100</span></div>
            </div>
            <div class="sec-card">
                <span style="font-size: 11px; color: #8b949e; text-transform: uppercase;">ANALYSIS COVERAGE</span>
                <div style="margin-top: 6px;">{coverage_badge}</div>
                <div style="font-size: 12px; color: #8b949e; margin-top: 4px;">{scan_result.coverageStats.fullCoverageMethods} / {scan_result.coverageStats.totalMethods} methods full</div>
            </div>
            <div class="sec-card" style="grid-column: span 2;">
                <span style="font-size: 11px; color: #8b949e; text-transform: uppercase;">VERDICT RATIONALE</span>
                <ul style="margin-top: 6px; padding-left: 18px; font-size: 13px; color: #c9d1d9;">
                    {reasons_html}
                </ul>
            </div>
        </div>
        {jar_findings_html}
    </section>
    """


def render_method_findings_html(findings: List[Finding]) -> str:
    """Renders inline findings cards attached to a method card in the HTML report."""
    if not findings:
        return ""

    cards = []
    for f in findings:
        sev = f.severity.lower()
        col = get_severity_color(sev)
        cwe_str = ", ".join(html.escape(c) for c in f.cwe) if f.cwe else "General Weakness"

        ev_items = []
        for ev in f.evidence:
            ev_items.append(f"<li><code>[{html.escape(ev.type)}]</code> {html.escape(ev.text)}</li>")
        ev_html = f'<ul class="sec-evidence-list">{"".join(ev_items)}</ul>' if ev_items else ""

        line_str = f"Line(s): {', '.join(str(l) for l in f.location.liftedLineNumbers)}" if f.location.liftedLineNumbers else ""
        off_str = f"Bytecode: {', '.join(f'0x{o:02x}' for o in f.location.bytecodeOffsets)}" if f.location.bytecodeOffsets else ""
        loc_meta = " &bull; ".join(s for s in (line_str, off_str) if s)

        cards.append(
            f"""
            <div class="sec-finding-card sec-finding-{html.escape(sev)}">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                    <div>
                        <span class="sec-badge" style="background: {col}; color: #fff;">{html.escape(f.severity.upper())}</span>
                        <strong style="color: #fff;">{html.escape(f.ruleId)}: {html.escape(f.title)}</strong>
                    </div>
                    <span style="font-size: 11px; color: #8b949e;">{cwe_str}</span>
                </div>
                <div style="color: #c9d1d9; margin-bottom: 4px;">{html.escape(f.description)}</div>
                {f'<div style="font-size: 11px; color: #58a6ff; margin-bottom: 4px;">{loc_meta}</div>' if loc_meta else ''}
                {ev_html}
                <div style="font-size: 12px; color: #7ee787; margin-top: 6px;">
                    <strong>Remediation:</strong> {html.escape(f.remediation)}
                </div>
            </div>
            """
        )

    return f'<div style="margin: 12px 0;">{"".join(cards)}</div>'
