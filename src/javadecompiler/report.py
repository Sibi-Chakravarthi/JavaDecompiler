"""
report.py — Dark-themed, multi-column HTML report generator for NeuroDecomp

Generates an offline, responsive report presenting:
- Class metadata & Constant Pool summary
- Detected OS & System API interactions
- Per-method 3-way view:
  1. Bytecode & CFG Blocks (Phase 2)
  2. Raw Symbolic Pseudo-Code (Phase 2)
  3. AI-Restored Source Code & Javadoc (Phase 3)
"""

import html
from typing import Any, Dict, List, Optional
from datetime import datetime

try:
    from javadecompiler.class_parser import ClassInfo
    from javadecompiler.cfg_builder import buildControlFlowGraph, printControlFlowGraphToString
    from javadecompiler.disassembler import disassembleMethod
    from javadecompiler.semantic_restorer import OSContext, RestorationResult
except ImportError:
    from class_parser import ClassInfo
    from cfg_builder import buildControlFlowGraph, printControlFlowGraphToString
    from disassembler import disassembleMethod
    from semantic_restorer import OSContext, RestorationResult


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NeuroDecomp Report: {target_name}</title>
    <style>
        :root {{
            --bg-primary: #0d1117;
            --bg-secondary: #161b22;
            --bg-tertiary: #21262d;
            --border-color: #30363d;
            --text-primary: #c9d1d9;
            --text-secondary: #8b949e;
            --accent-blue: #58a6ff;
            --accent-green: #3fb950;
            --accent-purple: #bc8cff;
            --accent-orange: #f0883e;
            --accent-red: #ff7b72;
            --font-mono: 'JetBrains Mono', 'Fira Code', Menlo, Consolas, monospace;
            --font-sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
        }}

        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }}

        body {{
            background-color: var(--bg-primary);
            color: var(--text-primary);
            font-family: var(--font-sans);
            line-height: 1.5;
            padding: 24px;
        }}

        header {{
            background: linear-gradient(135deg, #1f242c 0%, #161b22 100%);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 24px 32px;
            margin-bottom: 28px;
            box-shadow: 0 8px 24px rgba(0,0,0,0.4);
        }}

        .header-title {{
            display: flex;
            align-items: center;
            justify-content: space-between;
            flex-wrap: wrap;
            gap: 16px;
        }}

        h1 {{
            font-size: 26px;
            font-weight: 700;
            color: #fff;
            display: flex;
            align-items: center;
            gap: 12px;
        }}

        .logo-badge {{
            background: linear-gradient(135deg, var(--accent-blue), var(--accent-purple));
            color: #fff;
            font-size: 13px;
            padding: 4px 10px;
            border-radius: 6px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}

        .meta-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            margin-top: 20px;
            padding-top: 16px;
            border-top: 1px solid var(--border-color);
            font-size: 14px;
        }}

        .meta-item span:first-child {{
            color: var(--text-secondary);
            display: block;
            font-size: 12px;
            margin-bottom: 4px;
        }}

        .badge {{
            display: inline-block;
            font-size: 12px;
            font-weight: 600;
            padding: 2px 8px;
            border-radius: 12px;
            margin-right: 6px;
            margin-bottom: 4px;
        }}

        .badge-network {{ background: rgba(88, 166, 255, 0.2); color: var(--accent-blue); border: 1px solid var(--accent-blue); }}
        .badge-crypto {{ background: rgba(188, 140, 255, 0.2); color: var(--accent-purple); border: 1px solid var(--accent-purple); }}
        .badge-file {{ background: rgba(240, 136, 62, 0.2); color: var(--accent-orange); border: 1px solid var(--accent-orange); }}
        .badge-proc {{ background: rgba(255, 123, 114, 0.2); color: var(--accent-red); border: 1px solid var(--accent-red); }}
        .badge-clean {{ background: rgba(63, 185, 80, 0.2); color: var(--accent-green); border: 1px solid var(--accent-green); }}

        .class-card {{
            background-color: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            margin-bottom: 32px;
            overflow: hidden;
            box-shadow: 0 4px 16px rgba(0,0,0,0.25);
        }}

        .class-header {{
            background-color: var(--bg-tertiary);
            padding: 16px 24px;
            border-bottom: 1px solid var(--border-color);
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 12px;
        }}

        .class-name {{
            font-size: 18px;
            font-weight: 600;
            color: #fff;
            font-family: var(--font-mono);
        }}

        .method-container {{
            padding: 20px 24px;
            border-bottom: 1px solid var(--border-color);
        }}

        .method-container:last-child {{
            border-bottom: none;
        }}

        .method-title {{
            display: flex;
            align-items: center;
            justify-content: space-between;
            flex-wrap: wrap;
            margin-bottom: 14px;
            gap: 10px;
        }}

        .method-sig {{
            font-family: var(--font-mono);
            font-size: 15px;
            font-weight: 600;
            color: var(--accent-blue);
        }}

        .renamed-vars {{
            background: rgba(188, 140, 255, 0.1);
            border: 1px dashed var(--accent-purple);
            padding: 8px 14px;
            border-radius: 6px;
            font-size: 12px;
            font-family: var(--font-mono);
            margin-bottom: 16px;
        }}

        .pipeline-grid {{
            display: grid;
            grid-template-columns: 1fr 1fr 1fr;
            gap: 16px;
        }}

        @media (max-width: 1200px) {{
            .pipeline-grid {{
                grid-template-columns: 1fr;
            }}
        }}

        .stage-box {{
            background-color: var(--bg-primary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            display: flex;
            flex-direction: column;
            overflow: hidden;
        }}

        .stage-header {{
            background-color: var(--bg-tertiary);
            padding: 8px 14px;
            font-size: 12px;
            font-weight: 600;
            letter-spacing: 0.5px;
            text-transform: uppercase;
            border-bottom: 1px solid var(--border-color);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}

        .stage-title {{
            display: flex;
            align-items: center;
            gap: 6px;
        }}

        .stage-tag {{
            font-size: 10px;
            padding: 2px 6px;
            border-radius: 4px;
            font-weight: 700;
        }}

        .tag-p2 {{ background: #238636; color: #fff; }}
        .tag-p3 {{ background: #8957e5; color: #fff; }}

        pre {{
            margin: 0;
            padding: 14px;
            font-family: var(--font-mono);
            font-size: 12px;
            overflow-x: auto;
            flex-grow: 1;
            white-space: pre-wrap;
            line-height: 1.45;
        }}

        .code-p2-asm {{ color: #79c0ff; }}
        .code-p2-raw {{ color: #e6edf3; }}
        .code-p3-restored {{ color: #7ee787; }}

        footer {{
            text-align: center;
            margin-top: 40px;
            color: var(--text-secondary);
            font-size: 13px;
        }}
    </style>
</head>
<body>
    <header>
        <div class="header-title">
            <h1>
                NeuroDecomp
                <span class="logo-badge">Decompilation & Semantic Recovery</span>
            </h1>
            <div>
                <span style="font-size: 13px; color: var(--text-secondary);">Generated: {timestamp}</span>
            </div>
        </div>
        <div class="meta-grid">
            <div class="meta-item">
                <span>TARGET INPUT</span>
                <strong>{target_name}</strong>
            </div>
            <div class="meta-item">
                <span>CLASSES ANALYZED</span>
                <strong>{class_count} class file(s)</strong>
            </div>
            <div class="meta-item">
                <span>TOTAL METHODS</span>
                <strong>{total_methods} methods</strong>
            </div>
            <div class="meta-item">
                <span>AI RECOVERY ENGINE</span>
                <strong>{ai_engine}</strong>
            </div>
        </div>
    </header>

    <main>
        {classes_html}
    </main>

    <footer>
        <p>NeuroDecomp — AI-Powered Java Bytecode Decompiler & Semantic Restorer &bull; Python 3.10+ &bull; Ollama</p>
    </footer>
</body>
</html>
"""


def _getBadgeForCategory(cat: str) -> str:
    if "Network" in cat:
        return f'<span class="badge badge-network">{cat}</span>'
    elif "Crypto" in cat:
        return f'<span class="badge badge-crypto">{cat}</span>'
    elif "File" in cat:
        return f'<span class="badge badge-file">{cat}</span>'
    elif "Process" in cat:
        return f'<span class="badge badge-proc">{cat}</span>'
    return f'<span class="badge badge-clean">{cat}</span>'


def generateHtmlReport(
    classes: List[ClassInfo],
    raw_methods: Dict[str, Dict[str, str]],       # class_name -> method_name -> raw_code
    restored_methods: Dict[str, Dict[str, RestorationResult]], # class_name -> method_name -> RestorationResult
    target_name: str,
    ai_engine: str = "Local LLM (qwen2.5-coder:14b)",
) -> str:
    """Renders a complete, standalone dark-themed HTML report."""
    total_methods = sum(len(c.methods) for c in classes)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    classes_html_list: List[str] = []

    for cInfo in classes:
        cName = cInfo.class_name
        cRaw = raw_methods.get(cName, {})
        cRestored = restored_methods.get(cName, {})

        # Compute whole-class OS context
        try:
            from javadecompiler.semantic_restorer import extractOsContext
        except ImportError:
            from semantic_restorer import extractOsContext
        whole_ctx = extractOsContext(cInfo)

        badges = "".join(_getBadgeForCategory(cat) for cat in whole_ctx.categories)
        if not badges:
            badges = '<span class="badge badge-clean">Pure Algorithmic Computation</span>'

        methods_html_list: List[str] = []

        for mName, mInfo in cInfo.methods.items():
            if not mInfo.bytecode:
                continue

            rawCode = cRaw.get(mName, "// No raw lifted code")
            restResult = cRestored.get(mName)

            # Generate CFG text
            instructions = disassembleMethod(mName, mInfo.bytecode)
            cfg = buildControlFlowGraph(instructions)
            cfgText = printControlFlowGraphToString(cfg, mName).strip()

            # Renamed vars summary
            renamed_html = ""
            if restResult and restResult.renamed_variables:
                items = [f"<b>{k}</b> &rarr; <i>{v}</i>" for k, v in restResult.renamed_variables.items()]
                renamed_html = f'<div class="renamed-vars"><strong>Restored Identifiers:</strong> {", ".join(items)}</div>'

            # Method OS context
            mCtx = extractOsContext(cInfo, mName, rawCode, mInfo)
            mBadges = "".join(_getBadgeForCategory(cat) for cat in mCtx.categories)

            restoredCode = restResult.reconstructed_code if restResult else rawCode

            method_card = f"""
            <div class="method-container">
                <div class="method-title">
                    <span class="method-sig">{html.escape(mName)} ({html.escape(mInfo.descriptor)})</span>
                    <div>{mBadges}</div>
                </div>
                {renamed_html}
                <div class="pipeline-grid">
                    <div class="stage-box">
                        <div class="stage-header">
                            <span class="stage-title">Bytecode & CFG Blocks</span>
                            <span class="stage-tag tag-p2">Phase 2</span>
                        </div>
                        <pre class="code-p2-asm">{html.escape(cfgText)}</pre>
                    </div>

                    <div class="stage-box">
                        <div class="stage-header">
                            <span class="stage-title">Raw Pseudo-Code</span>
                            <span class="stage-tag tag-p2">Phase 2</span>
                        </div>
                        <pre class="code-p2-raw">{html.escape(rawCode)}</pre>
                    </div>

                    <div class="stage-box">
                        <div class="stage-header">
                            <span class="stage-title">AI-Restored Source Code</span>
                            <span class="stage-tag tag-p3">Phase 3</span>
                        </div>
                        <pre class="code-p3-restored">{html.escape(restoredCode)}</pre>
                    </div>
                </div>
            </div>
            """
            methods_html_list.append(method_card)

        class_section = f"""
        <section class="class-card">
            <div class="class-header">
                <div>
                    <span class="class-name">{html.escape(cName)}</span>
                    <span style="font-size: 12px; color: var(--text-secondary); margin-left: 8px;">
                        (version {cInfo.major_version}.{cInfo.minor_version}, {len(cInfo.constant_pool)} CP entries)
                    </span>
                </div>
                <div>{badges}</div>
            </div>
            {"".join(methods_html_list)}
        </section>
        """
        classes_html_list.append(class_section)

    return HTML_TEMPLATE.format(
        target_name=html.escape(target_name),
        class_count=len(classes),
        total_methods=total_methods,
        ai_engine=html.escape(ai_engine),
        timestamp=timestamp,
        classes_html="".join(classes_html_list),
    )
