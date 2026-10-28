"""
server.py — Zero-dependency HTTP server for the Interactive Drag-and-Drop Web UI.

Endpoints:
  GET /              -> Serves index.html
  GET /styles.css    -> Serves styles.css
  GET /app.js        -> Serves app.js
  GET /api/health    -> Health check & Ollama availability
  POST /api/scan     -> Upload class/jar, runs decompile + security scan, returns JSON
"""

from __future__ import annotations

import base64
import html
import json
import os
import shutil
import tempfile
import time
import urllib.request
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional

from javadecompiler.class_parser import ClassInfo, parseClassFile, parseJarFile
from javadecompiler.disassembler import disassembleMethod
from javadecompiler.lifter import liftMethod
from javadecompiler.report import generateHtmlReport
from javadecompiler.security import TOOL_VERSION
from javadecompiler.security.models import ScanResult
from javadecompiler.security.reporting.sarif import to_sarif
from javadecompiler.security.scanner import SecurityScanner

ASSETS_DIR = Path(__file__).parent / "assets"


class UiServerHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the Drag-and-Drop Web UI."""

    def log_message(self, format: str, *args: Any) -> None:
        """Suppress standard request logging to keep console clean."""
        pass

    def send_json_response(self, data: Any, status: int = 200) -> None:
        payload = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(payload)

    def send_file_response(self, file_path: Path, content_type: str) -> None:
        if not file_path.exists():
            self.send_response(404)
            self.end_headers()
            return
        content = file_path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", f"{content_type}; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(content)

    def do_OPTIONS(self) -> None:
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, X-Filename")
        self.end_headers()

    def do_GET(self) -> None:
        url_path = self.path.split("?")[0]

        if url_path in ("/", "/index.html"):
            self.send_file_response(ASSETS_DIR / "index.html", "text/html")
        elif url_path == "/styles.css":
            self.send_file_response(ASSETS_DIR / "styles.css", "text/css")
        elif url_path == "/app.js":
            self.send_file_response(ASSETS_DIR / "app.js", "application/javascript")
        elif url_path == "/api/health":
            self._handle_health()
        else:
            self.send_response(404)
            self.end_headers()

    def _handle_health(self) -> None:
        ollama_reachable = False
        models = []
        try:
            req = urllib.request.Request("http://localhost:11434/api/tags", method="GET")
            with urllib.request.urlopen(req, timeout=2) as resp:
                if resp.status == 200:
                    ollama_reachable = True
                    body = json.loads(resp.read().decode("utf-8"))
                    models = [m.get("name") for m in body.get("models", [])]
        except Exception:
            pass

        self.send_json_response({
            "status": "ok",
            "toolVersion": TOOL_VERSION,
            "ollamaReachable": ollama_reachable,
            "defaultModel": "qwen2.5-coder:14b",
            "modelsAvailable": models,
        })

    def do_POST(self) -> None:
        url_path = self.path.split("?")[0]
        if url_path == "/api/scan":
            self._handle_scan()
        else:
            self.send_response(404)
            self.end_headers()

    def _handle_scan(self) -> None:
        t0 = time.time()
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length <= 0:
            self.send_json_response({"error": "Empty request body"}, status=400)
            return

        body_bytes = self.rfile.read(content_length)

        # Parse request body (JSON or multipart)
        file_name = "target.class"
        file_bytes = b""
        enable_llm = False
        llm_investigate = False
        audit_model = "qwen2.5-coder:14b"

        content_type = self.headers.get("Content-Type", "")

        if "application/json" in content_type:
            try:
                req_json = json.loads(body_bytes.decode("utf-8"))
                file_name = req_json.get("fileName", "target.class")
                b64_data = req_json.get("fileBase64", "")
                file_bytes = base64.b64decode(b64_data)
                options = req_json.get("options", {})
                enable_llm = bool(options.get("enableLlm", False))
                llm_investigate = bool(options.get("llmInvestigate", False))
                audit_model = str(options.get("model", "qwen2.5-coder:14b"))
            except Exception as e:
                self.send_json_response({"error": f"Invalid JSON payload: {e}"}, status=400)
                return
        else:
            # Fallback: raw upload with X-Filename header
            header_name = self.headers.get("X-Filename")
            if header_name:
                file_name = header_name
            file_bytes = body_bytes

        if not file_bytes:
            self.send_json_response({"error": "No file data received"}, status=400)
            return

        # Execute Scan in temp directory
        temp_dir = tempfile.mkdtemp(prefix="neurodecomp_ui_")
        target_path = Path(temp_dir) / file_name

        try:
            target_path.write_bytes(file_bytes)

            is_jar = file_name.endswith(".jar")
            classes: List[ClassInfo] = []
            if is_jar:
                classes = parseJarFile(str(target_path))
            else:
                classes = [parseClassFile(str(target_path))]

            # Lift and disassemble methods
            raw_methods_dict: Dict[str, Dict[str, str]] = {}
            decompiled_data: Dict[str, Dict[str, Dict[str, str]]] = {}

            for c_info in classes:
                c_name = c_info.class_name
                raw_methods_dict[c_name] = {}
                decompiled_data[c_name] = {}

                for m_name, m_info in c_info.methods.items():
                    if not m_info.bytecode:
                        continue
                    try:
                        raw_code = liftMethod(m_name, m_info.bytecode, c_info.constant_pool)
                    except Exception:
                        raw_code = f"// Error lifting method {m_name}"

                    try:
                        ins = disassembleMethod(m_name, m_info.bytecode)
                        bc_text = "\n".join(f"0x{i.offset:02x}: {i.mnemonic} {i.operands}".strip() for i in ins)
                    except Exception:
                        bc_text = "// Error disassembling method"

                    raw_methods_dict[c_name][m_name] = raw_code
                    decompiled_data[c_name][m_name] = {
                        "liftedSource": raw_code,
                        "bytecodeText": bc_text,
                    }

            # Run Security Scanner
            scanner = SecurityScanner(
                enable_llm=enable_llm,
                audit_model=audit_model,
                llm_scope="suspicious",
                llm_investigate=llm_investigate,
            )
            scan_res: ScanResult = scanner.scan_file(str(target_path))

            # HTML & SARIF reports
            html_report = generateHtmlReport(
                classes=classes,
                raw_methods=raw_methods_dict,
                restored_methods={},
                target_name=file_name,
                scan_result=scan_res,
            )
            sarif_str = to_sarif(scan_res)

            elapsed_ms = round((time.time() - t0) * 1000.0, 1)

            resp_payload = {
                "success": True,
                "targetName": file_name,
                "scanResult": scan_res.to_dict(),
                "decompiled": decompiled_data,
                "htmlReport": html_report,
                "sarifReport": sarif_str,
                "executionTimeMs": elapsed_ms,
            }
            self.send_json_response(resp_payload)

        except Exception as e:
            self.send_json_response({"error": f"Analysis failed: {e}"}, status=500)
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)


def start_ui_server(port: int = 8080, host: str = "127.0.0.1", open_browser: bool = True) -> int:
    """Starts the Drag-and-Drop Web UI server."""
    server_address = (host, port)
    try:
        httpd = HTTPServer(server_address, UiServerHandler)
    except OSError as e:
        print(f"[!] Could not bind to {host}:{port}: {e}")
        return 1

    url = f"http://{host}:{port}/"
    print("\n" + "=" * 65)
    print(f"[+] NeuroDecomp Interactive Web UI is running at:")
    print(f"    {url}")
    print("=" * 65)
    print("[*] Press Ctrl+C in terminal to stop server.\n")

    if open_browser:
        try:
            webbrowser.open(url)
        except Exception:
            pass

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down Web UI server...")
        httpd.server_close()
    return 0
