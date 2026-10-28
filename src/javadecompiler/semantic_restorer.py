"""
semantic_restorer.py — Phase 3: NLP Semantic Restorer for NeuroDecomp

Analyzes raw decompiled Java pseudo-code along with Constant Pool OS/system
resource interactions, querying a local LLM via Ollama to restore meaningful
variable names, Javadoc documentation, and human-readable source code.
Includes a robust offline/no-LLM heuristic fallback mode.
"""

from dataclasses import dataclass, field
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    from javadecompiler.class_parser import ClassInfo, MethodInfo, resolveRef, resolveString, resolveClass, resolveNameAndType
except ImportError:
    from class_parser import ClassInfo, MethodInfo, resolveRef, resolveString, resolveClass, resolveNameAndType


# Known OS and system API prefixes categorized for semantic analysis
OS_API_PATTERNS = {
    "Network / Sockets": [
        "java/net/Socket",
        "java/net/ServerSocket",
        "java/net/DatagramSocket",
        "java/net/URL",
        "java/net/HttpURLConnection",
        "java/net/InetAddress",
        "java/net/URI",
        "java/net/http/HttpClient",
    ],
    "File I/O & Storage": [
        "java/io/File",
        "java/io/FileInputStream",
        "java/io/FileOutputStream",
        "java/io/FileReader",
        "java/io/FileWriter",
        "java/io/BufferedReader",
        "java/io/BufferedWriter",
        "java/io/InputStream",
        "java/io/OutputStream",
        "java/io/RandomAccessFile",
        "java/nio/file/Path",
        "java/nio/file/Paths",
        "java/nio/file/Files",
    ],
    "Cryptography & Hashing": [
        "java/security/MessageDigest",
        "javax/crypto/Cipher",
        "javax/crypto/SecretKey",
        "javax/crypto/KeyGenerator",
        "javax/crypto/Mac",
        "java/security/Signature",
        "java/security/SecureRandom",
        "java/security/KeyStore",
    ],
    "Process & OS Execution": [
        "java/lang/Runtime",
        "java/lang/ProcessBuilder",
        "java/lang/Process",
        "java/lang/System.exit",
        "java/lang/System.loadLibrary",
    ],
    "System & Environment": [
        "java/lang/System.getProperty",
        "java/lang/System.getenv",
        "java/lang/reflect",
    ],
    "Database / SQL": [
        "java/sql/Connection",
        "java/sql/DriverManager",
        "java/sql/PreparedStatement",
        "java/sql/ResultSet",
        "javax/sql",
    ],
}


def stripMarkdownFences(text: str) -> str:
    """Strips markdown code fences like ```java ... ``` or ```json ... ``` and leading/trailing whitespace."""
    if not text:
        return ""
    cleaned = text.strip()
    # Match enclosed ```lang ... ```
    m = re.match(r"^```(?:[a-zA-Z0-9_-]+)?\s*\n?(.*?)\n?```$", cleaned, re.DOTALL)
    if m:
        return m.group(1).strip()
    # If starting or ending with ```
    cleaned = re.sub(r"^```(?:[a-zA-Z0-9_-]+)?\s*\n?", "", cleaned)
    cleaned = re.sub(r"\n?```\s*$", "", cleaned)
    return cleaned.strip()


def extractJsonPayload(text: str) -> Optional[Dict[str, Any]]:
    """Extracts a valid JSON dict from raw text, code fences, or surrounding conversational text."""
    if not text or not text.strip():
        return None
    cleaned = text.strip()
    # 1. Direct parse
    try:
        data = json.loads(cleaned)
        if isinstance(data, dict):
            return data
    except Exception:
        pass

    # 2. Strip code fences
    unfenced = stripMarkdownFences(cleaned)
    try:
        data = json.loads(unfenced)
        if isinstance(data, dict):
            return data
    except Exception:
        pass

    # 3. Search for outermost curly braces
    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start != -1 and end != -1 and end > start:
        snippet = cleaned[start : end + 1]
        try:
            data = json.loads(snippet)
            if isinstance(data, dict):
                return data
        except Exception:
            pass

    return None


@dataclass
class OSContext:
    categories: List[str] = field(default_factory=list)
    apis_invoked: List[str] = field(default_factory=list)
    string_literals: List[str] = field(default_factory=list)

    def summary(self) -> str:
        if not self.categories and not self.apis_invoked:
            return "No sensitive OS, File I/O, or Network APIs detected (algorithmic logic)."
        parts = []
        if self.categories:
            parts.append(f"Categories: {', '.join(self.categories)}")
        if self.apis_invoked:
            parts.append(f"APIs: {', '.join(self.apis_invoked)}")
        if self.string_literals:
            parts.append(f"Constants/Strings: {', '.join(self.string_literals[:5])}")
        return "; ".join(parts)


def extractOsContext(
    class_info: ClassInfo,
    method_name: Optional[str] = None,
    raw_code: Optional[str] = None,
    method_info: Optional[MethodInfo] = None,
) -> OSContext:
    """Scans the constant pool and method bytecode for OS, network, file, and crypto interactions."""
    detected_categories: Set[str] = set()
    detected_apis: Set[str] = set()
    string_literals: Set[str] = set()
    cp = class_info.constant_pool

    # If method_name is given, look up its MethodInfo
    if method_info is None and method_name and method_name in class_info.methods:
        method_info = class_info.methods[method_name]

    referenced_indices: Set[int] = set()
    if method_info and method_info.bytecode:
        try:
            from javadecompiler.disassembler import disassembleMethod
        except ImportError:
            from disassembler import disassembleMethod
        try:
            instructions = disassembleMethod(method_info.name, method_info.bytecode)
            for instr in instructions:
                mnemonic = instr["mnemonic"]
                ops = instr["operands"]
                if mnemonic in ("invokevirtual", "invokespecial", "invokestatic", "invokeinterface",
                                "getstatic", "putstatic", "getfield", "putfield", "new", "anewarray",
                                "checkcast", "instanceof", "ldc_w", "ldc2_w"):
                    if len(ops) >= 2:
                        referenced_indices.add((ops[0] << 8) | ops[1])
                elif mnemonic == "ldc" and len(ops) >= 1:
                    referenced_indices.add(ops[0])
        except Exception:
            pass

    # If no instructions analyzed (e.g. whole class scan), scan all CP indices
    if not referenced_indices:
        referenced_indices = set(cp.keys())

    for idx in referenced_indices:
        entry = cp.get(idx)
        if not entry:
            continue

        eType = entry.get("type")
        if eType == "String":
            sVal = resolveString(cp, idx)
            if sVal and any(k in sVal.lower() for k in ("http", "tcp", "sha", "aes", "rsa", "/", "\\", ".key", ".dat")):
                string_literals.add(sVal)

        elif eType == "Ref":
            rawClass = resolveClass(cp, entry.get("classIndex", 0))
            mName, _ = resolveNameAndType(cp, entry.get("nameAndTypeIndex", 0))
            simpleCall = f"{rawClass.split('/')[-1]}.{mName}"

            for category, patterns in OS_API_PATTERNS.items():
                for pat in patterns:
                    if pat in rawClass:
                        detected_categories.add(category)
                        detected_apis.add(simpleCall)

        elif eType == "Class":
            rawClass = resolveClass(cp, idx)
            for category, patterns in OS_API_PATTERNS.items():
                for pat in patterns:
                    if pat in rawClass:
                        detected_categories.add(category)

    return OSContext(
        categories=sorted(detected_categories),
        apis_invoked=sorted(detected_apis),
        string_literals=sorted(string_literals),
    )


@dataclass
class RestorationResult:
    method_name: str
    renamed_variables: Dict[str, str] = field(default_factory=dict)
    javadoc: str = ""
    reconstructed_code: str = ""
    mode: str = "offline_fallback"
    error: Optional[str] = None


def infer_semantic_variables(
    class_name: str,
    method_name: str,
    raw_code: str,
    param_types: Optional[List[str]] = None,
    os_categories: Optional[List[str]] = None,
    os_apis: Optional[List[str]] = None,
    existing: Optional[Dict[str, str]] = None,
) -> Dict[str, str]:
    """Infers meaningful, context-aware semantic variable names for generic paramX and varX variables."""
    if param_types is None:
        param_types = []
    if os_categories is None:
        os_categories = []
    if os_apis is None:
        os_apis = []

    m_lower = method_name.lower()
    c_lower = class_name.lower()
    has_socket = any("Socket" in api for api in os_apis) or "Network / Sockets" in os_categories or any(k in m_lower for k in ("socket", "connect", "send", "host", "port", "net", "http"))
    has_file = any("File" in api for api in os_apis) or "File I/O & Storage" in os_categories or any(k in m_lower for k in ("file", "save", "write", "read", "load", "path", "dir", "extract"))
    has_crypto = any("MessageDigest" in api or "Cipher" in api for api in os_apis) or "Cryptography & Hashing" in os_categories or any(k in m_lower for k in ("hash", "digest", "crypto", "cipher", "secret", "token"))
    has_sql = any("Connection" in api or "Statement" in api for api in os_apis) or "Database / SQL" in os_categories or any(k in m_lower for k in ("query", "sql", "select", "account", "user", "db"))
    has_exec = any("Runtime" in api or "Process" in api for api in os_apis) or "Process & OS Execution" in os_categories or any(k in m_lower for k in ("exec", "command", "cmd", "process", "shell"))

    # Filter valid existing renamings (discard identity or generic)
    renamed: Dict[str, str] = {}
    if existing:
        for k, v in existing.items():
            if not v or not isinstance(v, str):
                continue
            v_clean = v.strip()
            if v_clean == k:
                continue
            if re.match(r"^(var|param)\d+$", v_clean):
                continue
            renamed[k] = v_clean

    used_names: Set[str] = set(renamed.values())

    def allocate_name(var_key: str, base_name: str) -> str:
        name = base_name
        idx = 2
        while name in used_names:
            name = f"{base_name}{idx}"
            idx += 1
        renamed[var_key] = name
        used_names.add(name)
        return name

    # 1. Parameter Renaming
    sig_params = re.findall(r"\b([\w.$]+(?:\[\])*)\s+(param\d+)\b", raw_code)
    extracted_types = {p_name: p_type for p_type, p_name in sig_params}

    param_matches = sorted(set(re.findall(r"\bparam\d+\b", raw_code)), key=lambda x: int(x.replace("param", "")))
    for p_name in param_matches:
        if p_name in renamed:
            continue
        p_idx = int(p_name.replace("param", ""))
        p_type = extracted_types.get(p_name)
        if not p_type and p_idx < len(param_types):
            p_type = param_types[p_idx]
        if not p_type:
            p_type = "Object"

        p_type_simple = p_type.split(".")[-1].split("/")[-1]

        # Specific parameter rules
        if method_name == "main" and ("[]" in p_type_simple or p_type_simple == "String[]"):
            allocate_name(p_name, "args")
            continue

        candidate = None
        # Loop / count context
        if any(k in m_lower for k in ("sum", "evens", "count", "loop", "calculate")) and p_type_simple == "int" and "health" not in m_lower:
            candidate = "limit" if p_idx == 0 else "step"
        # Health / damage context
        elif "health" in m_lower or "damage" in m_lower:
            if p_type_simple == "int":
                candidate = "baseHealth" if p_idx == 0 else "damage"
        # Math calculation
        elif any(k in m_lower for k in ("calc", "math", "add", "multiply", "divide", "sub")):
            if p_type_simple in ("int", "double", "float", "long"):
                candidate = "a" if p_idx == 0 else "b"
        # Database / SQL
        elif p_type_simple == "Connection":
            candidate = "connection"
        elif p_type_simple == "Statement":
            candidate = "statement"
        elif has_sql and p_type_simple == "String":
            if any(k in m_lower for k in ("user", "account", "login", "player")):
                candidate = "userId" if "user" in m_lower else "accountId"
            elif "query" in m_lower or "sql" in m_lower:
                candidate = "sqlQuery"
            else:
                candidate = "queryParam"
        # Network
        elif has_socket and p_type_simple == "String" and p_idx == 0:
            candidate = "host"
        elif has_socket and p_type_simple == "int":
            candidate = "port"
        # File I/O
        elif p_type_simple in ("File", "Path"):
            candidate = "destDir" if any(k in m_lower for k in ("dir", "extract", "folder")) and p_idx == 0 else "targetFile"
        elif has_file and p_type_simple == "String":
            if "extract" in m_lower or "zip" in m_lower or "entry" in m_lower:
                candidate = "fileName"
            else:
                candidate = "filePath"
        # Command / Exec
        elif has_exec and p_type_simple == "String":
            candidate = "command"
        # Crypto
        elif has_crypto and p_type_simple == "byte[]":
            candidate = "payload"
        elif has_crypto and p_type_simple == "String":
            candidate = "secretKey" if "key" in m_lower else "algorithm"

        # General type fallbacks if no contextual match
        if not candidate:
            if p_type_simple == "byte[]":
                candidate = "data"
            elif p_type_simple == "int":
                # Check usage in raw_code
                if "new Socket(" in raw_code and f", {p_name})" in raw_code:
                    candidate = "port"
                elif "while (" in raw_code and (f"< {p_name}" in raw_code or f"<= {p_name}" in raw_code):
                    candidate = "limit"
                elif f"sleep({p_name})" in raw_code:
                    candidate = "timeoutMs"
                else:
                    candidate = "value" if p_idx == 0 else "count"
            elif p_type_simple == "String":
                if f"new Socket({p_name}" in raw_code:
                    candidate = "host"
                elif f"new File({p_name}" in raw_code or (f"new File(" in raw_code and f", {p_name})" in raw_code):
                    candidate = "filePath"
                elif "Runtime.getRuntime().exec(" in raw_code:
                    candidate = "command"
                elif "SELECT " in raw_code or "accounts" in raw_code:
                    candidate = "userId"
                else:
                    candidate = "inputStr" if p_idx == 0 else "text"
            elif p_type_simple == "boolean":
                candidate = "flag"
            elif p_type_simple in ("InputStream", "FileInputStream"):
                candidate = "inputStream"
            elif p_type_simple in ("OutputStream", "FileOutputStream"):
                candidate = "outputStream"
            elif p_type_simple in ("Reader", "BufferedReader"):
                candidate = "reader"
            elif p_type_simple in ("Writer", "BufferedWriter"):
                candidate = "writer"
            elif p_type_simple in ("List", "ArrayList", "Collection"):
                candidate = "items"
            elif p_type_simple in ("Map", "HashMap"):
                candidate = "lookupMap"
            elif p_type_simple in ("Set", "HashSet"):
                candidate = "itemSet"
            else:
                candidate = p_type_simple[:1].lower() + p_type_simple[1:] if p_type_simple else f"arg{p_idx}"

        allocate_name(p_name, candidate)

    # 2. Local Variable Renaming
    local_vars = sorted(set(re.findall(r"\bvar\d+\b", raw_code)), key=lambda x: int(x.replace("var", "")))
    for v_name in local_vars:
        if v_name in renamed:
            continue

        candidate = None

        # Check catch block: catch (... v_name)
        if re.search(r"\bcatch\s*\([^)]*?\b" + re.escape(v_name) + r"\b", raw_code):
            candidate = "e"

        # Check loop induction / counter
        # e.g., v_name = 0; ... while (v_name < ... v_name = v_name + 1)
        is_loop_counter = False
        if re.search(r"\b" + re.escape(v_name) + r"\s*=\s*0\b", raw_code):
            if re.search(r"\bwhile\s*\([^)]*?\b" + re.escape(v_name) + r"\b", raw_code):
                if re.search(r"\b" + re.escape(v_name) + r"\s*=\s*" + re.escape(v_name) + r"\s*\+", raw_code):
                    is_loop_counter = True

        if is_loop_counter and not candidate:
            candidate = "i" if "i" not in used_names else ("j" if "j" not in used_names else "k")

        # Check health context
        if not candidate and ("health" in m_lower or "damage" in m_lower):
            candidate = "currentHealth"

        # Check accumulator
        if not candidate and re.search(r"\b" + re.escape(v_name) + r"\s*=\s*" + re.escape(v_name) + r"\s*[\+\-]", raw_code):
            candidate = "sum" if "sum" in m_lower else "total"

        # Check assignment RHS
        # Find lines: v_name = <RHS>;
        rhs_matches = re.findall(r"\b" + re.escape(v_name) + r"\s*=\s*(.+?);", raw_code)
        if not candidate and rhs_matches:
            rhs_str = " ".join(rhs_matches)

            # Database / SQL
            if "createStatement(" in rhs_str:
                candidate = "statement"
            elif "prepareStatement(" in rhs_str:
                candidate = "preparedStatement"
            elif "executeQuery(" in rhs_str:
                candidate = "resultSet"
            elif "executeUpdate(" in rhs_str:
                candidate = "rowsAffected"

            # StringBuilder / SQL / URL / Path
            elif "new StringBuilder" in rhs_str or "new StringBuffer" in rhs_str or ".toString()" in rhs_str:
                if any(k in rhs_str for k in ("SELECT ", "INSERT ", "UPDATE ", "DELETE ", "FROM ", "accounts")):
                    candidate = "sqlQuery"
                elif "http://" in rhs_str or "https://" in rhs_str:
                    candidate = "targetUrl"
                elif "/" in rhs_str or "\\" in rhs_str:
                    candidate = "pathBuilder"
                elif "new StringBuilder" in rhs_str:
                    candidate = "stringBuilder"
                else:
                    candidate = "resultStr"

            # Sockets / Network
            elif "new Socket(" in rhs_str:
                candidate = "socket"
            elif "new ServerSocket(" in rhs_str:
                candidate = "serverSocket"
            elif ".accept(" in rhs_str:
                candidate = "clientSocket"
            elif ".getInputStream(" in rhs_str:
                candidate = "socketIn"
            elif ".getOutputStream(" in rhs_str:
                candidate = "socketOut"
            elif "new URL(" in rhs_str:
                candidate = "targetUrl"

            # File I/O
            elif "new File(" in rhs_str:
                candidate = "targetFile"
            elif "new FileOutputStream(" in rhs_str:
                candidate = "fileOutStream"
            elif "new FileInputStream(" in rhs_str:
                candidate = "fileInStream"
            elif "new BufferedReader(" in rhs_str:
                candidate = "bufferedReader"
            elif "new BufferedWriter(" in rhs_str:
                candidate = "bufferedWriter"
            elif ".readLine(" in rhs_str:
                candidate = "line"
            elif ".read(" in rhs_str:
                candidate = "bytesRead"

            # Crypto
            elif "MessageDigest.getInstance(" in rhs_str:
                candidate = "digestEngine"
            elif ".digest(" in rhs_str:
                candidate = "computedHash"
            elif "Cipher.getInstance(" in rhs_str:
                candidate = "cipherEngine"
            elif ".doFinal(" in rhs_str:
                candidate = "cipherBytes"

            # Process
            elif "Runtime.getRuntime(" in rhs_str:
                candidate = "runtime"
            elif ".exec(" in rhs_str or "new ProcessBuilder(" in rhs_str:
                candidate = "process"
            elif ".waitFor(" in rhs_str or ".exitValue(" in rhs_str:
                candidate = "exitCode"

            # Parse / Math
            elif "Integer.parseInt(" in rhs_str:
                candidate = "parsedInt"
            elif "Long.parseLong(" in rhs_str:
                candidate = "parsedLong"
            elif "Double.parseDouble(" in rhs_str:
                candidate = "parsedDouble"
            elif ".split(" in rhs_str:
                candidate = "tokens"
            elif ".substring(" in rhs_str:
                candidate = "subStr"
            elif ".toLowerCase(" in rhs_str:
                candidate = "lowerStr"
            elif ".toUpperCase(" in rhs_str:
                candidate = "upperStr"

            # Subtraction / Math
            elif "-" in rhs_str and ("health" in m_lower or "damage" in m_lower):
                candidate = "currentHealth"

        # Check return statement: return v_name;
        if not candidate and re.search(r"\breturn\s+" + re.escape(v_name) + r"\s*;", raw_code):
            if "health" in m_lower:
                candidate = "currentHealth"
            elif "sum" in m_lower:
                candidate = "sum"
            elif "hash" in m_lower:
                candidate = "computedHash"
            else:
                candidate = "result"

        # Fallback if still unassigned
        if not candidate:
            if "health" in m_lower:
                candidate = "currentHealth"
            elif "sum" in m_lower:
                candidate = "total"
            else:
                candidate = "value"

        allocate_name(v_name, candidate)

    return renamed


class SemanticRestorer:
    """Handles prompt construction, Ollama queries, and offline heuristic fallback."""

    def __init__(
        self,
        model: str = "qwen2.5-coder:14b",
        host: str = "http://localhost:11434",
        timeout: int = 45,
        no_llm: bool = False,
    ) -> None:
        self.model = model
        self.host = host.rstrip("/")
        self.timeout = timeout
        self.no_llm = no_llm

    def isOllamaAvailable(self) -> bool:
        if self.no_llm:
            return False
        try:
            req = urllib.request.Request(f"{self.host}/api/tags", method="GET")
            with urllib.request.urlopen(req, timeout=2) as resp:
                return resp.status == 200
        except Exception:
            return False

    def buildPrompt(
        self,
        class_name: str,
        method_name: str,
        raw_code: str,
        os_context: OSContext,
    ) -> str:
        prompt = f"""You are an expert compiler and reverse engineering AI working on NeuroDecomp.
Your task is to analyze raw decompiled Java pseudo-code (Phase 2 output) and restore meaningful semantic variable names and clean Javadoc documentation.

Target Method:
- Enclosing Class: {class_name}
- Method Name: {method_name}
- OS & System Context Clues: {os_context.summary()}

Raw Decompiled Pseudo-Code:
```java
{raw_code}
```

Instructions:
1. Identify all generic placeholder variables like `var0`, `var1`, `var2`, `param0`, `param1`.
2. Infer meaningful, descriptive camelCase names for EVERY SINGLE generic variable based on its mathematical/logical purpose, type, and OS API usage:
   - NEVER keep generic placeholders like `var0`, `var1`, `param0` in your output.
   - For loops/counters: use `i`, `index`, `count`, `limit`.
   - For accumulators/results: use `sum`, `total`, `result`, `retVal`.
   - For DB/SQL: use `connection`, `statement`, `sqlQuery`, `resultSet`, `userId`.
   - For Network/IO: use `socket`, `targetFile`, `fileOutStream`, `buffer`, `payload`, `filePath`.
   - For Strings: infer from intent (e.g., `userName`, `queryParam`, `rawInput`, `line`).
3. Write a concise, professional Javadoc comment explaining what the method computes or executes, including its OS interactions.
4. Output the complete reconstructed Java method with the Javadoc prepended and all generic variables cleanly substituted. Every single variable in the reconstructed code MUST have a semantic name.

Return ONLY a valid JSON object matching this schema:
{{
  "renamed_variables": {{
    "genericVar": "semanticVar"
  }},
  "summary": "1-2 sentence description of what this method does",
  "javadoc": "/**\\n * ...\\n */",
  "reconstructed_code": "/**\\n * ...\\n */\\npublic ..."
}}
"""
        return prompt

    def restoreMethod(
        self,
        class_info: ClassInfo,
        method_name: str,
        raw_code: str,
    ) -> RestorationResult:
        os_context = extractOsContext(class_info, method_name, raw_code)

        if not self.no_llm:
            try:
                result = self._queryOllama(class_info, method_name, raw_code, os_context)
                if result:
                    return result
            except Exception:
                # Fall back gracefully to offline heuristic mode
                pass

        return self._heuristicFallback(class_info, method_name, raw_code, os_context)

    def _queryOllama(
        self,
        class_info: ClassInfo,
        method_name: str,
        raw_code: str,
        os_context: OSContext,
    ) -> Optional[RestorationResult]:
        prompt = self.buildPrompt(class_info.class_name, method_name, raw_code, os_context)
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "format": "json",
            "options": {"temperature": 0.2},
        }

        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            f"{self.host}/api/generate",
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                respBody = response.read().decode("utf-8", errors="replace")
                parsed = json.loads(respBody)
                replyText = parsed.get("response", "")

                data = extractJsonPayload(replyText)
                if not data:
                    return None

                raw_renamed = data.get("renamed_variables", {})
                if not isinstance(raw_renamed, dict):
                    raw_renamed = {}

                # Filter out identity mappings or generic names from LLM
                renamed: Dict[str, str] = {}
                for k, v in raw_renamed.items():
                    if isinstance(k, str) and isinstance(v, str):
                        k_clean = k.strip()
                        v_clean = v.strip()
                        if k_clean and v_clean and k_clean != v_clean and not re.match(r"^(var|param)\d+$", v_clean):
                            renamed[k_clean] = v_clean

                javadoc = stripMarkdownFences(data.get("javadoc", "")).strip()
                reconstructed = stripMarkdownFences(data.get("reconstructed_code", "")).strip()

                m_info = class_info.methods.get(method_name)
                param_types = m_info.param_types if m_info else []

                # Guard against empty, whitespace, or hallucinated output
                if not reconstructed or method_name not in reconstructed:
                    # Fill missing variables with heuristic inference
                    renamed = infer_semantic_variables(
                        class_name=class_info.class_name,
                        method_name=method_name,
                        raw_code=raw_code,
                        param_types=param_types,
                        os_categories=os_context.categories,
                        os_apis=os_context.apis_invoked,
                        existing=renamed,
                    )
                    reconstructed = self._applyRenaming(raw_code, renamed)
                    if javadoc:
                        reconstructed = f"{javadoc}\n{reconstructed}"
                else:
                    # LLM provided reconstructed code
                    # 1. First ensure all renamed variables are applied to reconstructed
                    if renamed:
                        reconstructed = self._applyRenaming(reconstructed, renamed)

                    # 2. Check if reconstructed code still contains any generic var\d+ or param\d+
                    has_leftover_generics = bool(re.search(r"\b(var\d+|param\d+)\b", reconstructed))
                    if has_leftover_generics:
                        # Infer good names for the remaining generic variables
                        additional = infer_semantic_variables(
                            class_name=class_info.class_name,
                            method_name=method_name,
                            raw_code=reconstructed,
                            param_types=param_types,
                            os_categories=os_context.categories,
                            os_apis=os_context.apis_invoked,
                            existing=renamed,
                        )
                        renamed.update(additional)
                        reconstructed = self._applyRenaming(reconstructed, additional)

                return RestorationResult(
                    method_name=method_name,
                    renamed_variables=renamed,
                    javadoc=javadoc,
                    reconstructed_code=reconstructed,
                    mode="ollama",
                )
        except Exception:
            return None

    def _heuristicFallback(
        self,
        class_info: ClassInfo,
        method_name: str,
        raw_code: str,
        os_context: OSContext,
    ) -> RestorationResult:
        """Deterministically recovers variable names and generates Javadoc when LLM is unavailable."""
        m_info = class_info.methods.get(method_name)
        param_types = m_info.param_types if m_info else []

        renamed = infer_semantic_variables(
            class_name=class_info.class_name,
            method_name=method_name,
            raw_code=raw_code,
            param_types=param_types,
            os_categories=os_context.categories,
            os_apis=os_context.apis_invoked,
        )

        # Generate structured Javadoc
        docLines = ["/**", f" * Decompiled method: {method_name}"]
        if os_context.categories:
            docLines.append(" *")
            docLines.append(f" * <p><b>OS & Resource Context:</b> {', '.join(os_context.categories)}")
            docLines.append(f" * <br><b>APIs Referenced:</b> {', '.join(os_context.apis_invoked)}</p>")
        else:
            docLines.append(" * <p>Performs pure computational / algorithmic logic.</p>")

        docLines.append(" *")
        docLines.append(" * @status NeuroDecomp Semantic Restorer (Deterministic Heuristic Mode)")
        docLines.append(" */")
        javadoc = "\n".join(docLines)

        # Substitute variables into raw code
        reconstructed = self._applyRenaming(raw_code, renamed)
        final_code = f"{javadoc}\n{reconstructed}"

        return RestorationResult(
            method_name=method_name,
            renamed_variables=renamed,
            javadoc=javadoc,
            reconstructed_code=final_code,
            mode="offline_heuristic",
        )

    def _applyRenaming(self, code: str, renaming_map: Dict[str, str]) -> str:
        """Replaces exact variable tokens while avoiding substring collisions."""
        result = code
        # Sort by key length descending to prevent prefix collisions
        for oldVar in sorted(renaming_map.keys(), key=len, reverse=True):
            newVar = renaming_map[oldVar]
            pattern = r"\b" + re.escape(oldVar) + r"\b"
            result = re.sub(pattern, newVar, result)
        return result


def restoreClassSemantics(
    class_info: ClassInfo,
    lifted_methods: Dict[str, str],
    restorer: Optional[SemanticRestorer] = None,
) -> Dict[str, RestorationResult]:
    """Applies semantic restoration across all lifted methods in a class."""
    if restorer is None:
        restorer = SemanticRestorer(no_llm=True)

    results: Dict[str, RestorationResult] = {}
    for mName, rawCode in lifted_methods.items():
        results[mName] = restorer.restoreMethod(class_info, mName, rawCode)
    return results
