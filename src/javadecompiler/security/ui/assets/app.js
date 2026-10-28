/**
 * app.js — Client-side controller for NeuroDecomp Drag-and-Drop Web UI.
 * Pure Vanilla JavaScript (zero third-party dependencies).
 */

(function () {
    "use strict";

    // Application State
    let currentScanData = null;
    let activeClass = null;
    let activeMethod = null;
    let activeView = "decompiled"; // "decompiled" | "bytecode"
    let activeSeverityFilter = "all";

    // DOM Elements
    const dropZone = document.getElementById("drop-zone");
    const fileInput = document.getElementById("file-input");
    const btnBrowse = document.getElementById("btn-browse");
    const summarySection = document.getElementById("summary-section");
    const ideContainer = document.getElementById("ide-container");
    const loadingOverlay = document.getElementById("loading-overlay");
    const toggleLlm = document.getElementById("toggle-llm");
    const toggleInvestigate = document.getElementById("toggle-investigate");
    const ollamaStatus = document.getElementById("ollama-status");
    const ollamaStatusText = document.getElementById("ollama-status-text");

    const targetNameDisplay = document.getElementById("target-name-display");
    const verdictBadge = document.getElementById("verdict-badge");
    const riskScoreDisplay = document.getElementById("risk-score-display");
    const coverageDisplay = document.getElementById("coverage-display");
    const coverageSub = document.getElementById("coverage-sub");
    const reasonsList = document.getElementById("reasons-list");

    const treeContainer = document.getElementById("tree-container");
    const explorerSearch = document.getElementById("explorer-search");
    const classCountBadge = document.getElementById("class-count-badge");

    const activeMethodTitle = document.getElementById("active-method-title");
    const activeMethodDesc = document.getElementById("active-method-descriptor");
    const lineNumbers = document.getElementById("line-numbers");
    const codeLines = document.getElementById("code-lines");
    const tabDecompiled = document.getElementById("tab-decompiled");
    const tabBytecode = document.getElementById("tab-bytecode");

    const findingsList = document.getElementById("findings-list");
    const findingsCountBadge = document.getElementById("findings-count-badge");
    const filterChips = document.querySelectorAll(".filter-chip");

    const btnExportJson = document.getElementById("btn-export-json");
    const btnExportSarif = document.getElementById("btn-export-sarif");
    const btnExportHtml = document.getElementById("btn-export-html");
    const btnReset = document.getElementById("btn-reset");

    // Initialize health check
    checkHealth();

    function checkHealth() {
        fetch("/api/health")
            .then(res => res.json())
            .then(data => {
                if (data.ollamaReachable) {
                    ollamaStatus.className = "ollama-status online";
                    ollamaStatusText.textContent = `Ollama: ${data.defaultModel}`;
                } else {
                    ollamaStatus.className = "ollama-status offline";
                    ollamaStatusText.textContent = "Ollama: Offline (Static Only)";
                }
            })
            .catch(() => {
                ollamaStatus.className = "ollama-status offline";
                ollamaStatusText.textContent = "Backend Offline";
            });
    }

    // Drag and Drop Listeners
    ["dragenter", "dragover", "dragleave", "drop"].forEach(eventName => {
        document.body.addEventListener(eventName, preventDefaults, false);
    });

    function preventDefaults(e) {
        e.preventDefault();
        e.stopPropagation();
    }

    ["dragenter", "dragover"].forEach(eventName => {
        dropZone.addEventListener(eventName, () => dropZone.classList.add("dragover"), false);
    });

    ["dragleave", "drop"].forEach(eventName => {
        dropZone.addEventListener(eventName, () => dropZone.classList.remove("dragover"), false);
    });

    dropZone.addEventListener("drop", handleDrop, false);
    btnBrowse.addEventListener("click", () => fileInput.click());
    fileInput.addEventListener("change", handleFileSelect);

    function handleDrop(e) {
        const dt = e.dataTransfer;
        const files = dt.files;
        if (files.length > 0) {
            uploadFile(files[0]);
        }
    }

    function handleFileSelect(e) {
        if (e.target.files.length > 0) {
            uploadFile(e.target.files[0]);
        }
    }

    // Upload & Scan API Call
    function uploadFile(file) {
        const fileName = file.name;
        if (!fileName.endsWith(".class") && !fileName.endsWith(".jar")) {
            alert("Please upload a valid compiled Java .class file or .jar archive.");
            return;
        }

        const scanId = "scan_" + Date.now() + "_" + Math.random().toString(36).substring(2, 8);

        const progressBar = document.getElementById("loading-progress-bar");
        const progressCount = document.getElementById("loading-count");
        const progressPct = document.getElementById("loading-percentage");
        const progressCurrentFn = document.getElementById("loading-current-fn");
        const loadingText = document.getElementById("loading-text");

        if (loadingText) loadingText.textContent = "Decompiling and Auditing Binary...";
        if (progressBar) progressBar.style.width = "0%";
        if (progressCount) progressCount.textContent = "Processing function 0 of 0";
        if (progressPct) progressPct.textContent = "0%";
        if (progressCurrentFn) {
            progressCurrentFn.textContent = "Initializing scan pipeline...";
            progressCurrentFn.title = "Initializing scan pipeline...";
        }

        const isLlmEnabled = toggleLlm.checked;
        const llmContainer = document.getElementById("loading-llm-container");
        const llmBar = document.getElementById("loading-llm-bar");
        const llmCount = document.getElementById("loading-llm-count");
        const llmPct = document.getElementById("loading-llm-percentage");
        const llmFn = document.getElementById("loading-llm-fn");

        if (isLlmEnabled && llmContainer) {
            llmContainer.classList.remove("hidden");
            if (llmBar) llmBar.style.width = "0%";
            if (llmCount) llmCount.textContent = "Auditing candidate 0 of 0";
            if (llmPct) llmPct.textContent = "0%";
            if (llmFn) {
                llmFn.textContent = "Waiting for static scan to identify candidates...";
                llmFn.title = "Waiting for static scan to identify candidates...";
            }
        } else if (llmContainer) {
            llmContainer.classList.add("hidden");
        }

        loadingOverlay.classList.remove("hidden");

        let pollInterval = setInterval(() => {
            fetch(`/api/scan/progress?id=${scanId}`)
                .then(res => res.json())
                .then(prog => {
                    if (prog && prog.total > 0) {
                        const current = prog.current || 0;
                        const total = prog.total;
                        const pct = Math.min(100, Math.round((current / total) * 100));
                        if (progressBar) progressBar.style.width = `${pct}%`;
                        if (progressCount) progressCount.textContent = `Processing function ${current} of ${total}`;
                        if (progressPct) progressPct.textContent = `${pct}%`;
                        if (progressCurrentFn) {
                            let fnDesc = "";
                            if (prog.currentClass && prog.currentMethod) {
                                fnDesc = `${prog.currentClass}#${prog.currentMethod}`;
                            } else if (prog.currentClass) {
                                fnDesc = prog.currentClass;
                            } else if (prog.currentMethod) {
                                fnDesc = prog.currentMethod;
                            } else {
                                fnDesc = "Analyzing bytecode...";
                            }
                            progressCurrentFn.textContent = fnDesc;
                            progressCurrentFn.title = fnDesc;
                        }
                    }

                    // Update LLM progress bar if enabled
                    if (isLlmEnabled && prog && llmContainer) {
                        const llmTotal = prog.llmTotal || 0;
                        const llmCurrent = prog.llmCurrent || 0;
                        if (llmTotal > 0) {
                            const pct = Math.min(100, Math.round((llmCurrent / llmTotal) * 100));
                            if (llmBar) llmBar.style.width = `${pct}%`;
                            if (llmCount) llmCount.textContent = `Auditing candidate ${llmCurrent} of ${llmTotal}`;
                            if (llmPct) llmPct.textContent = `${pct}%`;
                            if (llmFn) {
                                let fnDesc = "";
                                if (prog.llmClass && prog.llmMethod) {
                                    fnDesc = `${prog.llmClass}#${prog.llmMethod}`;
                                } else if (prog.llmClass) {
                                    fnDesc = prog.llmClass;
                                } else if (prog.llmMethod) {
                                    fnDesc = prog.llmMethod;
                                } else {
                                    fnDesc = "Auditing suspicious candidate...";
                                }
                                llmFn.textContent = fnDesc;
                                llmFn.title = fnDesc;
                            }
                        } else if (prog.status === "llm_auditing") {
                            if (llmCount) llmCount.textContent = "Selecting suspicious candidates...";
                            if (llmFn) llmFn.textContent = "Triaging methods...";
                        }
                    }
                })
                .catch(() => {});
        }, 150);

        const reader = new FileReader();
        reader.onload = function (e) {
            const arrayBuffer = e.target.result;
            const bytes = new Uint8Array(arrayBuffer);
            let binary = "";
            for (let i = 0; i < bytes.byteLength; i++) {
                binary += String.fromCharCode(bytes[i]);
            }
            const fileBase64 = btoa(binary);

            const payload = {
                fileName: fileName,
                fileBase64: fileBase64,
                scanId: scanId,
                options: {
                    enableLlm: toggleLlm.checked,
                    llmInvestigate: toggleInvestigate.checked,
                    model: "qwen2.5-coder:14b",
                },
            };

            fetch("/api/scan", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: jsonStringify(payload),
            })
                .then(res => {
                    if (!res.ok) throw new Error(`HTTP error ${res.status}`);
                    return res.json();
                })
                .then(data => {
                    clearInterval(pollInterval);
                    loadingOverlay.classList.add("hidden");
                    if (data.error) {
                        alert("Scan failed: " + data.error);
                        return;
                    }
                    currentScanData = data;
                    renderScanResult(data);
                })
                .catch(err => {
                    clearInterval(pollInterval);
                    loadingOverlay.classList.add("hidden");
                    alert("Error during scan: " + err.message);
                });
        };
        reader.readAsArrayBuffer(file);
    }

    function jsonStringify(obj) {
        return JSON.stringify(obj);
    }

    // Render Full Scan Results
    function renderScanResult(data) {
        dropZone.classList.add("hidden");
        summarySection.classList.remove("hidden");
        ideContainer.classList.remove("hidden");

        const sr = data.scanResult;

        targetNameDisplay.textContent = data.targetName;

        // Verdict Badge
        const verdict = (sr.overallVerdict || "CLEAN").toUpperCase();
        verdictBadge.textContent = verdict;
        verdictBadge.className = "verdict-badge";
        if (verdict === "CLEAN") verdictBadge.classList.add("verdict-clean");
        else if (verdict === "REVIEW_RECOMMENDED") verdictBadge.classList.add("verdict-review");
        else if (verdict === "VULNERABLE") verdictBadge.classList.add("verdict-vulnerable");
        else verdictBadge.classList.add("verdict-suspicious");

        // Risk Score
        const score = sr.overallRiskScore.toFixed(1);
        riskScoreDisplay.innerHTML = `${score} <span class="metric-sub">/ 100</span>`;
        if (score >= 70) riskScoreDisplay.style.color = "var(--accent-red)";
        else if (score >= 40) riskScoreDisplay.style.color = "var(--accent-orange)";
        else if (score >= 20) riskScoreDisplay.style.color = "var(--accent-yellow)";
        else riskScoreDisplay.style.color = "var(--accent-green)";

        // Coverage
        const cov = sr.coverageStats;
        if (cov.partialCoverageMethods === 0) {
            coverageDisplay.textContent = "FULL";
            coverageDisplay.style.color = "var(--accent-green)";
            coverageSub.textContent = `${cov.totalMethods} / ${cov.totalMethods} methods full`;
        } else {
            coverageDisplay.textContent = "PARTIAL";
            coverageDisplay.style.color = "var(--accent-yellow)";
            coverageSub.textContent = `${cov.partialCoverageMethods} methods with partial coverage`;
        }

        // Rationale List
        reasonsList.innerHTML = "";
        (sr.topReasons || []).forEach(r => {
            const li = document.createElement("li");
            li.textContent = r;
            reasonsList.appendChild(li);
        });

        // Populate Explorer Tree
        renderExplorerTree(sr.classes);

        // Populate Findings
        renderFindingsList(getAllFindings(sr));

        // Auto-select first method with findings (or first method overall)
        selectInitialMethod(sr.classes);
    }

    function getAllFindings(sr) {
        const out = [];
        (sr.jarFindings || []).forEach(f => out.push(f));
        Object.values(sr.classes || {}).forEach(c => {
            (c.findings || []).forEach(f => out.push(f));
            Object.values(c.methods || {}).forEach(m => {
                (m.findings || []).forEach(f => out.push(f));
            });
        });
        return out;
    }

    function renderExplorerTree(classesMap) {
        treeContainer.innerHTML = "";
        const classNames = Object.keys(classesMap || {}).sort((a, b) => {
            return (classesMap[b].riskScore || 0) - (classesMap[a].riskScore || 0);
        });

        classCountBadge.textContent = `${classNames.length} class${classNames.length === 1 ? "" : "es"}`;

        classNames.forEach(cName => {
            const cObj = classesMap[cName];
            const classDiv = document.createElement("div");
            classDiv.className = "tree-class";

            const header = document.createElement("div");
            header.className = "tree-class-header";

            const nameSpan = document.createElement("span");
            nameSpan.className = "tree-class-name";
            nameSpan.textContent = cName.split("/").pop();
            nameSpan.title = cName;

            const pill = document.createElement("span");
            pill.className = `pill-sev ${getPillClass(cObj.riskScore)}`;
            pill.textContent = `${cObj.riskScore.toFixed(0)}`;

            header.appendChild(nameSpan);
            header.appendChild(pill);
            classDiv.appendChild(header);

            // Methods list
            const methodNames = Object.keys(cObj.methods || {}).sort((a, b) => {
                return (cObj.methods[b].riskScore || 0) - (cObj.methods[a].riskScore || 0);
            });

            methodNames.forEach(mName => {
                const mObj = cObj.methods[mName];
                const methodDiv = document.createElement("div");
                methodDiv.className = "tree-method";
                methodDiv.dataset.className = cName;
                methodDiv.dataset.methodName = mName;

                const mNameSpan = document.createElement("span");
                mNameSpan.textContent = mName;

                const mPill = document.createElement("span");
                const fCount = (mObj.findings || []).length;
                if (fCount > 0) {
                    mPill.className = `pill-sev ${getPillClass(mObj.riskScore)}`;
                    mPill.textContent = `${fCount}`;
                }

                methodDiv.appendChild(mNameSpan);
                if (fCount > 0) methodDiv.appendChild(mPill);

                methodDiv.addEventListener("click", () => selectMethod(cName, mName));
                classDiv.appendChild(methodDiv);
            });

            treeContainer.appendChild(classDiv);
        });
    }

    function getPillClass(score) {
        if (score >= 70) return "pill-critical";
        if (score >= 40) return "pill-high";
        if (score >= 15) return "pill-medium";
        if (score > 0) return "pill-low";
        return "pill-clean";
    }

    function selectInitialMethod(classesMap) {
        // Try to find first method with riskScore > 0
        for (const [cName, cObj] of Object.entries(classesMap)) {
            for (const [mName, mObj] of Object.entries(cObj.methods || {})) {
                if ((mObj.findings || []).length > 0) {
                    selectMethod(cName, mName);
                    return;
                }
            }
        }
        // Fallback to first method
        for (const [cName, cObj] of Object.entries(classesMap)) {
            for (const mName of Object.keys(cObj.methods || {})) {
                selectMethod(cName, mName);
                return;
            }
        }
    }

    function selectMethod(className, methodName, targetLine = null) {
        activeClass = className;
        activeMethod = methodName;

        document.querySelectorAll(".tree-method").forEach(el => {
            if (el.dataset.className === className && el.dataset.methodName === methodName) {
                el.classList.add("active");
            } else {
                el.classList.remove("active");
            }
        });

        activeMethodTitle.textContent = `${className}#${methodName}`;

        const cObj = currentScanData.scanResult.classes[className];
        const mObj = cObj ? cObj.methods[methodName] : null;
        activeMethodDesc.textContent = mObj ? mObj.descriptor : "";

        renderCodeViewport(className, methodName, targetLine);
    }

    // Render Code Viewport with Line Highlights
    function renderCodeViewport(className, methodName, targetLine = null) {
        lineNumbers.innerHTML = "";
        codeLines.innerHTML = "";

        const decompiledMethod = (currentScanData.decompiled[className] || {})[methodName];
        if (!decompiledMethod) {
            codeLines.innerHTML = '<div class="code-empty-state">No decompiled code available.</div>';
            return;
        }

        const isBytecode = activeView === "bytecode";
        const codeText = isBytecode ? decompiledMethod.bytecodeText : decompiledMethod.liftedSource;
        const lines = codeText.split("\n");

        const cObj = currentScanData.scanResult.classes[className];
        const mObj = cObj ? cObj.methods[methodName] : null;
        const findings = mObj ? (mObj.findings || []) : [];

        // Map line numbers to findings
        const lineFindingsMap = {};
        findings.forEach(f => {
            const locLines = f.location.liftedLineNumbers || [];
            locLines.forEach(lNum => {
                if (!lineFindingsMap[lNum]) lineFindingsMap[lNum] = [];
                lineFindingsMap[lNum].push(f);
            });
        });

        lines.forEach((lineText, idx) => {
            const lineNum = idx + 1;

            // Line number column
            const numDiv = document.createElement("div");
            numDiv.textContent = lineNum;
            lineNumbers.appendChild(numDiv);

            // Code line
            const lineDiv = document.createElement("div");
            lineDiv.className = "code-line";
            lineDiv.id = `code-line-${lineNum}`;
            lineDiv.textContent = lineText;

            // Vulnerability highlighting
            const attachedFindings = lineFindingsMap[lineNum];
            if (attachedFindings && !isBytecode) {
                const maxSev = getHighestSeverity(attachedFindings);
                lineDiv.classList.add(`line-highlight-${maxSev}`);

                // Target scroll anchor
                if (targetLine === lineNum) {
                    lineDiv.classList.add("pulse-target");
                }
            }

            codeLines.appendChild(lineDiv);

            // Append inline finding annotation callout beneath line
            if (attachedFindings && !isBytecode) {
                attachedFindings.forEach(f => {
                    const callout = document.createElement("div");
                    const sev = (f.severity || "medium").toLowerCase();
                    callout.className = `inline-annotation inline-${sev}`;

                    const head = document.createElement("div");
                    head.style.display = "flex";
                    head.style.justifyContent = "space-between";
                    head.style.fontWeight = "bold";

                    const badge = document.createElement("span");
                    badge.textContent = `[${f.severity.toUpperCase()}] ${f.ruleId}: ${f.title}`;
                    head.appendChild(badge);

                    if (f.cwe && f.cwe.length > 0) {
                        const cweSpan = document.createElement("span");
                        cweSpan.style.color = "var(--text-secondary)";
                        cweSpan.textContent = f.cwe.join(", ");
                        head.appendChild(cweSpan);
                    }
                    callout.appendChild(head);

                    const desc = document.createElement("div");
                    desc.style.marginTop = "4px";
                    desc.textContent = f.description;
                    callout.appendChild(desc);

                    if (f.remediation) {
                        const fix = document.createElement("div");
                        fix.style.marginTop = "4px";
                        fix.style.color = "var(--accent-green)";
                        fix.textContent = "Remediation: " + f.remediation;
                        callout.appendChild(fix);
                    }

                    codeLines.appendChild(callout);
                });
            }
        });

        if (targetLine) {
            const targetEl = document.getElementById(`code-line-${targetLine}`);
            if (targetEl) {
                targetEl.scrollIntoView({ behavior: "smooth", block: "center" });
            }
        }
    }

    function getHighestSeverity(findings) {
        const order = ["critical", "high", "medium", "low", "info"];
        for (const s of order) {
            if (findings.some(f => (f.severity || "").toLowerCase() === s)) return s;
        }
        return "medium";
    }

    // Tab Switchers
    tabDecompiled.addEventListener("click", () => {
        activeView = "decompiled";
        tabDecompiled.classList.add("active");
        tabBytecode.classList.remove("active");
        if (activeClass && activeMethod) renderCodeViewport(activeClass, activeMethod);
    });

    tabBytecode.addEventListener("click", () => {
        activeView = "bytecode";
        tabBytecode.classList.add("active");
        tabDecompiled.classList.remove("active");
        if (activeClass && activeMethod) renderCodeViewport(activeClass, activeMethod);
    });

    // Render Right Pane Findings List
    function renderFindingsList(findings) {
        findingsList.innerHTML = "";

        const filtered = findings.filter(f => {
            if (activeSeverityFilter === "all") return true;
            return (f.severity || "").toLowerCase() === activeSeverityFilter;
        });

        findingsCountBadge.textContent = `${filtered.length} finding${filtered.length === 1 ? "" : "s"}`;

        if (filtered.length === 0) {
            findingsList.innerHTML = '<div class="empty-findings">No findings match the selected filter.</div>';
            return;
        }

        filtered.forEach(f => {
            const card = document.createElement("div");
            const sev = (f.severity || "medium").toLowerCase();
            card.className = `finding-card card-${sev}`;

            const title = document.createElement("div");
            title.className = "finding-title";
            title.textContent = `${f.ruleId}: ${f.title}`;
            card.appendChild(title);

            const meta = document.createElement("div");
            meta.className = "finding-meta";
            const locText = f.location.methodName ? `${f.location.className}#${f.location.methodName}` : f.location.className;
            meta.innerHTML = `<span>${f.severity.toUpperCase()} &bull; ${f.category}</span><span>${f.cwe ? f.cwe.join(", ") : ""}</span>`;
            card.appendChild(meta);

            const desc = document.createElement("div");
            desc.className = "finding-desc";
            desc.textContent = f.description;
            card.appendChild(desc);

            if (f.remediation) {
                const rem = document.createElement("div");
                rem.className = "finding-remediation";
                rem.textContent = "Fix: " + f.remediation;
                card.appendChild(rem);
            }

            // Click navigates center pane
            card.addEventListener("click", () => {
                if (f.location.className && f.location.methodName) {
                    const firstLine = (f.location.liftedLineNumbers || [])[0] || 1;
                    selectMethod(f.location.className, f.location.methodName, firstLine);
                }
            });

            findingsList.appendChild(card);
        });
    }

    // Filter Chips
    filterChips.forEach(chip => {
        chip.addEventListener("click", () => {
            filterChips.forEach(c => c.classList.remove("active"));
            chip.classList.add("active");
            activeSeverityFilter = chip.dataset.filter;
            if (currentScanData) {
                renderFindingsList(getAllFindings(currentScanData.scanResult));
            }
        });
    });

    // Explorer Search
    explorerSearch.addEventListener("input", e => {
        const query = e.target.value.toLowerCase();
        document.querySelectorAll(".tree-class").forEach(el => {
            const text = el.textContent.toLowerCase();
            el.style.display = text.includes(query) ? "" : "none";
        });
    });

    // Exports
    btnExportJson.addEventListener("click", () => {
        if (!currentScanData) return;
        downloadBlob(
            new Blob([jsonStringify(currentScanData.scanResult)], { type: "application/json" }),
            `${currentScanData.targetName}_scan.json`
        );
    });

    btnExportSarif.addEventListener("click", () => {
        if (!currentScanData || !currentScanData.sarifReport) return;
        downloadBlob(
            new Blob([currentScanData.sarifReport], { type: "application/json" }),
            `${currentScanData.targetName}.sarif`
        );
    });

    btnExportHtml.addEventListener("click", () => {
        if (!currentScanData || !currentScanData.htmlReport) return;
        downloadBlob(
            new Blob([currentScanData.htmlReport], { type: "text/html" }),
            `${currentScanData.targetName}_report.html`
        );
    });

    function downloadBlob(blob, filename) {
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }

    // Reset UI
    btnReset.addEventListener("click", () => {
        currentScanData = null;
        activeClass = null;
        activeMethod = null;
        summarySection.classList.add("hidden");
        ideContainer.classList.add("hidden");
        dropZone.classList.remove("hidden");
        fileInput.value = "";
    });

})();
