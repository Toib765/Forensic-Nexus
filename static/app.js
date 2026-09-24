let currentUser = null;
let currentCaseId = "CASE-2026-LIVE-DEMO";


function escapeHtml(value) {
    return String(value)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}


function log(message) {
    const terminal = document.getElementById("logTerminal");

    if (!terminal) {
        return;
    }

    terminal.textContent += `\n${message}`;
    terminal.scrollTop = terminal.scrollHeight;
}


function copyLogs() {
    const terminal = document.getElementById("logTerminal");
    const button = document.getElementById("copyLogBtn");

    if (!terminal) {
        return;
    }

    navigator.clipboard.writeText(terminal.textContent).then(() => {
        if (!button) {
            return;
        }

        button.textContent = "✓ Copied!";

        setTimeout(() => {
            button.textContent = "📋 Copy Log";
        }, 1500);
    });
}


function getAuthHeaders() {
    const token = getAuthToken();

    return {
        "Content-Type": "application/json",
        "Authorization": token ? `Bearer ${token}` : ""
    };
}


function validateTargetPath(value) {
    const path = String(value || "").trim();

    if (!path) {
        throw new Error("Target path is required.");
    }

    if (path.includes("\0")) {
        throw new Error("Target path contains an invalid character.");
    }

    return path;
}


async function parseResponse(response) {
    const contentType = response.headers.get("content-type") || "";

    if (contentType.includes("application/json")) {
        return response.json();
    }

    return {
        detail: await response.text()
    };
}


async function handleLogin(event) {
    event.preventDefault();

    const username = document.getElementById("loginUser").value.trim();
    const password = document.getElementById("loginPass").value;
    const errorBox = document.getElementById("loginError");

    errorBox.style.display = "none";

    try {
        const response = await fetch("/api/v1/auth/login", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                username,
                password
            })
        });

        const body = await parseResponse(response);

        if (!response.ok) {
            throw new Error(body.detail || "Invalid login credentials.");
        }

        setAuthToken(body.data.token);
        currentUser = body.data;

        document.getElementById("authOverlay").style.display = "none";

        applyRBAC();
        log(`[+] Operator authenticated: ${currentUser.username} (${currentUser.role})`);

        await fetchDrives();
    } catch (error) {
        errorBox.textContent = error.message;
        errorBox.style.display = "block";
    }
}


async function logout() {
    try {
        await fetch("/api/v1/auth/logout", {
            method: "POST",
            headers: getAuthHeaders()
        });
    } catch (error) {
        // The local session is still cleared below.
    }

    clearAuthToken();
    currentUser = null;
    window.location.reload();
}


async function checkSession() {
    const token = getAuthToken();
    const overlay = document.getElementById("authOverlay");

    if (!token) {
        overlay.style.display = "flex";
        return;
    }

    try {
        const response = await fetch("/api/v1/auth/me", {
            headers: getAuthHeaders()
        });

        const body = await parseResponse(response);

        if (!response.ok) {
            throw new Error(body.detail || "Session expired.");
        }

        currentUser = body.data;
        overlay.style.display = "none";

        applyRBAC();
        await fetchDrives();
    } catch (error) {
        clearAuthToken();
        currentUser = null;
        overlay.style.display = "flex";
    }
}

function handleSessionExpired() {
    clearAuthToken();
    currentUser = null;

    const overlay = document.getElementById("authOverlay");
    if (overlay) {
        overlay.style.display = "flex";
    }

    log("[!] Session expired. Please authenticate again.");
}



function applyRBAC() {
    if (!currentUser) {
        return;
    }

    const profile = document.getElementById("userProfileDisplay");

    profile.replaceChildren();

    const operatorText = document.createElement("span");
    operatorText.textContent =
        `Operator: ${currentUser.username} (${currentUser.role})`;

    const logoutButton = document.createElement("button");
    logoutButton.className = "logout-btn";
    logoutButton.textContent = "Logout";
    logoutButton.addEventListener("click", logout);

    profile.append(operatorText, logoutButton);

    const recoveryButton = document.getElementById("tabRecoveryBtn");
    const sanitizeButton = document.getElementById("tabSanitizeBtn");
    const vaultButton = document.getElementById("tabVaultBtn");

    if (currentUser.role === "ErasureOperator") {
        recoveryButton.style.display = "none";
        sanitizeButton.style.display = "flex";
        vaultButton.style.display = "flex";
        switchTab("sanitize");
    } else if (currentUser.role === "ForensicInvestigator") {
        recoveryButton.style.display = "flex";
        sanitizeButton.style.display = "none";
        vaultButton.style.display = "flex";
        switchTab("recovery");
    } else {
        recoveryButton.style.display = "flex";
        sanitizeButton.style.display = "flex";
        vaultButton.style.display = "flex";
        switchTab("recovery");
    }
}


function switchTab(tab) {
    document.querySelectorAll(".tab-btn").forEach((button) => {
        button.classList.remove("active", "sanitize-active");
    });

    document.querySelectorAll(".workspace").forEach((workspace) => {
        workspace.classList.remove("active");
    });

    if (tab === "recovery") {
        document.getElementById("tabRecoveryBtn").classList.add("active");
        document.getElementById("wsRecovery").classList.add("active");
    }

    if (tab === "sanitize") {
        document.getElementById("tabSanitizeBtn").classList.add("sanitize-active");
        document.getElementById("wsSanitize").classList.add("active");
    }

    if (tab === "vault") {
        document.getElementById("tabVaultBtn").classList.add("active");
        document.getElementById("wsVault").classList.add("active");
        loadAuditLedger();
    }
}


function selectDrive(path, safeForErasure = true) {
    if (!safeForErasure) {
        log("[!] This device is not safe for erasure.");
        return;
    }

    document.getElementById("targetPathCarve").value = path;
    document.getElementById("targetPathSanitize").value = path;

    log(`[*] Target media assigned to: ${path}`);
}


async function fetchDrives() {
    log("[*] Querying storage devices...");

    try {
        const response = await fetch(
            "/api/v1/erasure/drives",
            {
                headers: getAuthHeaders()
            }
        );

        const body = await parseResponse(response);

        if (response.status === 401) {
            handleSessionExpired();
            return;
        }

        if (!response.ok) {
            throw new Error(body.detail || "Drive scan failed.");
        }

        const drives = body.drives || [];
        const grid = document.getElementById("driveList");

        grid.replaceChildren();

        if (drives.length === 0) {
            const empty = document.createElement("div");
            empty.className = "drive-card";
            empty.textContent = "No block devices detected.";
            grid.appendChild(empty);
            return;
        }

        for (const drive of drives) {
            const card = document.createElement("div");
            card.className = "drive-card";

            const details = document.createElement("div");

            const name = document.createElement("div");
            name.className = "drive-name";
            name.textContent = `${drive.name || "Unknown"} (${drive.path || "N/A"})`;

            const metadata = document.createElement("div");
            metadata.className = "drive-meta";
            metadata.textContent =
                `${drive.type || "DEVICE"} • ` +
                `${drive.size || "unknown size"}`;

            details.append(name, metadata);

            if (drive.unsafe_reason) {
                const warning = document.createElement("div");
                warning.className = "drive-meta";
                warning.style.color = "#ff7597";
                warning.textContent = `Unavailable: ${drive.unsafe_reason}`;
                details.appendChild(warning);
            }

            const selectButton = document.createElement("button");
            selectButton.className = "select-btn";
            selectButton.textContent = drive.safe_for_erasure
                ? "Select"
                : "Unsafe";

            selectButton.disabled = !drive.safe_for_erasure;

            selectButton.addEventListener("click", () => {
                selectDrive(
                    drive.path,
                    drive.safe_for_erasure
                );
            });

            card.append(details, selectButton);
            grid.appendChild(card);
        }

        log(`[+] Detected ${drives.length} storage device(s).`);
    } catch (error) {
        log(`[-] Error scanning drives: ${error.message}`);
    }
}


async function downloadCertificate(jobId) {
    try {
        const response = await fetch(
            `/api/v1/erasure/certificate/${encodeURIComponent(jobId)}`,
            {
                headers: getAuthHeaders()
            }
        );

        if (response.status === 401) {
            handleSessionExpired();
            return;
        }

        if (!response.ok) {
            const body = await parseResponse(response);
            throw new Error(body.detail || "Certificate request failed.");
        }

        const blob = await response.blob();
        const url = URL.createObjectURL(blob);

        window.open(url, "_blank");

        setTimeout(() => {
            URL.revokeObjectURL(url);
        }, 60_000);
    } catch (error) {
        log(`[-] Certificate download failed: ${error.message}`);
    }
}


async function loadAuditLedger() {
    try {
        const response = await fetch(
            "/api/v1/erasure/ledger",
            {
                headers: getAuthHeaders()
            }
        );

        const body = await parseResponse(response);

        if (response.status === 401) {
            handleSessionExpired();
            return;
        }

        if (!response.ok) {
            throw new Error(body.detail || "Unable to load audit ledger.");
        }

        const ledger = body.data || [];
        const tableBody = document.getElementById("ledgerBody");

        tableBody.replaceChildren();

        for (const item of ledger) {
            const row = document.createElement("tr");

            const jobCell = document.createElement("td");
            jobCell.className = "mono";
            jobCell.textContent = item.job_id || "N/A";

            const operationCell = document.createElement("td");
            operationCell.textContent = item.operation || "N/A";

            const targetCell = document.createElement("td");
            targetCell.className = "mono";
            targetCell.textContent = item.target_path || "N/A";

            const hashCell = document.createElement("td");
            hashCell.className = "mono";
            hashCell.textContent = item.audit_hash || "N/A";

            const statusCell = document.createElement("td");
            statusCell.textContent = item.status || "N/A";

            const actionCell = document.createElement("td");

            if (item.operation === "SANITIZATION") {
                const certificateButton = document.createElement("button");
                certificateButton.className = "select-btn";
                certificateButton.textContent = "Certificate";

                certificateButton.addEventListener("click", () => {
                    downloadCertificate(item.job_id);
                });

                actionCell.appendChild(certificateButton);
            } else {
                actionCell.textContent = "READ-ONLY CARVE";
            }

            row.append(
                jobCell,
                operationCell,
                targetCell,
                hashCell,
                statusCell,
                actionCell
            );

            tableBody.appendChild(row);
        }
    } catch (error) {
        log(`[-] Failed to load audit ledger: ${error.message}`);
    }
}


function renderEntropyHeatmap(sampleMap) {
    const grid = document.getElementById("entropyGrid");
    const tooltip = document.getElementById("blockTooltip");

    if (!grid || !sampleMap) {
        return;
    }

    grid.replaceChildren();

    for (const block of sampleMap) {
        const cell = document.createElement("div");
        cell.className = "cell";

        if (
            block.entropy === 0 ||
            block.classification === "ZEROED_SANITIZED"
        ) {
            cell.classList.add("cell-zero");
        } else if (block.entropy < 4.5) {
            cell.classList.add("cell-struct");
        } else {
            cell.classList.add("cell-high");
        }

        cell.addEventListener("mouseenter", () => {
            tooltip.textContent =
                `Block #${block.block_index} | ` +
                `Offset: ${block.byte_offset} | ` +
                `Entropy: ${block.entropy} | ` +
                `${block.classification}`;
        });

        grid.appendChild(cell);
    }
}


async function inspectHex(fileName, category, sha256) {
    const modal = document.getElementById("hexModal");
    const title = document.getElementById("modalFileName");
    const metadata = document.getElementById("modalFileMeta");
    const container = document.getElementById("hexContainer");

    title.textContent = fileName;
    metadata.textContent = `Category: ${category} | SHA-256: ${sha256}`;
    container.textContent = "Loading hex data...";
    modal.classList.add("active");

    const query = new URLSearchParams({
        case_id: currentCaseId,
        file_name: fileName,
        category,
        length: "512"
    });

    try {
        const response = await fetch(
            `/api/v1/recovery/hex-inspect?${query.toString()}`,
            {
                headers: getAuthHeaders()
            }
        );

        const body = await parseResponse(response);

        if (response.status === 401) {
            handleSessionExpired();
            throw new Error("Session expired.");
        }

        if (!response.ok) {
            throw new Error(body.detail || "Hex inspection failed.");
        }

        container.replaceChildren();

        for (const line of body.hex_lines || []) {
            const row = document.createElement("div");
            row.className = "hex-row";

            const offset = document.createElement("span");
            offset.className = "hex-offset";
            offset.textContent = line.offset;

            const bytes = document.createElement("span");
            bytes.className = "hex-bytes";
            bytes.textContent = line.hex;

            const ascii = document.createElement("span");
            ascii.className = "hex-ascii";
            ascii.textContent = line.ascii;

            row.append(offset, bytes, ascii);
            container.appendChild(row);
        }
    } catch (error) {
        container.textContent = `Error: ${error.message}`;
    }
}


function closeHexModal() {
    document.getElementById("hexModal").classList.remove("active");
}


function renderCarvingResult(result) {
    const gallery = document.getElementById("evidenceGallery");
    const badge = document.getElementById("recoveryCountBadge");

    gallery.replaceChildren();

    const count = result.deleted_files_recovered || 0;
    badge.textContent = `${count} Recovered`;

    if (result.entropy_analysis?.sample_map) {
        renderEntropyHeatmap(result.entropy_analysis.sample_map);
    }

    if (!result.carved_catalog || result.carved_catalog.length === 0) {
        const empty = document.createElement("div");
        empty.style.gridColumn = "1 / -1";
        empty.textContent = "No recoverable deleted files found.";
        gallery.appendChild(empty);
        return;
    }

    for (const item of result.carved_catalog) {
        const card = document.createElement("div");
        card.className = "evidence-card";

        const thumbnail = document.createElement("div");
        thumbnail.className = "evidence-thumb";

        if (item.category === "Images") {
            const image = document.createElement("img");
            image.src =
                `/cases/${encodeURIComponent(result.job_id)}` +
                `/carved_evidence/images/` +
                `${encodeURIComponent(item.file_name)}`;
            image.alt = "Recovered evidence";
            thumbnail.appendChild(image);
        } else {
            thumbnail.textContent = "📄";
        }

        const metadata = document.createElement("div");
        metadata.className = "evidence-meta";

        const title = document.createElement("div");
        title.className = "evidence-title";
        title.textContent = item.file_name;

        const type = document.createElement("div");
        type.textContent =
            `${item.file_type} • ` +
            `${((item.size_bytes || 0) / 1024).toFixed(1)} KB`;

        const confidence = document.createElement("span");
        confidence.className =
            item.confidence_score >= 90
                ? "badge badge-verified"
                : "badge badge-partial";

        confidence.textContent =
            `${item.classification} (${item.confidence_score}%)`;

        metadata.append(title, type, confidence);
        card.append(thumbnail, metadata);

        card.addEventListener("click", () => {
            inspectHex(
                item.file_name,
                item.category,
                item.sha256
            );
        });

        gallery.appendChild(card);
    }
}


async function runCarving() {
    const pathInput = document.getElementById("targetPathCarve");
    const caseInput = document.getElementById("caseIdCarve");
    const mode = document.getElementById("carveMode").value;
    const button = document.getElementById("startCarveBtn");

    let path;
    let caseId;

    try {
        path = validateTargetPath(pathInput.value);
        caseId = caseInput.value.trim();

        if (!caseId) {
            throw new Error("Case ID is required.");
        }
    } catch (error) {
        log(`[-] ${error.message}`);
        return;
    }

    currentCaseId = caseId;
    button.disabled = true;
    button.textContent = "Carving...";

    document.getElementById(
        "engineStatusBadge"
    ).textContent = "CARVING_IN_PROGRESS";

    const payload = {
        job_id: caseId,
        target_path: path,
        output_dir: "./cases",
        scan_unallocated_only: mode === "unallocated_only"
    };

    try {
        const response = await fetch(
            "/api/v1/recovery/carve",
            {
                method: "POST",
                headers: getAuthHeaders(),
                body: JSON.stringify(payload)
            }
        );

        const body = await parseResponse(response);

        if (response.status === 401) {
            handleSessionExpired();
            throw new Error("Session expired.");
        }

        if (!response.ok) {
            throw new Error(body.detail || "Recovery request failed.");
        }

        const result = body.data;
        currentCaseId = result.job_id;

        log(
            `[+] Carving complete. ` +
            `${result.deleted_files_recovered || 0} file(s) recovered.`
        );

        renderCarvingResult(result);
    } catch (error) {
        log(`[-] Carving failed: ${error.message}`);
    } finally {
        button.disabled = false;
        button.textContent = "⚡ Start Forensic Deep Carving";

        document.getElementById(
            "engineStatusBadge"
        ).textContent = "ENGINE_IDLE";
    }
}


async function runSanitization() {
    const button = document.getElementById("startSanitizeBtn");

    let path;

    try {
        path = validateTargetPath(
            document.getElementById("targetPathSanitize").value
        );
    } catch (error) {
        log(`[-] ${error.message}`);
        return;
    }

    const method = document.getElementById("sanitizeStandard").value;
    const coverage = Number(
        document.getElementById("verifyCoverage").value
    );

    const confirmed = window.confirm(
        `WARNING:\n\n` +
        `You are about to permanently overwrite:\n${path}\n\n` +
        `Method: ${method}\n` +
        `Verification coverage: ${coverage}%\n\n` +
        `Continue?`
    );

    if (!confirmed) {
        return;
    }

    button.disabled = true;
    button.textContent = "Sanitizing...";

    document.getElementById(
        "engineStatusBadge"
    ).textContent = "OVERWRITE_IN_PROGRESS";

    try {
        const response = await fetch(
            "/api/v1/erasure/execute",
            {
                method: "POST",
                headers: getAuthHeaders(),
                body: JSON.stringify({
                    target_path: path,
                    method,
                    verification_coverage_pct: coverage
                })
            }
        );

        const body = await parseResponse(response);

        if (response.status === 401) {
            handleSessionExpired();
            throw new Error("Session expired.");
        }

        if (!response.ok) {
            throw new Error(body.detail || "Sanitization request failed.");
        }

        const data = body.data;

        if (data.verified === true) {
            log(
                `[+] Sanitization verified. ` +
                `Job: ${data.job_id}`
            );
            log(
                `[+] Verified coverage: ` +
                `${data.verification_coverage_pct}%`
            );

            window.alert(
                `Sanitization verified.\n\nJob: ${data.job_id}`
            );
        } else {
            log(
                `[-] Sanitization failed: ` +
                `${data.status || "verification failed"}`
            );

            window.alert(
                "Sanitization verification failed. " +
                "The target was not deleted automatically."
            );
        }
    } catch (error) {
        log(`[-] Sanitization failed: ${error.message}`);
    } finally {
        button.disabled = false;
        button.textContent = "☠ Execute Media Sanitization";

        document.getElementById(
            "engineStatusBadge"
        ).textContent = "ENGINE_IDLE";
    }
}


window.addEventListener("DOMContentLoaded", () => {
    const emptyMap = Array.from(
        { length: 64 },
        (_, index) => ({
            block_index: index + 1,
            byte_offset: index * 65536,
            entropy: 0,
            classification: "ZEROED_SANITIZED"
        })
    );

    renderEntropyHeatmap(emptyMap);
    checkSession();
});