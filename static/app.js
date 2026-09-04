let currentUser = null;
let currentCaseId = "CASE-2026-LIVE-DEMO";

function log(msg) {
    const term = document.getElementById('logTerminal');
    term.textContent += "\n" + msg;
    term.scrollTop = term.scrollHeight;
}

function copyLogs() {
    const text = document.getElementById('logTerminal').textContent;
    navigator.clipboard.writeText(text).then(() => {
        const btn = document.getElementById('copyLogBtn');
        btn.innerHTML = '&#10003; Copied!';
        setTimeout(() => { btn.innerHTML = '&#128203; Copy Log'; }, 1500);
    });
}

function getAuthHeaders() {
    const token = localStorage.getItem('fn_token');
    return {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
    };
}

async function handleLogin(e) {
    e.preventDefault();
    const userInp = document.getElementById('loginUser').value.trim();
    const passInp = document.getElementById('loginPass').value.trim();
    const errBox = document.getElementById('loginError');

    errBox.style.display = 'none';

    try {
        const res = await fetch('/api/v1/auth/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username: userInp, password: passInp })
        });
        const data = await res.json();
        if (!res.ok) {
            errBox.innerText = data.detail || 'Access Denied. Invalid credentials.';
            errBox.style.display = 'block';
            return;
        }

        localStorage.setItem('fn_token', data.data.token);
        currentUser = data.data;
        document.getElementById('authOverlay').style.display = 'none';
        applyRBAC();
        log(`[+] Operator authenticated: ${currentUser.username} (${currentUser.role})`);
        fetchDrives();
    } catch (err) {
        errBox.innerText = 'Authentication server connection error.';
        errBox.style.display = 'block';
    }
}

async function logout() {
    try {
        await fetch('/api/v1/auth/logout', { method: 'POST', headers: getAuthHeaders() });
    } catch (e) {}
    localStorage.removeItem('fn_token');
    currentUser = null;
    location.reload();
}

async function checkSession() {
    const token = localStorage.getItem('fn_token');
    if (!token) {
        document.getElementById('authOverlay').style.display = 'flex';
        return;
    }
    try {
        const res = await fetch('/api/v1/auth/me', { headers: getAuthHeaders() });
        const data = await res.json();
        if (res.ok) {
            currentUser = data.data;
            document.getElementById('authOverlay').style.display = 'none';
            applyRBAC();
            fetchDrives();
        } else {
            localStorage.removeItem('fn_token');
            document.getElementById('authOverlay').style.display = 'flex';
        }
    } catch (err) {
        document.getElementById('authOverlay').style.display = 'flex';
    }
}

function applyRBAC() {
    if (!currentUser) return;

    document.getElementById('userProfileDisplay').innerHTML = `
        <span>Operator: <b style="color:var(--accent-emerald);">${currentUser.username}</b> (<font color="#00e5ff">${currentUser.role}</font>)</span>
        <button class="logout-btn" onclick="logout()">Logout</button>
    `;

    const tabRec = document.getElementById('tabRecoveryBtn');
    const tabSan = document.getElementById('tabSanitizeBtn');
    const tabVlt = document.getElementById('tabVaultBtn');

    if (currentUser.role === 'ErasureOperator') {
        tabRec.style.display = 'none';
        tabSan.style.display = 'flex';
        tabVlt.style.display = 'flex';
        switchTab('sanitize');
    } else if (currentUser.role === 'ForensicInvestigator') {
        tabRec.style.display = 'flex';
        tabSan.style.display = 'none';
        tabVlt.style.display = 'flex';
        switchTab('recovery');
    } else { // Admin
        tabRec.style.display = 'flex';
        tabSan.style.display = 'flex';
        tabVlt.style.display = 'flex';
        switchTab('recovery');
    }
}

function switchTab(tab) {
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active', 'sanitize-active'));
    document.querySelectorAll('.workspace').forEach(w => w.classList.remove('active'));
    
    if (tab === 'recovery') {
        document.getElementById('tabRecoveryBtn').classList.add('active');
        document.getElementById('wsRecovery').classList.add('active');
    } else if (tab === 'sanitize') {
        document.getElementById('tabSanitizeBtn').classList.add('sanitize-active');
        document.getElementById('wsSanitize').classList.add('active');
    } else if (tab === 'vault') {
        document.getElementById('tabVaultBtn').classList.add('active');
        document.getElementById('wsVault').classList.add('active');
        loadAuditLedger();
    }
}

function selectDrive(path) {
    document.getElementById('targetPathCarve').value = path;
    document.getElementById('targetPathSanitize').value = path;
    log(`[*] Target media assigned to: ${path}`);
}

async function fetchDrives() {
    log("[*] Querying kernel block storage controller...");
    try {
        const res = await fetch('/api/v1/erasure/drives', { headers: getAuthHeaders() });
        const data = await res.json();
        if (data.drives) {
            const grid = document.getElementById('driveList');
            grid.innerHTML = '';
            data.drives.forEach(d => {
                grid.innerHTML += `
                    <div class="drive-card">
                        <div>
                            <div class="drive-name">${d.name} (${d.path})</div>
                            <div class="drive-meta">${d.type} &bull; ${d.size_gb} GB</div>
                        </div>
                        <button class="select-btn" onclick="selectDrive('${d.path}')">Select</button>
                    </div>
                `;
            });
            log(`[+] Detected ${data.drives.length} active block storage node(s).`);
        }
    } catch (err) {
        log(`[-] Error scanning drives: ${err}`);
    }
}

async function loadAuditLedger() {
    try {
        const res = await fetch('/api/v1/erasure/ledger', { headers: getAuthHeaders() });
        const resp = await res.json();
        if (resp.data) {
            const tbody = document.getElementById('ledgerBody');
            tbody.innerHTML = '';
            resp.data.forEach(item => {
                const isSanitize = item.operation === "SANITIZATION";
                const badgeClass = isSanitize ? 'style="background:rgba(255, 42, 95, 0.15); border:1px solid rgba(255, 42, 95, 0.4); color:#ff7597;"' : 'class="badge badge-verified"';
                const certCol = isSanitize 
                    ? `<a href="/api/v1/erasure/certificate/${item.job_id}" target="_blank" style="background:#0284c7; color:#fff; padding:4px 8px; border-radius:4px; text-decoration:none; font-size:10px; font-weight:700;">&#128196; NIST Certificate</a>`
                    : `<span class="mono" style="font-size: 10px; color:#00e5ff;">&#128274; READ-ONLY CARVE</span>`;

                tbody.innerHTML += `
                    <tr>
                        <td class="mono"><b>${item.job_id}</b></td>
                        <td><span ${badgeClass}>${item.operation}</span></td>
                        <td class="mono">${item.target_path}</td>
                        <td class="mono" style="font-size: 9px;">${item.audit_hash}</td>
                        <td style="color:${isSanitize ? '#ff7597' : '#34d399'}; font-weight:600;">${item.status}</td>
                        <td>${certCol}</td>
                    </tr>
                `;
            });
        }
    } catch (err) {
        log(`[-] Failed to load database ledger: ${err}`);
    }
}

function renderEntropyHeatmap(sampleMap) {
    const grid = document.getElementById('entropyGrid');
    const tooltip = document.getElementById('blockTooltip');
    if (!grid || !sampleMap) return;
    grid.innerHTML = '';

    sampleMap.forEach(block => {
        const cell = document.createElement('div');
        cell.className = 'cell';
        if (block.entropy === 0 || block.classification === "ZEROED_SANITIZED") {
            cell.classList.add('cell-zero');
        } else if (block.entropy < 4.5) {
            cell.classList.add('cell-struct');
        } else {
            cell.classList.add('cell-high');
        }
        cell.onmouseenter = () => {
            tooltip.innerHTML = `<b>Block #${block.block_index}</b> | Offset: 0x${block.byte_offset.toString(16).toUpperCase()} (${block.byte_offset.toLocaleString()} B) | Entropy: <font color="#00e5ff">${block.entropy.toFixed(4)}</font> [${block.classification}]`;
        };
        grid.appendChild(cell);
    });
}

async function inspectHex(fileName, category, sha256) {
    const modal = document.getElementById('hexModal');
    const title = document.getElementById('modalFileName');
    const meta = document.getElementById('modalFileMeta');
    const container = document.getElementById('hexContainer');

    title.innerText = fileName;
    meta.innerHTML = `Category: <b>${category}</b> | SHA-256: <code>${sha256}</code>`;
    container.innerHTML = '<div style="color:var(--text-dim); padding:30px; text-align:center;">Streaming raw sectors into hex matrix...</div>';
    modal.classList.add('active');

    try {
        const res = await fetch(`/api/v1/recovery/hex-inspect?case_id=${currentCaseId}&file_name=${fileName}&category=${category}&length=512`, {
            headers: getAuthHeaders()
        });
        const data = await res.json();
        
        if (data.hex_lines && data.hex_lines.length > 0) {
            container.innerHTML = '';
            data.hex_lines.forEach((line, idx) => {
                const isHeader = (idx === 0);
                const hexFormatted = isHeader 
                    ? `<span class="hex-magic">${line.hex.substring(0, 11)}</span>${line.hex.substring(11)}`
                    : line.hex;

                container.innerHTML += `
                    <div class="hex-row">
                        <span class="hex-offset">${line.offset}</span>
                        <span class="hex-bytes">${hexFormatted}</span>
                        <span class="hex-ascii">${line.ascii}</span>
                    </div>
                `;
            });
        } else {
            container.innerHTML = '<div style="color:#ff2a5f;">Unable to render hex slice.</div>';
        }
    } catch (err) {
        container.innerHTML = `<div style="color:#ff2a5f;">Error: ${err}</div>`;
    }
}

function closeHexModal() {
    document.getElementById('hexModal').classList.remove('active');
}

async function runCarving() {
    const path = document.getElementById('targetPathCarve').value;
    const caseId = document.getElementById('caseIdCarve').value;
    const mode = document.getElementById('carveMode').value;
    const btn = document.getElementById('startCarveBtn');
    currentCaseId = caseId;

    btn.disabled = true;
    btn.innerHTML = '&#9203; Carving Sectors...';
    document.getElementById('engineStatusBadge').innerText = 'CARVING_IN_PROGRESS';
    log(`[*] Ingesting raw block sectors from ${path} (Strict Read-Only)...`);

    const payload = {
        job_id: caseId,
        target_path: path,
        output_dir: "./cases",
        scan_unallocated_only: mode.includes("Unallocated")
    };

    try {
        const res = await fetch('/api/v1/recovery/carve', {
            method: 'POST',
            headers: getAuthHeaders(),
            body: JSON.stringify(payload)
        });
        
        const responseJson = await res.json();
        
        if (!res.ok) {
            log(`[-] Server Error [${res.status}]: ${JSON.stringify(responseJson)}`);
            return;
        }

        const result = responseJson.data ? responseJson.data : responseJson;
        const bytesTotal = result.target_size_bytes || 134217728;
        const recCount = result.deleted_files_recovered !== undefined ? result.deleted_files_recovered : (result.carved_catalog ? result.carved_catalog.length : 0);
        const auditHash = result.audit_hash || "N/A";

        log(`[+] Deep carving complete! Processed ${bytesTotal.toLocaleString()} bytes.`);
        log(`[+] Carved ${recCount} deleted file(s) with SHA-256 seal: ${auditHash}`);
        document.getElementById('recoveryCountBadge').innerText = `${recCount} Recovered`;

        if (result.entropy_analysis && result.entropy_analysis.sample_map) {
            renderEntropyHeatmap(result.entropy_analysis.sample_map);
        }

        const gallery = document.getElementById('evidenceGallery');
        gallery.innerHTML = '';
        if (result.carved_catalog && result.carved_catalog.length > 0) {
            result.carved_catalog.forEach(item => {
                const isImg = item.category === "Images";
                let icon = "&#128196;";
                if (item.category === "Databases") icon = "&#128452;";
                else if (item.category === "Network") icon = "&#127760;";
                else if (item.category === "Media") icon = "&#127916;";

                const thumbContent = isImg 
                    ? `<img src="/cases/${result.job_id}/carved_evidence/images/${item.file_name}" alt="Evidence" onerror="this.src=''"/>` 
                    : `<div class="doc-icon">${icon}</div>`;
                
                gallery.innerHTML += `
                    <div class="evidence-card" onclick="inspectHex('${item.file_name}', '${item.category}', '${item.sha256}')">
                        <div class="evidence-thumb">${thumbContent}</div>
                        <div class="evidence-meta">
                            <div class="evidence-title">${item.file_name}</div>
                            <div style="color:var(--text-dim); margin-top:2px;">${item.file_type} &bull; ${((item.size_bytes||0)/1024).toFixed(1)} KB</div>
                            <span class="badge ${item.confidence_score >= 90 ? 'badge-verified' : 'badge-partial'}">
                                ${item.classification} (${item.confidence_score}%)
                            </span>
                        </div>
                    </div>
                `;
            });
        } else {
            gallery.innerHTML = '<div style="grid-column: 1/-1; text-align: center; padding: 40px; color: var(--text-dim);">No recoverable deleted files found (Drive Sanitized).</div>';
        }

    } catch (err) {
        log(`[-] Carving failed: ${err}`);
    } finally {
        btn.disabled = false;
        btn.innerHTML = '&#9889; Start Forensic Deep Carving';
        document.getElementById('engineStatusBadge').innerText = 'ENGINE_IDLE';
    }
}

async function runSanitization() {
    const path = document.getElementById('targetPathSanitize').value;
    const method = document.getElementById('sanitizeStandard').value;
    const coverage = parseFloat(document.getElementById('verifyCoverage').value);
    const btn = document.getElementById('startSanitizeBtn');

    if (!confirm(`CRITICAL WARNING:\n\nAre you sure you want to sanitize ${path} using ${method}?\nAll physical sectors will be permanently overwritten.`)) {
        return;
    }

    btn.disabled = true;
    btn.innerHTML = '&#9203; Sanitizing Blocks...';
    document.getElementById('engineStatusBadge').innerText = 'OVERWRITE_IN_PROGRESS';
    log(`[!] Initiating destructive raw sector overwrite on ${path} (${method})...`);

    try {
        const res = await fetch('/api/v1/erasure/execute', {
            method: 'POST',
            headers: getAuthHeaders(),
            body: JSON.stringify({ target_path: path, method: method, verification_coverage_pct: coverage })
        });
        const responseJson = await res.json();
        
        if (responseJson.status === "success") {
            const data = responseJson.data ? responseJson.data : responseJson;
            
            if (data.verified === true) {
                const bytesCount = data.bytes_processed || 0;
                log(`[+] Sanitization Successful! Job: ${data.job_id}`);
                log(`[+] Processed: ${bytesCount.toLocaleString()} bytes (${data.verification_coverage_pct}% Verified).`);
                log(`[+] Cryptographic Audit Seal: ${data.audit_hash}`);
                alert(`Sanitization Verified: ${data.job_id}\n\nBlocks overwritten and verified.`);
            } else {
                log(`[-] VERIFICATION FAILED. Sectors unreadable for ${data.job_id}`);
                alert(`WARNING: Verification failed for ${data.job_id}`);
            }
        } else {
            log(`[-] Sanitization error: ${JSON.stringify(responseJson)}`);
        }
    } catch (err) {
        log(`[-] Execution failed: ${err}`);
    } finally {
        btn.disabled = false;
        btn.innerHTML = '&#9762; Execute Media Sanitization';
        document.getElementById('engineStatusBadge').innerText = 'ENGINE_IDLE';
    }
}

window.addEventListener('DOMContentLoaded', () => {
    const emptyMap = Array.from({ length: 64 }, (_, i) => ({
        block_index: i + 1,
        byte_offset: i * 65536,
        entropy: 0,
        classification: "ZEROED_SANITIZED"
    }));
    renderEntropyHeatmap(emptyMap);
    checkSession();
});
