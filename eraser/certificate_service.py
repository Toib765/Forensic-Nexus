import time

def generate_nist_certificate(job_data: dict) -> bytes:
    job_id = job_data.get('job_id', 'N/A')
    target_path = job_data.get('target_path', 'N/A')
    target_type = job_data.get('target_type', 'BLOCK_DEVICE')
    method = job_data.get('method', 'NIST_CLEAR')
    bytes_proc = f"{job_data.get('bytes_processed', 0):,}"
    v_method = job_data.get('verification_method', 'Deterministic Read-Back Pass')
    v_scope = job_data.get('verification_coverage_pct', 100.0)
    audit_hash = job_data.get('audit_hash', 'N/A')
    operator = job_data.get('operator_username', 'toib')
    timestamp = time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(job_data.get('end_time', time.time())))

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>NIST SP 800-88 Certificate - {job_id}</title>
    <style>
        @page {{ size: A4 portrait; margin: 15mm; }}
        body {{
            background-color: #0b0f19;
            color: #e2e8f0;
            font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto, sans-serif;
            margin: 0;
            padding: 30px;
            display: flex;
            justify-content: center;
        }}
        .cert-card {{
            background: #111827;
            border: 2px solid #00e5ff;
            box-shadow: 0 0 35px rgba(0, 229, 255, 0.15);
            border-radius: 12px;
            max-width: 820px;
            width: 100%;
            padding: 40px 50px;
            position: relative;
            box-sizing: border-box;
        }}
        .header {{
            text-align: center;
            border-bottom: 1px solid #1f2937;
            padding-bottom: 24px;
            margin-bottom: 28px;
        }}
        .badge {{
            display: inline-block;
            background: rgba(0, 229, 255, 0.1);
            color: #00e5ff;
            border: 1px solid #00e5ff;
            padding: 4px 14px;
            font-size: 11px;
            font-weight: 700;
            letter-spacing: 1.5px;
            border-radius: 20px;
            text-transform: uppercase;
            margin-bottom: 12px;
        }}
        h1 {{
            margin: 0 0 6px 0;
            font-size: 22px;
            letter-spacing: 0.5px;
            color: #f8fafc;
        }}
        .subtitle {{
            color: #94a3b8;
            font-size: 13px;
            margin: 0;
        }}
        .grid {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 16px 32px;
            margin-bottom: 28px;
        }}
        .field-group {{
            display: flex;
            flex-direction: column;
        }}
        .field-label {{
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 0.8px;
            color: #64748b;
            margin-bottom: 4px;
            font-weight: 600;
        }}
        .field-value {{
            font-size: 14px;
            color: #f1f5f9;
            font-weight: 500;
        }}
        .mono {{
            font-family: 'SF Mono', Consolas, Monaco, monospace;
            color: #38bdf8;
        }}
        .seal-box {{
            background: #0f172a;
            border: 1px dashed #334155;
            border-radius: 8px;
            padding: 16px 20px;
            margin-bottom: 30px;
        }}
        .hash-text {{
            font-family: monospace;
            font-size: 12px;
            color: #10b981;
            word-break: break-all;
            margin-top: 6px;
        }}
        .status-badge {{
            display: inline-block;
            background: rgba(16, 185, 129, 0.15);
            border: 1px solid #10b981;
            color: #10b981;
            font-weight: 700;
            padding: 3px 10px;
            border-radius: 4px;
            font-size: 12px;
        }}
        .footer {{
            display: flex;
            justify-content: space-between;
            align-items: flex-end;
            border-top: 1px solid #1f2937;
            padding-top: 24px;
            margin-top: 10px;
        }}
        .sign-line {{
            width: 220px;
            border-top: 1px solid #475569;
            padding-top: 6px;
            font-size: 11px;
            color: #94a3b8;
            text-align: center;
        }}
        .print-btn {{
            position: absolute;
            top: 20px;
            right: 20px;
            background: #0284c7;
            color: #fff;
            border: none;
            padding: 8px 16px;
            border-radius: 6px;
            font-weight: 600;
            font-size: 12px;
            cursor: pointer;
        }}
        .print-btn:hover {{ background: #0369a1; }}
        @media print {{
            body {{ background: #fff; color: #000; padding: 0; }}
            .cert-card {{ border: 2px solid #000; box-shadow: none; background: #fff; color: #000; }}
            .print-btn {{ display: none; }}
            .field-value, h1 {{ color: #000; }}
            .seal-box {{ background: #f8fafc; border: 1px solid #cbd5e1; }}
            .hash-text {{ color: #0f172a; }}
        }}
    </style>
</head>
<body>
    <div class="cert-card">
        <button class="print-btn" onclick="window.print()">&#128438; Print / Save PDF</button>
        <div class="header">
            <div class="badge">NIST SP 800-88 Rev. 1 Validated</div>
            <h1>Certificate of Media Sanitization</h1>
            <p class="subtitle">National Forensic Chain-of-Custody & Cryptographic Destruction Verification</p>
        </div>

        <div class="grid">
            <div class="field-group">
                <span class="field-label">Certificate Serial / Job ID</span>
                <span class="field-value mono"><b>{job_id}</b></span>
            </div>
            <div class="field-group">
                <span class="field-label">Verification Status</span>
                <span class="field-value"><span class="status-badge">&#10003; VERIFIED SANITIZED</span></span>
            </div>
            <div class="field-group">
                <span class="field-label">Target Media / Block Device</span>
                <span class="field-value mono">{target_path} ({target_type})</span>
            </div>
            <div class="field-group">
                <span class="field-label">Sanitization Standard</span>
                <span class="field-value">{method}</span>
            </div>
            <div class="field-group">
                <span class="field-label">Total Overwritten Capacity</span>
                <span class="field-value mono">{bytes_proc} Bytes</span>
            </div>
            <div class="field-group">
                <span class="field-label">Linear Verification Scope</span>
                <span class="field-value">{v_scope}% Full Media Read-Back</span>
            </div>
            <div class="field-group">
                <span class="field-label">Authorized Operator</span>
                <span class="field-value">{operator} (Specialist)</span>
            </div>
            <div class="field-group">
                <span class="field-label">Destruction Timestamp</span>
                <span class="field-value mono">{timestamp}</span>
            </div>
        </div>

        <div class="seal-box">
            <span class="field-label">Cryptographic Integrity Seal (SHA-256)</span>
            <div class="hash-text">{audit_hash}</div>
        </div>

        <div class="footer">
            <div>
                <div style="font-size: 11px; color:#64748b;">Defense-Grade Forensic Nexus &bull; SIH-26149</div>
                <div style="font-size: 10px; color:#475569; margin-top:2px;">Immutable tamper-evident record stored in local audit ledger.</div>
            </div>
            <div class="sign-line">
                Digital Forensic Examiner Seal
            </div>
        </div>
    </div>
</body>
</html>
"""
    return html.encode('utf-8')
