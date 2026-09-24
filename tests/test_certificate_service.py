from eraser.certificate_service import generate_nist_certificate


def test_certificate_escapes_user_controlled_fields():
    html_bytes = generate_nist_certificate(
        {
            "job_id": '<script>alert("job")</script>',
            "target_path": '<img src=x onerror=alert("target")>',
            "target_type": '<b>BLOCK</b>',
            "method": '<svg onload=alert("method")>',
            "operator_username": '<script>alert("operator")</script>',
            "audit_hash": '<iframe src="javascript:alert(1)"></iframe>',
            "verified": True,
        }
    )

    doc = html_bytes.decode("utf-8")

    assert "<script>alert" not in doc
    assert "<img src=x" not in doc
    assert "<svg onload" not in doc
    assert "<iframe" not in doc
    assert "&lt;script&gt;alert" in doc
    assert "&lt;img src=x onerror=alert(&quot;target&quot;)&gt;" in doc
