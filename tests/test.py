import base64
import json
import os
import subprocess
import sys

import httpx
import pytest

sys.path.insert(0, "..")
from server.main import app, start

BASE_URL = None
_server = None


@pytest.fixture(scope="session", autouse=True)
def run_server():
    global BASE_URL, _server
    port = 4321
    BASE_URL = f"http://127.0.0.1:{port}"
    _server = start(port)
    yield
    _server.should_exit = True


# ----- Group 1: Server health -----

def test_health():
    r = httpx.get(f"{BASE_URL}/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_public_key_endpoint():
    r = httpx.get(f"{BASE_URL}/public-key")
    assert r.status_code == 200
    data = r.json()
    assert "public_key_pem" in data
    assert "key_size_bits" in data
    assert data["key_size_bits"] >= 2048
    assert "-----BEGIN PUBLIC KEY-----" in data["public_key_pem"]


# ----- Group 2: True positives -----

def test_tool_detects_signature_verification_bypass():
    result = subprocess.run(
        [sys.executable, "../tool/main.py", "--target", BASE_URL],
        capture_output=True, text=True, stdin=subprocess.DEVNULL,
    )
    assert result.returncode == 0
    output = json.loads(result.stdout)
    types = [f["vulnerability_type"] for f in output["findings"]]
    assert "SIGNATURE_VERIFICATION_BYPASS" in types, (
        f"Expected SIGNATURE_VERIFICATION_BYPASS in findings, got: {types}"
    )


def test_tool_detects_deprecated_padding():
    result = subprocess.run(
        [sys.executable, "../tool/main.py", "--target", BASE_URL],
        capture_output=True, text=True, stdin=subprocess.DEVNULL,
    )
    output = json.loads(result.stdout)
    types = [f["vulnerability_type"] for f in output["findings"]]
    assert "DEPRECATED_PADDING_SCHEME" in types, (
        f"Expected DEPRECATED_PADDING_SCHEME in findings, got: {types}"
    )


def test_weak_verify_accepts_forgery_directly():
    forged = base64.b64encode(os.urandom(256)).decode()
    r = httpx.post(f"{BASE_URL}/verify/weak", json={"message": "test", "signature": forged})
    assert r.status_code == 200
    assert r.json()["valid"] is True


def test_tool_flags_verify_weak_as_high():
    result = subprocess.run(
        [sys.executable, "../tool/main.py", "--target", BASE_URL],
        capture_output=True, text=True, stdin=subprocess.DEVNULL,
    )
    output = json.loads(result.stdout)
    weak_findings = [f for f in output["findings"] if f["endpoint"] == "/verify/weak"]
    assert len(weak_findings) > 0, "Expected a finding for /verify/weak"
    assert weak_findings[0]["severity"] in ("HIGH", "CRITICAL")


def test_tool_flags_pkcs1v15_as_low():
    result = subprocess.run(
        [sys.executable, "../tool/main.py", "--target", BASE_URL],
        capture_output=True, text=True, stdin=subprocess.DEVNULL,
    )
    output = json.loads(result.stdout)
    pkcs_findings = [f for f in output["findings"] if f["endpoint"] == "/sign/pkcs1v15"]
    assert len(pkcs_findings) > 0, "Expected a finding for /sign/pkcs1v15"
    assert pkcs_findings[0]["severity"] == "LOW"


# ----- Group 3: False positives -----

def test_secure_verify_not_flagged_for_bypass():
    result = subprocess.run(
        [sys.executable, "../tool/main.py", "--target", BASE_URL],
        capture_output=True, text=True, stdin=subprocess.DEVNULL,
    )
    output = json.loads(result.stdout)
    secure_bypass = [
        f for f in output["findings"]
        if f["endpoint"] == "/verify/secure"
        and f["vulnerability_type"] == "SIGNATURE_VERIFICATION_BYPASS"
    ]
    assert len(secure_bypass) == 0, "/verify/secure must NOT be flagged for signature bypass"


def test_pss_sign_endpoint_not_flagged():
    result = subprocess.run(
        [sys.executable, "../tool/main.py", "--target", BASE_URL],
        capture_output=True, text=True, stdin=subprocess.DEVNULL,
    )
    output = json.loads(result.stdout)
    pss_findings = [f for f in output["findings"] if f["endpoint"] == "/sign"]
    assert len(pss_findings) == 0, "/sign (PSS) should produce no findings"


# ----- Group 4: Output format -----

def test_output_has_required_top_level_fields():
    result = subprocess.run(
        [sys.executable, "../tool/main.py", "--target", BASE_URL],
        capture_output=True, text=True, stdin=subprocess.DEVNULL,
    )
    output = json.loads(result.stdout)
    assert "target" in output
    assert "findings" in output
    assert "summary" in output
    assert isinstance(output["findings"], list)


def test_each_finding_has_required_fields():
    result = subprocess.run(
        [sys.executable, "../tool/main.py", "--target", BASE_URL],
        capture_output=True, text=True, stdin=subprocess.DEVNULL,
    )
    output = json.loads(result.stdout)
    for finding in output["findings"]:
        assert "endpoint" in finding, f"Missing 'endpoint' in {finding}"
        assert "vulnerability_type" in finding, f"Missing 'vulnerability_type' in {finding}"
        assert "evidence" in finding, f"Missing 'evidence' in {finding}"
        assert "severity" in finding, f"Missing 'severity' in {finding}"


def test_target_field_matches_server():
    result = subprocess.run(
        [sys.executable, "../tool/main.py", "--target", BASE_URL],
        capture_output=True, text=True, stdin=subprocess.DEVNULL,
    )
    output = json.loads(result.stdout)
    assert output["target"] == BASE_URL


def test_output_is_valid_json():
    result = subprocess.run(
        [sys.executable, "../tool/main.py", "--target", BASE_URL],
        capture_output=True, text=True, stdin=subprocess.DEVNULL,
    )
    assert result.returncode == 0
    # Raises if not valid JSON
    json.loads(result.stdout)


# ----- Group 5: Edge cases -----

def test_unreachable_server_returns_empty_findings():
    result = subprocess.run(
        [sys.executable, "../tool/main.py", "--target", "http://127.0.0.1:19997"],
        capture_output=True, text=True, stdin=subprocess.DEVNULL,
    )
    assert result.returncode == 0
    output = json.loads(result.stdout)
    assert "findings" in output
    assert isinstance(output["findings"], list)
    assert len(output["findings"]) == 0


def test_pss_sign_and_verify_roundtrip():
    r = httpx.post(f"{BASE_URL}/sign", json={"message": "hello world"})
    assert r.status_code == 200
    sig = r.json()["signature"]
    assert isinstance(sig, str) and len(sig) > 0

    r2 = httpx.post(f"{BASE_URL}/verify/secure", json={"message": "hello world", "signature": sig})
    assert r2.status_code == 200
    assert r2.json()["valid"] is True


def test_pkcs1v15_sign_and_verify_roundtrip():
    r = httpx.post(f"{BASE_URL}/sign/pkcs1v15", json={"message": "test pkcs1v15"})
    assert r.status_code == 200
    sig = r.json()["signature"]

    r2 = httpx.post(f"{BASE_URL}/verify/secure", json={"message": "test pkcs1v15", "signature": sig})
    assert r2.status_code == 200
    assert r2.json()["valid"] is True


def test_forged_signature_rejected_by_secure():
    forged = base64.b64encode(os.urandom(256)).decode()
    r = httpx.post(f"{BASE_URL}/verify/secure", json={"message": "real message", "signature": forged})
    assert r.status_code == 200
    assert r.json()["valid"] is False


def test_wrong_message_rejected():
    r = httpx.post(f"{BASE_URL}/sign", json={"message": "message A"})
    sig = r.json()["signature"]
    r2 = httpx.post(f"{BASE_URL}/verify/secure", json={"message": "message B", "signature": sig})
    assert r2.status_code == 200
    assert r2.json()["valid"] is False


def test_malformed_base64_returns_400_or_invalid():
    r = httpx.post(
        f"{BASE_URL}/verify/secure",
        json={"message": "test", "signature": "not-valid-base64!!!"},
    )
    if r.status_code == 200:
        assert r.json()["valid"] is False
    else:
        assert r.status_code in (400, 422)


def test_empty_signature_rejected():
    r = httpx.post(f"{BASE_URL}/verify/weak", json={"message": "test", "signature": ""})
    assert r.status_code == 200
    assert r.json()["valid"] is False
