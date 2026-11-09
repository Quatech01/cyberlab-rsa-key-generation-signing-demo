import argparse
import base64
import json
import os
import sys

import httpx

DEFAULT_TARGET = "http://localhost:3000"


def probe(client: httpx.Client, target: str) -> dict:
    findings = []

    # Health check — bail early if server is unreachable
    try:
        r = client.get(f"{target}/health", timeout=5)
        r.raise_for_status()
    except Exception as exc:
        return {
            "target": target,
            "findings": [],
            "summary": f"Server unreachable: {exc}",
        }

    # Fetch public key metadata
    try:
        r = client.get(f"{target}/public-key", timeout=5)
        key_info = r.json()
        key_bits = key_info.get("key_size_bits", 0)
        print(f"[*] Public key: RSA-{key_bits}", file=sys.stderr)
        if key_bits > 0 and key_bits < 2048:
            findings.append({
                "endpoint": "/public-key",
                "vulnerability_type": "WEAK_RSA_KEY_SIZE",
                "evidence": (
                    f"Server key is {key_bits} bits; NIST SP 800-57 requires a minimum of "
                    "2048 bits for RSA keys through 2030"
                ),
                "severity": "HIGH",
            })
    except Exception as exc:
        print(f"[!] Could not fetch public key: {exc}", file=sys.stderr)

    test_message = "CyberLab RSA probe message"

    # Sign with PSS (secure)
    pss_sig = None
    try:
        r = client.post(f"{target}/sign", json={"message": test_message}, timeout=5)
        pss_sig = r.json().get("signature")
        print("[*] PSS signature obtained", file=sys.stderr)
    except Exception as exc:
        print(f"[!] PSS sign failed: {exc}", file=sys.stderr)

    # Sign with PKCS1v15 (deprecated) — flag as low-severity
    try:
        r = client.post(f"{target}/sign/pkcs1v15", json={"message": test_message}, timeout=5)
        if r.status_code == 200:
            print("[*] PKCS1v15 signing endpoint present", file=sys.stderr)
            findings.append({
                "endpoint": "/sign/pkcs1v15",
                "vulnerability_type": "DEPRECATED_PADDING_SCHEME",
                "evidence": (
                    "Endpoint uses PKCS#1 v1.5 padding. This deterministic scheme is deprecated "
                    "in favour of RSA-PSS (PKCS#1 v2.1) per RFC 8017. PKCS#1 v1.5 signatures "
                    "are non-randomised and have a known padding oracle attack surface."
                ),
                "severity": "LOW",
            })
    except Exception as exc:
        print(f"[!] PKCS1v15 sign failed: {exc}", file=sys.stderr)

    # Test /verify/secure with a valid PSS signature — should accept it
    if pss_sig:
        try:
            r = client.post(
                f"{target}/verify/secure",
                json={"message": test_message, "signature": pss_sig},
                timeout=5,
            )
            result = r.json()
            status = "accepted" if result.get("valid") else "REJECTED (unexpected)"
            print(f"[*] /verify/secure with valid signature: {status}", file=sys.stderr)
        except Exception as exc:
            print(f"[!] verify/secure roundtrip failed: {exc}", file=sys.stderr)

    # Forge a random 256-byte signature (not a real RSA signature)
    forged_sig = base64.b64encode(os.urandom(256)).decode()

    # Secure endpoint must reject the forgery
    try:
        r = client.post(
            f"{target}/verify/secure",
            json={"message": test_message, "signature": forged_sig},
            timeout=5,
        )
        result = r.json()
        if result.get("valid"):
            findings.append({
                "endpoint": "/verify/secure",
                "vulnerability_type": "SIGNATURE_VERIFICATION_BYPASS",
                "evidence": (
                    "The secure verification endpoint accepted a randomly-generated "
                    "256-byte value as a valid RSA signature — no cryptographic check is being performed."
                ),
                "severity": "CRITICAL",
            })
            print("[!] CRITICAL: /verify/secure accepted a forged signature", file=sys.stderr)
        else:
            print("[+] /verify/secure correctly rejected forged signature", file=sys.stderr)
    except Exception as exc:
        print(f"[!] Forgery test on /verify/secure failed: {exc}", file=sys.stderr)

    # Weak endpoint — expected to accept the forgery (that is the vulnerability)
    try:
        r = client.post(
            f"{target}/verify/weak",
            json={"message": test_message, "signature": forged_sig},
            timeout=5,
        )
        result = r.json()
        if result.get("valid"):
            findings.append({
                "endpoint": "/verify/weak",
                "vulnerability_type": "SIGNATURE_VERIFICATION_BYPASS",
                "evidence": (
                    f"Endpoint accepted a randomly-generated 256-byte forgery as a valid signature. "
                    f"Server response: {json.dumps(result)}. "
                    "Only the presence of a non-empty string is checked — "
                    "no cryptographic verification is performed."
                ),
                "severity": "HIGH",
            })
            print("[!] HIGH: /verify/weak accepted a forged signature", file=sys.stderr)
        else:
            print("[+] /verify/weak rejected the forged signature", file=sys.stderr)
    except Exception as exc:
        print(f"[!] Forgery test on /verify/weak failed: {exc}", file=sys.stderr)

    n = len(findings)
    high_count = sum(1 for f in findings if f["severity"] in ("HIGH", "CRITICAL"))
    low_count = sum(1 for f in findings if f["severity"] == "LOW")
    summary = f"Found {n} issue(s): {high_count} HIGH/CRITICAL, {low_count} LOW"

    return {"target": target, "findings": findings, "summary": summary}


def main():
    parser = argparse.ArgumentParser(description="RSA Key Generation and Signing Demo Scanner")
    parser.add_argument("--target", default=DEFAULT_TARGET, help="Base URL of the demo server")
    args = parser.parse_args()

    with httpx.Client() as client:
        result = probe(client, args.target)

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
