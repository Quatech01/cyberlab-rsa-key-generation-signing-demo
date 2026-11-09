# RSA Key Generation and Signing Demo

A cybersecurity scanner that probes a document-signing API for two common RSA implementation flaws: signature verification bypass and use of the deprecated PKCS#1 v1.5 padding scheme.

## What This Demonstrates

RSA digital signatures are only as secure as their implementation. Two failure modes appear repeatedly in real-world code:

**1. Signature verification bypass** — the server checks only that a signature field is non-empty, without calling any cryptographic verification function. An attacker can submit random bytes as a "signature" and the server will accept them as valid, completely defeating the purpose of signing.

**2. Deprecated PKCS#1 v1.5 padding** — RSA-PKCS#1 v1.5 signatures are deterministic: signing the same message twice always produces the same signature. This non-randomness creates a surface for padding oracle attacks and means the scheme does not meet modern provable-security requirements. RFC 8017 (PKCS#1 v2.2) recommends RSA-PSS for all new signature applications.

## How It Works

```
demo server (FastAPI, port 3000)
  GET  /health                → {"status": "ok"}
  GET  /public-key            → RSA-2048 public key PEM + key size
  POST /sign                  → RSA-PSS signature       (safe)
  POST /sign/pkcs1v15         → PKCS#1 v1.5 signature   (deprecated)
  POST /verify/secure         → cryptographic verification via Python cryptography library (safe)
  POST /verify/weak           → non-empty string check only, no crypto (vulnerable)

scanner tool (Python, tool/main.py)
  1. Health check — bail if server unreachable
  2. Fetch /public-key — flag if key size < 2048 bits
  3. Sign a test message via /sign (PSS) and /sign/pkcs1v15
  4. Flag /sign/pkcs1v15 as DEPRECATED_PADDING_SCHEME (LOW)
  5. Submit a randomly-generated 256-byte forgery to /verify/secure → rejected → no finding
  6. Submit the same forgery to /verify/weak → accepted → SIGNATURE_VERIFICATION_BYPASS (HIGH)
  7. Emit structured JSON with findings and summary
```

## Quick Start

```bash
# Install server dependencies
cd server
pip install -r requirements.txt

# Start the demo server
python main.py

# In another terminal — run the scanner
cd tool
pip install -r requirements.txt
python main.py --target http://localhost:3000

# Run the test suite
cd tests
pip install -r requirements.txt
python -m pytest test.py -v
```

## Example Output

```json
{
  "target": "http://localhost:3000",
  "findings": [
    {
      "endpoint": "/sign/pkcs1v15",
      "vulnerability_type": "DEPRECATED_PADDING_SCHEME",
      "evidence": "Endpoint uses PKCS#1 v1.5 padding. This deterministic scheme is deprecated in favour of RSA-PSS (PKCS#1 v2.1) per RFC 8017. PKCS#1 v1.5 signatures are non-randomised and have a known padding oracle attack surface.",
      "severity": "LOW"
    },
    {
      "endpoint": "/verify/weak",
      "vulnerability_type": "SIGNATURE_VERIFICATION_BYPASS",
      "evidence": "Endpoint accepted a randomly-generated 256-byte forgery as a valid signature. Server response: {\"valid\": true, \"endpoint\": \"weak\"}. Only the presence of a non-empty string is checked — no cryptographic verification is performed.",
      "severity": "HIGH"
    }
  ],
  "summary": "Found 2 issue(s): 1 HIGH/CRITICAL, 1 LOW"
}
```

## Key Takeaways

- **Never use a non-empty check as a proxy for cryptographic validity.** Always call the library's `verify()` function and handle the exception it raises on failure. A non-empty string proves only that something was sent, not that it corresponds to the message.
- **Prefer RSA-PSS over PKCS#1 v1.5 for signatures.** PSS uses a random salt on every signing call, making it non-deterministic and meeting modern provable-security definitions. PKCS#1 v1.5 encryption (not signatures) is known-vulnerable to Bleichenbacher's 1998 padding oracle; the signature scheme has weaker theoretical guarantees and is deprecated by RFC 8017.
- **Minimum RSA key size is 2048 bits.** NIST SP 800-57 permits 2048-bit RSA keys through 2030; 3072 or 4096 bits are recommended for keys that must remain secure beyond that horizon.
- **Use an audited library for all RSA operations** — Python `cryptography`, Java Bouncy Castle, Go `crypto/rsa`. Never implement RSA primitives manually; subtle mistakes in modular exponentiation or padding are catastrophic.

## Further Reading

- [RFC 8017 — PKCS #1: RSA Cryptography Specifications Version 2.2](https://www.rfc-editor.org/rfc/rfc8017)
- [NIST SP 800-57 Part 1 Rev. 5 — Recommendation for Key Management](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final)
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
