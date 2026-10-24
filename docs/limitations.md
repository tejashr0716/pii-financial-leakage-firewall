# Limitations & Boundary Conditions: PII Financial Leakage Firewall

## 1. Structured Format Reliance
- Credit card and IBAN validation rely on mathematical checksums (Luhn Mod-10 and ISO 7064 Mod-97), resulting in near-zero false positive rates on valid numbers.
- Unstructured PII without formal mathematical checksums (e.g. personal names, physical street addresses) are better handled via Named Entity Recognition (NER) models.

## 2. GitHub Public Stream Rate Limits
- Unauthenticated requests to `https://api.github.com/events` are subject to GitHub's standard rate limit of 60 requests per hour per IP.
- For 24/7 continuous enterprise monitoring, an authenticated Personal Access Token (PAT) can be passed in `headers`.

## 3. Encrypted Payloads
- The firewall inspects plaintext HTTP payloads, logs, and commit streams. Encrypted payloads (TLS streams, GPG encrypted blobs) must be decrypted prior to DLP inspection.
