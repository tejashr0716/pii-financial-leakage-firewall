# Architecture: PII Financial Leakage Firewall

## System Architecture

The **PII Financial Leakage Firewall** provides inline data loss prevention (DLP), credential sanitization, and secret surveillance across high-throughput financial log streams and public APIs (such as GitHub Public Events). It executes deterministic algorithmic validation (Luhn Mod-10, ISO 7064 Mod-97, SSA Area/Group rules) with sub-0.02ms inspection latency.

```mermaid
flowchart TD
    Inbound[Inbound Traffic / Logs / GitHub Public Stream] -->|Payload Text with X-Request-ID| API[FastAPI Gateway Layer]
    API --> Middleware[Request Correlation Middleware]
    Middleware --> Routes{API Endpoints}

    Routes -->|POST /api/inspect| DLP[DLP Inspection Engine]
    Routes -->|POST /api/redact| Redactor[In-Place Sanitizer & Tokenizer]
    Routes -->|POST /api/stream/monitor| StreamMon[GitHub Public Stream Monitor]

    StreamMon -->|HTTPS GET Events| GitHubAPI[GitHub Public Events Stream API]
    StreamMon --> DLP

    DLP --> FastRegex[Candidate Token Extraction]
    FastRegex --> Luhn[Luhn Mod-10 Checksum: PAN Cards]
    FastRegex --> IBANCheck[ISO 7064 Mod-97: IBAN Accounts]
    FastRegex --> SSNCheck[SSA Exclusion Rules: US SSN]
    FastRegex --> SecretsCheck[Regex Entropy: Stripe sk_live, AWS AKIA, PEM]

    Luhn --> Findings[Deduplicated Leakage Findings]
    IBANCheck --> Findings
    SSNCheck --> Findings
    SecretsCheck --> Findings

    Findings --> Redactor
    Findings --> SQLite[(SQLite WAL Audit Trail)]
    Redactor --> Output[Sanitized Response]
```

## Algorithmic Detection & Sanitization Pipeline

### 1. Credit Card PAN (Primary Account Number) Validation
- Identifies 13-19 digit candidate sequences.
- Evaluates checksum using the **Luhn Algorithm (Mod-10)**:
  $$\left( \sum_{i} d_i' \right) \bmod 10 = 0$$
  where odd-indexed digits from the right are doubled ($d \to 2d - 9$ if $2d > 9$).
- Classifies card brands by IIN (Issuer Identification Number): Visa (4), Mastercard (51-55, 2221-2720), Amex (34, 37), Discover (6011, 644-649, 65).

### 2. International Bank Account Number (IBAN) Mod-97 (ISO 7064)
- Formats 15-34 alphanumeric string by transposing leading 4 characters to the rear.
- Converts alphabetical characters to numerical values ($A=10, \dots, Z=35$).
- Evaluates modulo arithmetic:
  $$\text{NumericString} \bmod 97 = 1$$

### 3. US Social Security Number (SSN) Structural Rules
- Validates 9-digit format (`AAA-GG-SSSS`).
- Rejects non-existent and fraudulent area blocks ($000$, $666$, $900-999$), group zeros ($00$), and serial zeros ($0000$).

### 4. API Keys & Cryptographic Private Keys
- Scans high-entropy live secret tokens: Stripe live secret keys (`sk_live_...`), AWS IAM access keys (`AKIA...`), and PEM private key envelope blocks (`-----BEGIN RSA PRIVATE KEY-----`).

### 5. Multi-Mode Sanitization
- **PARTIAL_MASK**: Preserves diagnostic utility (e.g. `4111-XXXX-XXXX-1111`, `XXX-XX-6789`).
- **FULL_MASK**: Replaces entity entirely (e.g. `[REDACTED_CREDIT_CARD]`).
- **HASH_TOKEN**: Replaces entity with deterministic SHA-256 token (`TOK_CREDIT_CARD_a1b2c3d4e5f6`).
