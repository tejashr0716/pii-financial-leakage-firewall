import re
import hashlib


def validate_luhn(number_str: str) -> bool:
    """Validate numeric string using the Luhn (Mod-10) algorithm."""
    digits = re.sub(r"\D", "", number_str)
    if len(digits) < 13 or len(digits) > 19:
        return False

    total = 0
    reverse_digits = digits[::-1]

    for i, char in enumerate(reverse_digits):
        d = int(char)
        if i % 2 == 1:
            d = d * 2
            if d > 9:
                d = d - 9
        total += d

    return total % 10 == 0


def identify_card_brand(digits: str) -> str:
    """Identify card brand from leading digits."""
    d = re.sub(r"\D", "", digits)
    if d.startswith("4"):
        return "VISA"
    elif d.startswith(("51", "52", "53", "54", "55")) or (len(d) >= 4 and 2221 <= int(d[:4]) <= 2720):
        return "MASTERCARD"
    elif d.startswith(("34", "37")):
        return "AMEX"
    elif d.startswith("6011") or d.startswith(("644", "645", "646", "647", "648", "649")) or d.startswith("65"):
        return "DISCOVER"
    return "GENERIC_PAN"


def validate_iban(iban_str: str) -> bool:
    """Validate International Bank Account Number using ISO 7064 Mod-97 checksum."""
    clean = re.sub(r"[\s\-]", "", iban_str).upper()
    if len(clean) < 15 or len(clean) > 34:
        return False

    if not re.match(r"^[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}$", clean):
        return False

    # Move first 4 characters to end
    rearranged = clean[4:] + clean[:4]

    # Convert letters to digits (A=10, ..., Z=35)
    digits_list = []
    for c in rearranged:
        if c.isdigit():
            digits_list.append(c)
        else:
            digits_list.append(str(ord(c) - 55))

    numeric_str = "".join(digits_list)
    try:
        return int(numeric_str) % 97 == 1
    except ValueError:
        return False


def validate_ssn(ssn_str: str) -> bool:
    """Validate US Social Security Number format and regulatory exclusion rules."""
    clean = re.sub(r"\D", "", ssn_str)
    if len(clean) != 9:
        return False

    area = int(clean[:3])
    group = int(clean[3:5])
    serial = int(clean[5:])

    # Exclusions
    if area == 0 or area == 666 or (900 <= area <= 999):
        return False
    if group == 0:
        return False
    if serial == 0:
        return False

    return True


def mask_value(raw: str, finding_type: str, mode: str = "PARTIAL_MASK") -> str:
    """Format sanitized representation of sensitive value based on mode."""
    if mode == "FULL_MASK":
        return f"[REDACTED_{finding_type}]"

    if mode == "HASH_TOKEN":
        h = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]
        return f"TOK_{finding_type}_{h}"

    # Default: PARTIAL_MASK
    digits = re.sub(r"\D", "", raw)
    if finding_type == "CREDIT_CARD":
        if len(digits) >= 8:
            return f"{digits[:4]}-XXXX-XXXX-{digits[-4:]}"
        return "****-****-****-****"

    elif finding_type == "IBAN":
        clean = re.sub(r"[\s\-]", "", raw).upper()
        if len(clean) >= 8:
            return f"{clean[:4]}XXXX...XXXX{clean[-2:]}"
        return "[REDACTED_IBAN]"

    elif finding_type == "SSN":
        if len(digits) == 9:
            return f"XXX-XX-{digits[-4:]}"
        return "XXX-XX-XXXX"

    elif finding_type.startswith("API_KEY"):
        if "_" in raw:
            parts = raw.split("_")
            prefix = "_".join(parts[:-1]) + "_"
            return f"{prefix}XXXX...XXXX"
        return raw[:4] + "XXXX...XXXX"

    elif finding_type == "PRIVATE_KEY":
        return "[REDACTED_PRIVATE_KEY_BLOCK]"

    return "[REDACTED]"
