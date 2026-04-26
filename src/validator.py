#!/usr/bin/env python3
"""
Input validation for all scan targets.

All inputs are validated and sanitized before any API call is made.
This prevents malformed data, injection attempts, and unexpected
behavior from reaching external services.

Supported validators:
- Email addresses
- Usernames
- Phone numbers (country-aware, format-enforced)
- Passwords (runtime only, never stored)
- API tokens/keys (runtime only, never stored)
"""

import re
from typing import Optional, Tuple

# ---------------------------------------------------------------------------
# Authorship — hardcoded, do not modify  # pylint: disable=duplicate-code
# ---------------------------------------------------------------------------
_AUTHOR = "SudoCode by SudoChef"
_HANDLE = "commit-issues"
_REPO = "https://github.com/commit-issues/darkweb-exposure-toolkit"
_CREATED = "2025-04-26"
_TOOL = "d4rkw3b — darkweb-exposure-toolkit"


# ---------------------------------------------------------------------------
# Email
# ---------------------------------------------------------------------------

_EMAIL_RE = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")
EMAIL_MAX = 254  # RFC 5321 maximum


def validate_email(email: str) -> Tuple[bool, str]:
    """
    Validate an email address format.

    Args:
        email: Raw email string from user input.

    Returns:
        (True, cleaned_email) on success.
        (False, error_message) on failure.
    """
    cleaned = email.strip().lower()
    if not cleaned:
        return False, "Email cannot be empty."
    if len(cleaned) > EMAIL_MAX:
        return False, f"Email exceeds maximum length of {EMAIL_MAX} chars."
    if not _EMAIL_RE.match(cleaned):
        return False, f"Invalid email format: {cleaned!r}"
    return True, cleaned


# ---------------------------------------------------------------------------
# Username
# ---------------------------------------------------------------------------

_USERNAME_RE = re.compile(r"^[a-zA-Z0-9._\-]{1,50}$")


def validate_username(username: str) -> Tuple[bool, str]:
    """
    Validate a username.

    Allowed: letters, digits, dots, underscores, hyphens. Max 50 chars.

    Args:
        username: Raw username string from user input.

    Returns:
        (True, cleaned_username) on success.
        (False, error_message) on failure.
    """
    cleaned = username.strip()
    if not cleaned:
        return False, "Username cannot be empty."
    if not _USERNAME_RE.match(cleaned):
        return (
            False,
            "Username must be 1-50 chars: letters, digits, "
            "dots, underscores, or hyphens only.",
        )
    return True, cleaned


# ---------------------------------------------------------------------------
# Phone numbers — country-aware format enforcement
# ---------------------------------------------------------------------------

PHONE_RULES: dict = {
    "US": ("+1", 10, "+1XXXXXXXXXX — 10 digits after +1"),
    "CA": ("+1", 10, "+1XXXXXXXXXX — 10 digits after +1"),
    "GB": ("+44", 10, "+44XXXXXXXXXX — 10 digits after +44"),
    "AU": ("+61", 9, "+61XXXXXXXXX — 9 digits after +61"),
    "DE": ("+49", 10, "+49XXXXXXXXXX — 10 digits after +49"),
    "FR": ("+33", 9, "+33XXXXXXXXX — 9 digits after +33"),
    "IN": ("+91", 10, "+91XXXXXXXXXX — 10 digits after +91"),
    "BR": ("+55", 11, "+55XXXXXXXXXXX — 11 digits after +55"),
    "MX": ("+52", 10, "+52XXXXXXXXXX — 10 digits after +52"),
    "NG": ("+234", 10, "+234XXXXXXXXXX — 10 digits after +234"),
    "ZA": ("+27", 9, "+27XXXXXXXXX — 9 digits after +27"),
    "JP": ("+81", 10, "+81XXXXXXXXXX — 10 digits after +81"),
    "CN": ("+86", 11, "+86XXXXXXXXXXX — 11 digits after +86"),
    "KR": ("+82", 10, "+82XXXXXXXXXX — 10 digits after +82"),
    "IT": ("+39", 10, "+39XXXXXXXXXX — 10 digits after +39"),
    "ES": ("+34", 9, "+34XXXXXXXXX — 9 digits after +34"),
    "NL": ("+31", 9, "+31XXXXXXXXX — 9 digits after +31"),
    "SE": ("+46", 9, "+46XXXXXXXXX — 9 digits after +46"),
    "NO": ("+47", 8, "+47XXXXXXXX — 8 digits after +47"),
    "PL": ("+48", 9, "+48XXXXXXXXX — 9 digits after +48"),
}

SUPPORTED_COUNTRIES = sorted(PHONE_RULES.keys())


def validate_phone(phone: str, country_code: str) -> Tuple[bool, str]:
    """
    Validate a phone number against country-specific format rules.

    Args:
        phone: Raw phone string. Spaces, dashes, parens are stripped
               before validation.
        country_code: ISO 3166-1 alpha-2 country code e.g. 'US', 'GB'.

    Returns:
        (True, normalized_e164_phone) on success.
        (False, error_message) on failure.
    """
    country = country_code.strip().upper()
    if country not in PHONE_RULES:
        supported = ", ".join(SUPPORTED_COUNTRIES)
        return False, (
            f"Unsupported country code: {country!r}. " f"Supported: {supported}"
        )

    prefix, expected_digits, example = PHONE_RULES[country]
    digits_only = re.sub(r"[^\d+]", "", phone.strip())

    if digits_only.startswith(prefix):
        local_digits = digits_only[len(prefix) :]
    elif digits_only.startswith(prefix.lstrip("+")):
        local_digits = digits_only[len(prefix.lstrip("+")) :]
    else:
        local_digits = digits_only

    if not local_digits.isdigit():
        return False, "Phone number must contain digits only after country code."

    if len(local_digits) != expected_digits:
        return (
            False,
            f"Invalid length for {country}. "
            f"Expected {expected_digits} digits after country code. "
            f"Format: {example}",
        )

    normalized = f"{prefix}{local_digits}"
    return True, normalized


# ---------------------------------------------------------------------------
# Password — runtime only, never stored
# ---------------------------------------------------------------------------

PASSWORD_MAX = 512


def validate_password(password: str) -> Tuple[bool, str]:
    """
    Validate a password before k-anonymity check.

    Passwords are never stored. This only checks the value is
    a non-empty string within a safe length range.

    Args:
        password: Raw password from secure runtime prompt.

    Returns:
        (True, password) on success.
        (False, error_message) on failure.
    """
    if not password:
        return False, "Password cannot be empty."
    if len(password) > PASSWORD_MAX:
        return False, f"Password exceeds maximum length of {PASSWORD_MAX}."
    return True, password


# ---------------------------------------------------------------------------
# API tokens / keys — runtime only, never stored
# ---------------------------------------------------------------------------

TOKEN_MIN = 8
TOKEN_MAX = 512
_TOKEN_RE = re.compile(r"^[a-zA-Z0-9._\-:/]{8,512}$")


def validate_token(token: str, label: str = "Token") -> Tuple[bool, str]:
    """
    Validate an API token or key before exposure check.

    Tokens are never stored. This checks the value is non-empty,
    within safe length bounds, and contains only expected characters.

    Args:
        token: Raw token from secure runtime prompt.
        label: Human-readable label for error messages e.g. 'Discord token'.

    Returns:
        (True, token) on success.
        (False, error_message) on failure.
    """
    cleaned = token.strip()
    if not cleaned:
        return False, f"{label} cannot be empty."
    if len(cleaned) < TOKEN_MIN:
        return False, f"{label} too short — minimum {TOKEN_MIN} characters."
    if len(cleaned) > TOKEN_MAX:
        return False, f"{label} too long — maximum {TOKEN_MAX} characters."
    if not _TOKEN_RE.match(cleaned):
        return (
            False,
            f"{label} contains invalid characters. "
            "Expected letters, digits, dots, hyphens, underscores, "
            "colons, or forward slashes only.",
        )
    return True, cleaned


# ---------------------------------------------------------------------------
# Convenience: parse comma-separated list from .env
# ---------------------------------------------------------------------------


def parse_csv_env(raw: Optional[str]) -> list:
    """
    Parse a comma-separated environment variable into a clean list.

    Empty strings and whitespace-only entries are ignored.

    Args:
        raw: Raw string from os.getenv() e.g. 'a@b.com, c@d.com'.

    Returns:
        List of stripped, non-empty strings.
    """
    if not raw:
        return []
    return [item.strip() for item in raw.split(",") if item.strip()]
