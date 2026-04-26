#!/usr/bin/env python3
"""
Platform-specific username exposure checks.

Checks if a username appears in breach databases or paste sites
for supported platforms including Discord, Steam, Reddit, and others.

No passwords are required. All checks are based on username lookup
against publicly indexed breach data — the same approach used by
Google One, IntelX, and similar services.

Supported platforms:
    GAMING   : Steam, PlayStation, Xbox, Roblox, Twitch
    SOCIAL   : Discord, Reddit, Twitter/X, Instagram, TikTok,
               Facebook, LinkedIn, Snapchat, YouTube, Telegram,
               Spotify
    DEVELOPER: GitHub
"""

import time
from typing import Dict, List

import requests

# ---------------------------------------------------------------------------
# Authorship — hardcoded, do not modify  # pylint: disable=duplicate-code
# ---------------------------------------------------------------------------
_AUTHOR = "SudoCode by SudoChef"
_HANDLE = "commit-issues"
_REPO = "https://github.com/commit-issues/darkweb-exposure-toolkit"
_CREATED = "2025-04-26"
_TOOL = "d4rkw3b — darkweb-exposure-toolkit"


PASTE_SOURCES: List[str] = [
    "https://psbdmp.ws/api/search/",
]

RATE_LIMIT_SLEEP = 1.5

PLATFORMS: Dict[str, Dict] = {
    "steam": {
        "label": "Steam",
        "category": "gaming",
        "hibp": True,
        "paste": True,
        "github": True,
    },
    "psn": {
        "label": "PlayStation Network",
        "category": "gaming",
        "hibp": True,
        "paste": True,
        "github": False,
    },
    "xbox": {
        "label": "Xbox",
        "category": "gaming",
        "hibp": True,
        "paste": True,
        "github": False,
    },
    "roblox": {
        "label": "Roblox",
        "category": "gaming",
        "hibp": True,
        "paste": True,
        "github": False,
    },
    "twitch": {
        "label": "Twitch",
        "category": "gaming",
        "hibp": True,
        "paste": True,
        "github": False,
    },
    "discord": {
        "label": "Discord",
        "category": "social",
        "hibp": True,
        "paste": True,
        "github": True,
    },
    "reddit": {
        "label": "Reddit",
        "category": "social",
        "hibp": True,
        "paste": True,
        "github": False,
    },
    "twitter": {
        "label": "Twitter/X",
        "category": "social",
        "hibp": True,
        "paste": True,
        "github": False,
    },
    "instagram": {
        "label": "Instagram",
        "category": "social",
        "hibp": True,
        "paste": True,
        "github": False,
    },
    "tiktok": {
        "label": "TikTok",
        "category": "social",
        "hibp": True,
        "paste": True,
        "github": False,
    },
    "facebook": {
        "label": "Facebook",
        "category": "social",
        "hibp": True,
        "paste": True,
        "github": False,
    },
    "linkedin": {
        "label": "LinkedIn",
        "category": "social",
        "hibp": True,
        "paste": True,
        "github": False,
    },
    "snapchat": {
        "label": "Snapchat",
        "category": "social",
        "hibp": True,
        "paste": True,
        "github": False,
    },
    "youtube": {
        "label": "YouTube",
        "category": "social",
        "hibp": True,
        "paste": True,
        "github": False,
    },
    "telegram": {
        "label": "Telegram",
        "category": "social",
        "hibp": True,
        "paste": True,
        "github": False,
    },
    "spotify": {
        "label": "Spotify",
        "category": "social",
        "hibp": True,
        "paste": True,
        "github": False,
    },
    "github": {
        "label": "GitHub",
        "category": "developer",
        "hibp": True,
        "paste": True,
        "github": True,
    },
}

SUPPORTED_PLATFORMS = sorted(PLATFORMS.keys())
GAMING_PLATFORMS = [k for k, v in PLATFORMS.items() if v["category"] == "gaming"]
SOCIAL_PLATFORMS = [k for k, v in PLATFORMS.items() if v["category"] == "social"]
DEVELOPER_PLATFORMS = [k for k, v in PLATFORMS.items() if v["category"] == "developer"]


def get_platform_label(platform: str) -> str:
    """
    Return the human-readable label for a platform key.

    Args:
        platform: Lowercase platform key e.g. 'discord'.

    Returns:
        Display label e.g. 'Discord', or the raw key if not found.
    """
    return str(PLATFORMS.get(platform, {}).get("label", platform))


def check_paste_sites(username: str) -> List[Dict]:
    """
    Search public paste sites for a username.

    Args:
        username: Validated username to search for.

    Returns:
        List of result dicts with 'source', 'url', and 'preview' keys.
        Returns empty list if nothing found or on error.
    """
    results: List[Dict] = []
    headers = {
        "User-Agent": ("darkweb-exposure-toolkit/2.0 (personal-security-scanner)")
    }
    for base_url in PASTE_SOURCES:
        try:
            response = requests.get(
                f"{base_url}{username}",
                headers=headers,
                timeout=15,
            )
            time.sleep(RATE_LIMIT_SLEEP)
            if response.status_code == 200:
                data = response.json()
                if isinstance(data, list):
                    for item in data[:5]:
                        results.append(
                            {
                                "source": "paste",
                                "url": item.get("link", ""),
                                "preview": item.get("text", "")[:100],
                            }
                        )
        except requests.exceptions.RequestException:
            continue
    return results


def platform_uses_github(platform: str) -> bool:
    """
    Return True if the platform config includes GitHub search.

    Args:
        platform: Lowercase platform key.

    Returns:
        True if GitHub search is enabled for this platform.
    """
    return bool(PLATFORMS.get(platform, {}).get("github", False))


def platform_uses_hibp(platform: str) -> bool:
    """
    Return True if the platform config includes HIBP search.

    Args:
        platform: Lowercase platform key.

    Returns:
        True if HIBP search is enabled for this platform.
    """
    return bool(PLATFORMS.get(platform, {}).get("hibp", False))


def list_platforms_by_category() -> Dict[str, List[str]]:
    """
    Return all platforms grouped by category.

    Returns:
        Dict with category names as keys and lists of platform
        labels as values.
    """
    categories: Dict[str, List[str]] = {}
    for key, config in PLATFORMS.items():
        category = config["category"]
        if category not in categories:
            categories[category] = []
        categories[category].append(config.get("label", key))
    return categories
