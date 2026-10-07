"""Identifier detection, validation and normalisation.

The search box accepts anything and the app figures out what it is.  Detection
is intentionally conservative: when the input is ambiguous the user can always
override the type manually, and every claim the app makes about an identifier
is limited to what can actually be derived locally (for example a phone number
yields a *country calling code*, never an owner or a location).
"""

from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Any

from .crypto import bitcoin_address_kind, ethereum_address_status

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-z0-9\u00c0-\u024f-]{1,63}(?<!-)(\.(?!-)[a-z0-9\u00c0-\u024f-]{1,63}(?<!-))+$"
)
SINGLE_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,253}$")
USERNAME_RE = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,37}[a-z0-9])?$")
NAME_RE = re.compile(r"^[\w'’\-. ]{2,100}$", re.UNICODE)
PHONE_RE = re.compile(r"^\+?[0-9]{6,15}$")
ETH_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")
IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
IPV6_RE = re.compile(r"^[0-9a-f:]{2,45}$", re.IGNORECASE)
TLD_RE = re.compile(r"^(?:[a-z]{2,63}|xn--[a-z0-9]{1,59})$")

# Free/shared mailbox providers: a match against one of these is weak evidence
# because millions of unrelated people use the same domain.
SHARED_EMAIL_DOMAINS = frozenset({
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "msn.com",
    "yahoo.com", "yahoo.co.uk", "ymail.com", "icloud.com", "me.com", "mac.com",
    "aol.com", "gmx.com", "gmx.de", "gmx.net", "mail.com", "proton.me", "protonmail.com",
    "pm.me", "zoho.com", "yandex.com", "yandex.ru", "mail.ru", "inbox.ru", "list.ru",
    "qq.com", "163.com", "126.com", "sina.com", "naver.com", "daum.net", "rediffmail.com",
    "fastmail.com", "tutanota.com", "tuta.io", "hushmail.com", "cock.li", "disroot.org",
    "duck.com", "simplelogin.io", "mozmail.com", "apple.com", "att.net", "sbcglobal.net",
    "bellsouth.net", "comcast.net", "verizon.net", "charter.net", "cox.net", "earthlink.net",
})

# Profile sites: a pasted profile URL becomes a username lookup.
PROFILE_URL_SITES = {
    "github.com": "github",
    "www.github.com": "github",
    "gitlab.com": "gitlab",
    "www.gitlab.com": "gitlab",
    "codeberg.org": "codeberg",
    "keybase.io": "keybase",
    "news.ycombinator.com": "hackernews",
    "twitter.com": "twitter",
    "x.com": "twitter",
    "instagram.com": "instagram",
    "www.instagram.com": "instagram",
    "mastodon.social": "mastodon",
    "gravatar.com": "gravatar",
    "en.gravatar.com": "gravatar",
}

IDENTIFIER_TYPES = ("domain", "email", "username", "name", "phone", "bitcoin", "ethereum")

TYPE_LABELS = {
    "domain": "Domain / hostname",
    "email": "Email address",
    "username": "Username / handle",
    "name": "Person name",
    "phone": "Phone number",
    "bitcoin": "Bitcoin address",
    "ethereum": "Ethereum address",
}


class IdentifierError(ValueError):
    """Raised when input cannot be interpreted as a supported identifier."""


@dataclass
class Identifier:
    kind: str
    value: str  # normalised value used for lookups
    display: str  # what the UI shows (echoes the user's input shape)
    notes: list[str] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "type": self.kind,
            "type_label": TYPE_LABELS.get(self.kind, self.kind),
            "value": self.value,
            "display": self.display,
            "notes": self.notes,
            "meta": self.meta,
        }


# ---------------------------------------------------------------------------
# Phone handling (local only - nothing is ever sent to a third party)
# ---------------------------------------------------------------------------

CALLING_CODES: dict[str, str] = {
    "1": "NANP region (United States, Canada and ~18 Caribbean territories)",
    "7": "Russia / Kazakhstan", "20": "Egypt", "27": "South Africa", "30": "Greece",
    "31": "Netherlands", "32": "Belgium", "33": "France", "34": "Spain", "36": "Hungary",
    "39": "Italy", "40": "Romania", "41": "Switzerland", "43": "Austria", "44": "United Kingdom",
    "45": "Denmark", "46": "Sweden", "47": "Norway", "48": "Poland", "49": "Germany",
    "51": "Peru", "52": "Mexico", "53": "Cuba", "54": "Argentina", "55": "Brazil",
    "56": "Chile", "57": "Colombia", "58": "Venezuela", "60": "Malaysia", "61": "Australia",
    "62": "Indonesia", "63": "Philippines", "64": "New Zealand", "65": "Singapore",
    "66": "Thailand", "81": "Japan", "82": "South Korea", "84": "Vietnam", "86": "China",
    "90": "Türkiye", "91": "India", "92": "Pakistan", "93": "Afghanistan", "94": "Sri Lanka",
    "95": "Myanmar", "98": "Iran", "211": "South Sudan", "212": "Morocco", "213": "Algeria",
    "216": "Tunisia", "218": "Libya", "220": "Gambia", "221": "Senegal", "222": "Mauritania",
    "223": "Mali", "224": "Guinea", "225": "Côte d'Ivoire", "226": "Burkina Faso",
    "227": "Niger", "228": "Togo", "229": "Benin", "230": "Mauritius", "231": "Liberia",
    "232": "Sierra Leone", "233": "Ghana", "234": "Nigeria", "235": "Chad", "236": "CAR",
    "237": "Cameroon", "238": "Cape Verde", "239": "São Tomé & Príncipe", "240": "Equatorial Guinea",
    "241": "Gabon", "242": "Congo-Brazzaville", "243": "DR Congo", "244": "Angola",
    "245": "Guinea-Bissau", "248": "Seychelles", "249": "Sudan", "250": "Rwanda",
    "251": "Ethiopia", "252": "Somalia", "253": "Djibouti", "254": "Kenya", "255": "Tanzania",
    "256": "Uganda", "257": "Burundi", "258": "Mozambique", "260": "Zambia", "261": "Madagascar",
    "262": "Réunion / Mayotte", "263": "Zimbabwe", "264": "Namibia", "265": "Malawi",
    "266": "Lesotho", "267": "Botswana", "268": "Eswatini", "269": "Comoros",
    "290": "Saint Helena", "291": "Eritrea", "297": "Aruba", "298": "Faroe Islands",
    "299": "Greenland", "350": "Gibraltar", "351": "Portugal", "352": "Luxembourg",
    "353": "Ireland", "354": "Iceland", "355": "Albania", "356": "Malta", "357": "Cyprus",
    "358": "Finland", "359": "Bulgaria", "370": "Lithuania", "371": "Latvia", "372": "Estonia",
    "373": "Moldova", "374": "Armenia", "375": "Belarus", "376": "Andorra", "377": "Monaco",
    "378": "San Marino", "379": "Vatican City", "380": "Ukraine", "381": "Serbia",
    "382": "Montenegro", "383": "Kosovo", "385": "Croatia", "386": "Slovenia",
    "387": "Bosnia & Herzegovina", "389": "North Macedonia", "420": "Czechia",
    "421": "Slovakia", "423": "Liechtenstein", "500": "Falkland Islands", "501": "Belize",
    "502": "Guatemala", "503": "El Salvador", "504": "Honduras", "505": "Nicaragua",
    "506": "Costa Rica", "507": "Panama", "508": "Saint-Pierre & Miquelon", "509": "Haiti",
    "590": "Guadeloupe", "591": "Bolivia", "592": "Guyana", "593": "Ecuador", "594": "French Guiana",
    "595": "Paraguay", "596": "Martinique", "597": "Suriname", "598": "Uruguay",
    "599": "Caribbean Netherlands / Curaçao", "670": "Timor-Leste", "672": "Norfolk Island",
    "673": "Brunei", "674": "Nauru", "675": "Papua New Guinea", "676": "Tonga", "677": "Solomon Islands",
    "678": "Vanuatu", "679": "Fiji", "680": "Palau", "681": "Wallis & Futuna",
    "682": "Cook Islands", "683": "Niue", "685": "Samoa", "686": "Kiribati",
    "687": "New Caledonia", "688": "Tuvalu", "689": "French Polynesia", "690": "Tokelau",
    "691": "Micronesia", "692": "Marshall Islands", "850": "North Korea", "852": "Hong Kong",
    "853": "Macau", "855": "Cambodia", "856": "Laos", "880": "Bangladesh", "886": "Taiwan",
    "960": "Maldives", "961": "Lebanon", "962": "Jordan", "963": "Syria", "964": "Iraq",
    "965": "Kuwait", "966": "Saudi Arabia", "967": "Yemen", "968": "Oman", "970": "Palestine",
    "971": "United Arab Emirates", "972": "Israel", "973": "Bahrain", "974": "Qatar",
    "975": "Bhutan", "976": "Mongolia", "977": "Nepal", "992": "Tajikistan",
    "993": "Turkmenistan", "994": "Azerbaijan", "995": "Georgia", "996": "Kyrgyzstan",
    "998": "Uzbekistan",
}


# North American Numbering Plan toll-free prefixes (informational only).
NANP_TOLL_FREE = frozenset({"800", "888", "877", "866", "855", "844", "833"})


def parse_phone(raw: str) -> dict[str, Any]:
    """Parse a phone number locally.  Returns format/country facts only."""
    digits = re.sub(r"[^0-9+]", "", raw.strip())
    if not digits:
        raise IdentifierError("That does not look like a phone number.")
    had_plus = digits.startswith("+") or raw.strip().startswith("+")
    digits_only = digits.lstrip("+")
    if not digits_only.isdigit():
        raise IdentifierError("Phone numbers may only contain digits, spaces and + - ( ) .")
    if not 6 <= len(digits_only) <= 15:
        raise IdentifierError(
            "Phone numbers must contain between 6 and 15 digits (E.164 allows up to 15)."
        )
    if not had_plus and len(digits_only) == 10 and digits_only[0] in "23456789":
        # Assume a North American style 10-digit local number, but say so.
        e164 = "+1" + digits_only
        assumption = "Assumed +1 (North America) because no country code was given."
    elif had_plus:
        e164 = "+" + digits_only
        assumption = ""
    else:
        e164 = "+" + digits_only
        assumption = "No leading '+' was given, so the digits were read as a full international number."
    body = e164[1:]
    calling_code = ""
    country = "Unknown / not in the bundled table"
    for length in (3, 2, 1):
        candidate = body[:length]
        if candidate in CALLING_CODES:
            calling_code = "+" + candidate
            country = CALLING_CODES[candidate]
            break
    national = body[len(calling_code.lstrip("+")):] if calling_code else body
    notes = [
        "Parsed locally in your browser session - the number is never sent to a third-party API.",
        "This shows format and country calling code only. It does not identify the owner, "
        "the carrier, whether the number is currently active, or any location.",
    ]
    if assumption:
        notes.append(assumption)
    if calling_code == "+1":
        notes.append(
            "Country calling code +1 is shared by the US, Canada and many Caribbean territories; "
            "the specific country cannot be determined from the number alone."
        )
        if national[:3] in NANP_TOLL_FREE:
            notes.append(
                f"North American toll-free prefix ({national[:3]}): this is a service or business line, "
                "not a personal mobile number, and calls to it are not charged to the caller."
            )
    return {
        "e164": e164,
        "calling_code": calling_code,
        "country": country,
        "national_significant_number": national,
        "digit_count": len(body),
        "international_format": (calling_code + " " + national).strip(),
        "notes": notes,
    }


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------


def _is_ip_literal(text: str) -> bool:
    candidate = text.strip().strip("[]")
    if IP_RE.match(candidate):
        return True
    return ":" in candidate and bool(IPV6_RE.match(candidate)) and not candidate.startswith("http")


def _normalise_domain(raw: str) -> str:
    domain = raw.strip().lower().rstrip(".")
    if domain.startswith("*."):
        domain = domain[2:]
    try:
        domain = domain.encode("idna").decode("ascii") if any(ord(c) > 127 for c in domain) else domain
    except (UnicodeError, ValueError):
        pass
    return domain


def _host_from_url(raw: str) -> tuple[str, str] | None:
    candidate = raw.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", candidate):
        candidate = "https://" + candidate
    try:
        parsed = urllib.parse.urlsplit(candidate)
    except ValueError:
        return None
    host = (parsed.hostname or "").strip().lower().rstrip(".")
    if not host:
        return None
    path = parsed.path.strip("/")
    return host, path


def detect(raw: str, *, forced_type: str = "auto") -> Identifier:
    """Detect (or coerce) an identifier type.  Raises :class:`IdentifierError`."""
    if raw is None:
        raise IdentifierError("Enter an identifier to look up.")
    text = raw.strip()
    if not text:
        raise IdentifierError("Enter an identifier to look up.")
    if len(text) > 300:
        raise IdentifierError("Input is too long (limit 300 characters).")
    if any(ord(ch) < 32 for ch in text):
        raise IdentifierError("Input contains control characters.")

    kind = (forced_type or "auto").strip().lower()
    if kind not in ("auto",) + IDENTIFIER_TYPES:
        raise IdentifierError(f"Unknown identifier type '{kind}'.")

    # --- obvious structural types first (they beat "auto" heuristics) -------
    if kind == "auto":
        if ETH_RE.match(text):
            status = ethereum_address_status(text)
            if status == "invalid":
                raise IdentifierError(
                    "That looks like an Ethereum address but fails the EIP-55 mixed-case checksum. "
                    "Re-copy it, or paste it in all-lowercase."
                )
            notes = []
            if status == "valid-no-checksum":
                notes.append("Address is all lower/upper case, so the EIP-55 checksum could not be verified.")
            else:
                notes.append("EIP-55 mixed-case checksum verified locally.")
            return Identifier(
                kind="ethereum",
                value=text[:2].lower() + text[2:],
                display=text,
                notes=notes,
                meta={"checksum": status},
            )
        if re.match(r"^(bc1|tb1|1|3)[a-zA-HJ-NP-Z0-9]{20,}$", text, re.IGNORECASE):
            address_kind = bitcoin_address_kind(text)
            if address_kind:
                return Identifier(
                    kind="bitcoin", value=text.strip(), display=text,
                    notes=[f"Valid mainnet Bitcoin address ({address_kind}); checksum verified locally."],
                    meta={"address_kind": address_kind},
                )
            lowered = text.lower()
            if lowered.startswith("tb1"):
                raise IdentifierError(
                    "That is a Bitcoin testnet address (tb1...). Only mainnet addresses are supported."
                )
            raise IdentifierError(
                "That looks like a Bitcoin address but the checksum is invalid. Re-copy it and try again."
            )
        if EMAIL_RE.match(text.lower()):
            local, _, domain = text.lower().partition("@")
            if not DOMAIN_RE.match(domain) or "." not in domain:
                raise IdentifierError("The domain part of that email address is not valid.")
            notes = []
            if domain in SHARED_EMAIL_DOMAINS:
                notes.append(
                    f"{domain} is a shared mailbox provider used by millions of people, so a matching "
                    "name or handle elsewhere is weak evidence."
                )
            return Identifier(
                kind="email",
                value=f"{local}@{domain}",
                display=text,
                notes=notes,
                meta={"local_part": local, "domain": domain, "shared_provider": domain in SHARED_EMAIL_DOMAINS},
            )
        if "://" in text or text.startswith("www.") or (("/" in text) and (" " not in text) and ("." in text.split("/")[0])):
            parsed = _host_from_url(text)
            if parsed:
                host, path = parsed
                if _is_ip_literal(host):
                    raise IdentifierError(
                        "IP addresses are not a supported identifier type in this build. Regional IP registration data "
                        "(ARIN/RIPE/APNIC RDAP) is not part of the allowlisted source set. Use a domain name instead."
                    )
                site = PROFILE_URL_SITES.get(host)
                if site and path and "/" not in path and USERNAME_RE.match(path.lower()):
                    return Identifier(
                        kind="username",
                        value=path.lower(),
                        display=path,
                        notes=[f"Username '{path}' extracted from a pasted {host} profile URL."],
                        meta={"origin_site": site, "origin_host": host},
                    )
                if DOMAIN_RE.match(host) and TLD_RE.match(host.rsplit(".", 1)[-1]):
                    return Identifier(
                        kind="domain", value=_normalise_domain(host), display=host,
                        notes=["Host extracted from a pasted URL; the path/query was discarded."],
                        meta={"from_url": True},
                    )
        if _is_ip_literal(text):
            raise IdentifierError(
                "IP addresses are not a supported identifier type in this build. Regional IP registration data "
                "(ARIN/RIPE/APNIC RDAP) is not part of the allowlisted source set, so a lookup would be misleading. "
                "Use a domain name, email, username, person name, phone number or wallet address."
            )
        if DOMAIN_RE.match(text.lower()) and TLD_RE.match(text.lower().rsplit(".", 1)[-1]):
            return Identifier(kind="domain", value=_normalise_domain(text), display=text.lower())
        if PHONE_RE.match(re.sub(r"[\s().\-]", "", text)) and sum(c.isdigit() for c in text) >= 7:
            data = parse_phone(text)
            return Identifier(
                kind="phone", value=data["e164"], display=data["international_format"],
                notes=data["notes"], meta=data,
            )
        if text.startswith("@") and USERNAME_RE.match(text[1:].lower()):
            return Identifier(
                kind="username", value=text[1:].lower(), display=text,
                notes=["'@handle' read as a username. The '@' is not part of the handle itself."],
            )
        if SINGLE_LABEL_RE.match(text.lower()) and USERNAME_RE.match(text.lower()):
            return Identifier(
                kind="username", value=text.lower(), display=text,
                notes=["Single-token input read as a username. Switch the type manually if you meant a domain or name."],
            )
        if NAME_RE.match(text) and " " in text.strip():
            cleaned = re.sub(r"\s+", " ", text.strip())
            return Identifier(
                kind="name", value=cleaned, display=cleaned,
                notes=[
                    "Name searches return *candidates* from public indexes. A matching name is not "
                    "evidence that two records describe the same person.",
                ],
            )
        raise IdentifierError(
            "Could not work out what that is. Try a domain (example.com), an email address, a "
            "username, a person's full name, a phone number in international format (+44...) or a "
            "Bitcoin/Ethereum wallet address - or pick the type manually."
        )

    # --- forced types ------------------------------------------------------
    if kind == "domain":
        host = text.lower()
        parsed = _host_from_url(host) if ("/" in host or "://" in host) else None
        if parsed:
            host = parsed[0]
        host = _normalise_domain(host)
        if _is_ip_literal(host):
            raise IdentifierError("That is an IP address, not a domain name. IP registration lookups are not supported here.")
        if not DOMAIN_RE.match(host):
            raise IdentifierError(f"'{host}' is not a valid domain name (it needs at least one dot).")
        if not TLD_RE.match(host.rsplit(".", 1)[-1]):
            raise IdentifierError(
                f"'{host}' does not end in a valid top-level domain. A TLD is letters only (for example .com, .org, .museum)."
            )
        return Identifier(kind="domain", value=host, display=host)

    if kind == "email":
        lowered = text.lower()
        if not EMAIL_RE.match(lowered):
            raise IdentifierError("That is not a valid email address (expected local-part@domain).")
        local, _, domain = lowered.partition("@")
        if not DOMAIN_RE.match(domain):
            raise IdentifierError("The domain part of that email address is not valid.")
        return Identifier(
            kind="email", value=lowered, display=text,
            meta={"local_part": local, "domain": domain, "shared_provider": domain in SHARED_EMAIL_DOMAINS},
        )

    if kind == "username":
        candidate = text.strip().lstrip("@")
        parsed = _host_from_url(candidate) if "/" in candidate else None
        if parsed and PROFILE_URL_SITES.get(parsed[0]) and parsed[1] and "/" not in parsed[1]:
            candidate = parsed[1]
        candidate = candidate.strip().lower()
        if not USERNAME_RE.match(candidate):
            raise IdentifierError(
                "Usernames may contain letters, digits, dots, hyphens and underscores "
                "(2-39 characters, no leading/trailing separator)."
            )
        return Identifier(kind="username", value=candidate, display=candidate)

    if kind == "name":
        cleaned = re.sub(r"\s+", " ", text.strip())
        if not NAME_RE.match(cleaned):
            raise IdentifierError("Names may contain letters, spaces, apostrophes, hyphens and dots.")
        if len(cleaned) < 3:
            raise IdentifierError("Enter at least 3 characters for a name search.")
        return Identifier(kind="name", value=cleaned, display=cleaned)

    if kind == "phone":
        data = parse_phone(text)
        return Identifier(kind="phone", value=data["e164"], display=data["international_format"],
                          notes=data["notes"], meta=data)

    if kind == "bitcoin":
        address_kind = bitcoin_address_kind(text)
        if not address_kind:
            raise IdentifierError("That is not a valid mainnet Bitcoin address (checksum failed).")
        return Identifier(kind="bitcoin", value=text.strip(), display=text.strip(),
                          notes=[f"Valid mainnet Bitcoin address ({address_kind}); checksum verified locally."],
                          meta={"address_kind": address_kind})

    if kind == "ethereum":
        status = ethereum_address_status(text)
        if status == "invalid":
            raise IdentifierError("That is not a valid Ethereum address (0x + 40 hex characters, EIP-55 checksum).")
        return Identifier(kind="ethereum", value=text[:2].lower() + text[2:], display=text,
                          notes=["EIP-55 checksum verified locally." if status == "valid-checksum"
                                 else "All lower/upper case: EIP-55 checksum could not be verified."],
                          meta={"checksum": status})

    raise IdentifierError("Unknown identifier type.")  # pragma: no cover


def apex_domain(domain: str) -> str:
    """Best-effort registrable domain (last two labels; common 2-level TLDs kept)."""
    parts = domain.lower().strip(".").split(".")
    if len(parts) <= 2:
        return ".".join(parts)
    second_level = {
        "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk", "sch.uk", "nhs.uk", "police.uk",
        "com.au", "net.au", "org.au", "edu.au", "gov.au", "id.au",
        "co.nz", "net.nz", "org.nz", "govt.nz", "ac.nz", "school.nz",
        "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp",
        "com.br", "net.br", "org.br", "gov.br", "edu.br",
        "co.in", "net.in", "org.in", "gen.in", "firm.in", "ind.in",
        "com.tr", "net.tr", "org.tr", "gov.tr",
        "co.za", "org.za", "web.za", "net.za",
        "com.mx", "org.mx", "gob.mx", "edu.mx", "net.mx",
        "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn",
        "com.hk", "org.hk", "gov.hk", "edu.hk",
        "com.tw", "org.tw", "gov.tw", "edu.tw",
        "com.sg", "org.sg", "gov.sg", "edu.sg",
        "co.kr", "or.kr", "go.kr", "ne.kr",
        "com.ar", "net.ar", "org.ar", "gob.ar",
        "com.my", "net.my", "org.my", "gov.my", "edu.my",
        "co.id", "web.id", "or.id", "go.id", "ac.id",
        "com.ua", "org.ua", "net.ua", "edu.ua", "gov.ua",
        "com.pl", "net.pl", "org.pl", "gov.pl", "edu.pl",
        "com.ru", "net.ru", "org.ru", "msk.ru",
    }
    suffix = ".".join(parts[-2:])
    if suffix in second_level and len(parts) >= 3:
        return ".".join(parts[-3:])
    return suffix
