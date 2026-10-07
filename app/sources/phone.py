"""Local-only phone parsing.

No phone number is ever sent to a third party by this app. Carrier, owner and
location lookups require paid databases (and often the subject's consent), so
they are deliberately not attempted; the source says exactly that.
"""

from __future__ import annotations

from typing import Any

from .base import Evidence, Finding, SourceContext, STATUS_OK, source

# Non-geographic North American prefixes that can be identified from the number
# itself (nothing here implies an owner or a location).
NANP_TOLL_FREE = {"800", "888", "877", "866", "855", "844", "833"}
NANP_PREMIUM = {"900"}


@source(
    id="phone_local",
    name="Phone number analysis (local)",
    category="identity",
    applies_to=("phone",),
    sends="Nothing. The number is parsed inside this app and never sent to any third party.",
    docs="https://en.wikipedia.org/wiki/E.164",
    description="Validates the format, derives the country calling code and states what cannot be known.",
)
def phone_local(ctx: SourceContext) -> dict[str, Any]:
    ident = ctx.identifier
    meta = dict(ident.meta or {})
    e164 = meta.get("e164") or ident.value
    calling_code = meta.get("calling_code", "")
    country = meta.get("country", "unknown")
    national = str(meta.get("national_significant_number", ""))

    evidence = [
        Evidence("Input", ident.display),
        Evidence("E.164 form", e164),
        Evidence("Country calling code", calling_code or "not recognised"),
        Evidence("Region for that code", country),
        Evidence("Digits after the calling code", str(len(national))),
    ]
    notes: list[str] = []

    if calling_code == "+1" and len(national) >= 3:
        prefix = national[:3]
        if prefix in NANP_TOLL_FREE:
            notes.append(f"The +1 {prefix} prefix is a North American toll-free range (non-geographic).")
            evidence.append(Evidence("Number range", f"toll-free ({prefix})"))
        elif prefix in NANP_PREMIUM:
            notes.append("The +1 900 prefix is a North American premium-rate range.")
            evidence.append(Evidence("Number range", "premium rate (900)"))
        else:
            notes.append("The +1 area code cannot be mapped to a current location reliably; area codes are "
                         "portable and re-assigned.")
    if len(national) <= 5:
        notes.append("Very short national numbers are usually internal short codes, not public subscriber lines.")

    interpretation = (
        "This is a format/country check only. It cannot tell you who owns the number, which carrier serves it, "
        "whether it is still in service, or where it is - and this app does not query paid people-search or "
        "carrier databases, HLR lookups, or any 'dark web' source."
    )
    findings = [Finding(
        source_id="phone_local", source_name="Phone number analysis (local)", severity="info",
        category="identity",
        title=f"Phone number parses as {e164}",
        summary=(f"Valid international format with country calling code {calling_code or 'unknown'} "
                 f"({country}).") + (" " + notes[0] if notes else ""),
        evidence=evidence,
        links=[Evidence("E.164 numbering standard (reference)", "https://en.wikipedia.org/wiki/E.164")],
        interpretation=interpretation,
    )]
    data = {
        "e164": e164, "calling_code": calling_code, "country": country,
        "national_significant_number_length": len(national), "notes": notes,
        "third_party_queries": 0,
    }
    return {
        "status": STATUS_OK,
        "message": "Parsed locally. No third-party service was queried with this phone number.",
        "findings": findings,
        "data": data,
        "upstream_host": "",
    }
