"""DNS (Google DNS-over-HTTPS) and domain registration (RDAP) sources."""

from __future__ import annotations

import concurrent.futures as futures
import re
from datetime import datetime, timedelta, timezone
from typing import Any

from ..config import SETTINGS
from ..http_client import UpstreamError, UpstreamHTTPError
from .base import (
    Evidence,
    Finding,
    SourceContext,
    SourceOutcome,
    STATUS_NO_MATCH,
    STATUS_OK,
    STATUS_UNAVAILABLE,
    parse_upstream_timestamp,
    source,
)

DOH_BASE = "https://dns.google/resolve"
RDAP_BOOTSTRAP = "https://rdap.org/domain/"

# DoH numeric types (kept explicit so we never pass an arbitrary type string).
RRTYPES = {"A": 1, "AAAA": 28, "MX": 15, "NS": 2, "TXT": 16, "SOA": 6, "CAA": 257}

DNS_NXDOMAIN = 3


def _answers(payload: dict[str, Any], rrtype: int) -> list[dict[str, Any]]:
    return [a for a in (payload.get("Answer") or []) if a.get("type") == rrtype]


def doh_lookup(ctx: SourceContext, name: str, rrtype: str, *, timeout: float | None = None) -> dict[str, Any]:
    if rrtype not in RRTYPES:
        raise UpstreamError(f"unsupported record type {rrtype}")
    query_name = name.strip(".").lower()
    url = f"{DOH_BASE}?name={query_name}&type={rrtype}"
    return ctx.fetcher.get_json(
        url,
        headers={"Accept": "application/dns-json"},
        timeout=timeout or SETTINGS.limits.per_source_timeout,
        cache_key=f"doh:{rrtype}:{query_name}",
        cache_ttl=SETTINGS.limits.cache_default_ttl,
    )


def _parse_spf(txt_records: list[str]) -> dict[str, Any]:
    spf = next((r for r in txt_records if r.lower().replace(" ", "").startswith("v=spf1")), None)
    if spf is None:
        return {"present": False}
    tokens = spf.split()
    all_mechanism = ""
    includes: list[str] = []
    for token in tokens:
        low = token.lower()
        if low in ("+all", "-all", "~all", "?all", "all"):
            all_mechanism = low if low != "all" else "+all"
        if low.startswith("include:"):
            includes.append(token.split(":", 1)[1])
    return {"present": True, "record": spf, "all": all_mechanism, "includes": includes}


def _parse_dmarc(txt_records: list[str]) -> dict[str, Any]:
    record = next((r for r in txt_records if r.lower().replace(" ", "").startswith("v=dmarc1")), None)
    if record is None:
        return {"present": False}
    parts = dict()
    for chunk in record.split(";"):
        if "=" in chunk:
            key, _, value = chunk.strip().partition("=")
            parts[key.strip().lower()] = value.strip()
    return {
        "present": True,
        "record": record,
        "policy": parts.get("p", "none"),
        "subdomain_policy": parts.get("sp", ""),
        "report_uri": parts.get("rua", ""),
        "forensic_uri": parts.get("ruf", ""),
        "percentage": parts.get("pct", ""),
    }


def _txt_strings(payload: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for answer in _answers(payload, RRTYPES["TXT"]):
        data = str(answer.get("data", "")).strip()
        if data.startswith('"') and data.endswith('"'):
            data = data[1:-1]
        # Google DoH splits long TXT records into quoted chunks.
        data = data.replace('" "', "").replace('""', "")
        out.append(data)
    return out


@source(
    id="dns_doh",
    name="Google DNS-over-HTTPS",
    category="infrastructure",
    applies_to=("domain", "email"),
    sends="The domain name only (no email address, no personal data).",
    docs="https://developers.google.com/speed/public-dns/docs/doh/json",
    description="A, AAAA, MX, NS, TXT (SPF) and _dmarc TXT (DMARC) records via Google's public resolver.",
)
def dns_doh(ctx: SourceContext) -> dict[str, Any]:
    ident = ctx.identifier
    domain = ident.value if ident.kind == "domain" else ident.meta.get("domain", "")
    if not domain:
        raise SourceOutcome(STATUS_NO_MATCH, "No domain to resolve.")

    wanted = ("A", "AAAA", "MX", "NS", "TXT", "DMARC")
    results: dict[str, Any] = {}
    errors: dict[str, str] = {}

    def fetch(record_type: str) -> tuple[str, dict[str, Any]]:
        name = f"_dmarc.{domain}" if record_type == "DMARC" else domain
        key = "TXT" if record_type == "DMARC" else record_type
        return record_type, doh_lookup(ctx, name, key, timeout=min(8.0, SETTINGS.limits.per_source_timeout))

    with futures.ThreadPoolExecutor(max_workers=4, thread_name_prefix="doh") as pool:
        pending = {pool.submit(fetch, rt): rt for rt in wanted}
        done, _ = futures.wait(pending, timeout=SETTINGS.limits.per_source_timeout + 4)
        for future in done:
            try:
                rtype, payload = future.result()
                results[rtype] = payload
            except UpstreamError as exc:
                errors[pending[future]] = str(exc)
        for future, rtype in pending.items():
            if future not in done:
                future.cancel()
                errors[rtype] = "timed out"

    if not results and errors:
        raise SourceOutcome(
            STATUS_UNAVAILABLE,
            f"DNS lookups failed ({next(iter(errors.values()))}).",
            data={"errors": errors},
        )

    a_records = [str(x.get("data")) for x in _answers(results.get("A", {}), RRTYPES["A"])]
    aaaa_records = [str(x.get("data")) for x in _answers(results.get("AAAA", {}), RRTYPES["AAAA"])]
    mx_records = sorted(str(x.get("data", "")) for x in _answers(results.get("MX", {}), RRTYPES["MX"]))
    ns_records = sorted(str(x.get("data", "")).strip(".").lower() for x in _answers(results.get("NS", {}), RRTYPES["NS"]))
    txt_records = _txt_strings(results.get("TXT", {}))
    dmarc_records = _txt_strings(results.get("DMARC", {}))

    spf = _parse_spf(txt_records)
    dmarc = _parse_dmarc(dmarc_records)

    # A failed query must never be reported as "record absent": the three states
    # (data / no match / could not check) have to stay distinguishable.
    got = set(results.keys())
    nxdomain = bool(got) and all((results[rt] or {}).get("Status") == DNS_NXDOMAIN for rt in got)
    dnssec = bool(results.get("A", {}).get("AD")) if "A" in got else False

    data = {
        "domain": domain,
        "a": a_records,
        "aaaa": aaaa_records,
        "mx": mx_records,
        "nameservers": ns_records,
        "txt": txt_records[:20],
        "spf": spf,
        "dmarc": dmarc,
        "dnssec_validated": dnssec,
        "nxdomain": nxdomain,
        "queries_succeeded": sorted(got),
        "partial_failures": errors,
    }

    findings: list[Finding] = []
    src = "dns_doh"
    src_name = "Google DNS-over-HTTPS"

    if not got:
        raise SourceOutcome(
            STATUS_UNAVAILABLE,
            f"All DNS queries for {domain} failed ({next(iter(errors.values()), 'unknown error')}).",
            data=data,
        )

    if nxdomain:
        findings.append(Finding(
            source_id=src, source_name=src_name, severity="info", category="infrastructure",
            title="Domain does not resolve in DNS",
            summary=f"DNS returned NXDOMAIN for {domain}: no A, AAAA, MX, NS or TXT record exists. "
                    "The domain may be unregistered, expired, or delegated without any records.",
            evidence=[Evidence("Query", domain), Evidence("DNS status", "NXDOMAIN (3)"),
                      Evidence("Record types checked", ", ".join(sorted(got)))],
            links=[Evidence("Google DNS view", f"https://dns.google/query?name={domain}&type=A")],
            interpretation="Absence of DNS records is not evidence of wrongdoing; it usually means the name is not in active use.",
        ))
    elif {"A", "AAAA"} & got:
        evidence = [Evidence("Domain", domain), Evidence("Record types answered", ", ".join(sorted(got)))]
        if a_records:
            evidence.append(Evidence("IPv4", ", ".join(a_records[:6])))
        if aaaa_records:
            evidence.append(Evidence("IPv6", ", ".join(aaaa_records[:6])))
        if "NS" in got and ns_records:
            evidence.append(Evidence("Nameservers", ", ".join(ns_records[:8])))
        findings.append(Finding(
            source_id=src, source_name=src_name, severity="info", category="infrastructure",
            title=("Domain resolves in public DNS" if (a_records or aaaa_records)
                   else "Domain exists in DNS but has no address records"),
            summary=(f"{domain} publishes address records, so it is actively delegated and reachable."
                     if (a_records or aaaa_records) else
                     f"{domain} exists in DNS (the resolver returned an answer) but published no A/AAAA records."),
            evidence=evidence,
            links=[Evidence("Google DNS view", f"https://dns.google/query?name={domain}&type=A")],
            interpretation="Resolving in DNS says nothing about who operates the service or whether it is trustworthy.",
        ))

    if dnssec:
        findings.append(Finding(
            source_id=src, source_name=src_name, severity="info", category="infrastructure",
            title="DNSSEC-signed responses",
            summary=f"The resolver marked answers for {domain} as DNSSEC-authenticated (AD flag set).",
            evidence=[Evidence("DNSSEC", "validated (AD=1)")],
            interpretation="DNSSEC protects DNS answers from tampering; it does not vouch for the site's content.",
        ))

    # --- Mail configuration (only when the MX query actually succeeded) -----
    if "MX" in got and not nxdomain:
        if mx_records:
            findings.append(Finding(
                source_id=src, source_name=src_name, severity="info", category="email",
                title="Domain accepts email",
                summary=f"{len(mx_records)} MX record(s) point at mail servers, so addresses at {domain} can receive mail.",
                evidence=[Evidence("MX records", "; ".join(mx_records[:6]))],
                interpretation="Mail servers are usually a provider (Google Workspace, Microsoft 365, ...); that reveals the mail vendor, not the mailbox owner.",
            ))
        else:
            findings.append(Finding(
                source_id=src, source_name=src_name,
                severity="low" if ident.kind == "email" else "info", category="email",
                title="No MX records for this domain",
                summary=f"{domain} publishes no MX records, so standard email delivery to this domain will fail.",
                evidence=[Evidence("MX records", "none"), Evidence("Domain", domain)],
                interpretation="An address at a domain without MX records is often a typo, a placeholder or a disposable alias.",
            ))

    if "TXT" in got and not nxdomain:
        if spf.get("present"):
            all_mech = spf.get("all", "")
            severity = {"-all": "info", "~all": "low", "?all": "low", "+all": "high"}.get(all_mech, "low")
            title = {
                "-all": "SPF published with a strict 'fail all' policy",
                "~all": "SPF published with a 'softfail' policy",
                "?all": "SPF published with a neutral policy",
                "+all": "SPF published with a permissive 'allow all' policy",
            }.get(all_mech, "SPF record published")
            summary_map = {
                "-all": f"Mail from {domain} that does not match the SPF record should be rejected by receivers.",
                "~all": f"Mail from {domain} that does not match SPF is only marked 'softfail', so spoofed mail may still be delivered.",
                "?all": f"The SPF record for {domain} takes no position on non-matching mail.",
                "+all": f"The SPF record for {domain} ends in +all, which allows ANY server to send mail as this domain.",
            }
            findings.append(Finding(
                source_id=src, source_name=src_name, severity=severity, category="email",
                title=title,
                summary=summary_map.get(all_mech, f"SPF record published for {domain}."),
                evidence=[Evidence("SPF record", spf.get("record", "")[:300]),
                          Evidence("Delegated senders (include:)", ", ".join(spf.get("includes") or []) or "none")],
                interpretation="SPF lists who may send mail for the domain; each include: also hands some reputation to a third party.",
            ))
        else:
            findings.append(Finding(
                source_id=src, source_name=src_name,
                severity="medium" if mx_records else "low", category="email",
                title="No SPF record published",
                summary=f"{domain} has no SPF record, so receiving mail servers cannot tell legitimate senders from spoofed ones.",
                evidence=[Evidence("SPF", "absent"),
                          Evidence("MX present", ("yes" if mx_records else "no") if "MX" in got else "unknown (MX query failed)")],
                interpretation="Missing SPF is an email-security gap for the domain owner, not evidence about any individual.",
            ))

    if "DMARC" in got and not nxdomain:
        if dmarc.get("present"):
            policy = (dmarc.get("policy") or "none").lower()
            severity = {"reject": "info", "quarantine": "info", "none": "low"}.get(policy, "low")
            summary = {
                "reject": f"DMARC policy for {domain} is 'reject': unauthenticated mail should be refused.",
                "quarantine": f"DMARC policy for {domain} is 'quarantine': unauthenticated mail is typically sent to spam.",
                "none": f"DMARC policy for {domain} is 'none': reports only, spoofed mail is not blocked.",
            }.get(policy, f"DMARC policy for {domain} is '{policy}'.")
            evidence = [Evidence("DMARC record", dmarc.get("record", "")[:300]), Evidence("Policy (p=)", policy)]
            if dmarc.get("report_uri"):
                evidence.append(Evidence("Aggregate reports sent to", dmarc["report_uri"][:200]))
            findings.append(Finding(
                source_id=src, source_name=src_name, severity=severity, category="email",
                title=f"DMARC published (policy: {policy})", summary=summary, evidence=evidence,
                interpretation="A DMARC 'rua=' address can itself leak a mailbox at another domain - worth checking if this is your domain.",
            ))
        elif mx_records:
            findings.append(Finding(
                source_id=src, source_name=src_name, severity="medium", category="email",
                title="No DMARC policy published",
                summary=f"{domain} accepts mail (MX records exist) but publishes no DMARC policy, so spoofed mail is not filtered by policy.",
                evidence=[Evidence("DMARC", "absent"), Evidence("MX present", "yes")],
                interpretation="Missing DMARC is an email-security gap for the domain owner; it does not identify any person.",
            ))

    if errors:
        findings.append(Finding(
            source_id=src, source_name=src_name, severity="info", category="infrastructure",
            title=f"{len(errors)} of {len(wanted)} DNS queries could not be completed",
            summary="Some record types could not be checked, so this source's result is partial. The findings above "
                    "only cover the record types that answered.",
            evidence=[Evidence(record_type, reason[:160]) for record_type, reason in sorted(errors.items())],
            links=[Evidence("Google DNS view", f"https://dns.google/query?name={domain}&type=A")],
            interpretation="Partial DNS data is not clean data: treat the unchecked record types as 'source unavailable'.",
        ))

    message = (f"DNS answered {len(got)}/{len(wanted)} queries for {domain}"
               + (f"; {len(errors)} could not be completed." if errors else "."))
    return {"status": STATUS_OK, "message": message, "findings": findings, "data": data,
            "upstream_host": "dns.google"}


# ---------------------------------------------------------------------------
# RDAP (domain registration data)
# ---------------------------------------------------------------------------


def _vcard_fields(entity: dict[str, Any]) -> dict[str, str]:
    fields: dict[str, str] = {}
    array = entity.get("vcardArray") or []
    rows = array[1] if len(array) > 1 and isinstance(array[1], list) else []
    for row in rows:
        if not isinstance(row, list) or len(row) < 4:
            continue
        key, value = str(row[0]).lower(), row[3]
        if isinstance(value, list):
            value = ", ".join(str(v) for v in value)
        if isinstance(value, str) and value.strip():
            fields[key] = value.strip()
    return fields


def _event_date(events: list[dict[str, Any]], *actions: str) -> str | None:
    """RDAP events use ``eventAction`` + ``eventDate`` (verified against Verisign)."""
    wanted = {a.lower().replace("_", " ") for a in actions}
    for event in events or []:
        action = str(event.get("eventAction", "")).lower().replace("_", " ")
        if action in wanted:
            date = event.get("eventDate") or event.get("eventDateUtc")
            return parse_upstream_timestamp(date)
    return None


def _parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


@source(
    id="rdap",
    name="RDAP registration data",
    category="registry",
    applies_to=("domain", "email"),
    sends="The domain name only.",
    docs="https://about.rdap.org/",
    description="Registration data (registrar, created/updated/expires, status codes, nameservers) from the registry's RDAP server.",
)
def rdap(ctx: SourceContext) -> dict[str, Any]:
    ident = ctx.identifier
    domain = ident.value if ident.kind == "domain" else ident.meta.get("domain", "")
    if not domain:
        raise SourceOutcome(STATUS_NO_MATCH, "No domain to look up.")

    url = f"{RDAP_BOOTSTRAP}{domain}"
    try:
        response = ctx.fetcher.request_with_retry(
            url,
            headers={"Accept": "application/rdap+json, application/json"},
            timeout=SETTINGS.limits.per_source_timeout,
            bootstrap_redirect=True,
            cache_key=f"rdap:{domain}",
            cache_ttl=SETTINGS.limits.cache_default_ttl,
        )
    except UpstreamHTTPError as exc:
        if exc.status == 404:
            raise SourceOutcome(
                STATUS_NO_MATCH,
                f"No RDAP registration record was returned for {domain} (HTTP 404). "
                "The domain may be unregistered, or its registry may not publish RDAP.",
                data={"domain": domain, "http_status": 404},
            ) from exc
        raise
    if response.status >= 400:
        raise SourceOutcome(
            STATUS_UNAVAILABLE, f"RDAP server returned HTTP {response.status} for {domain}.",
            data={"http_status": response.status},
        )
    payload = response.json()
    if not isinstance(payload, dict):
        raise SourceOutcome(STATUS_UNAVAILABLE, "RDAP response was not a JSON object.")

    events = payload.get("events") or []
    registered_at = _event_date(events, "registration", "registered")
    expires_at = _event_date(events, "expiration", "expires", "expiry")
    changed_at = _event_date(events, "last changed", "last update of registration data")
    statuses = [str(s) for s in (payload.get("status") or [])]
    nameservers = sorted(
        str(ns.get("ldhName", "")).lower() for ns in (payload.get("nameservers") or []) if ns.get("ldhName")
    )
    registrar = ""
    registrar_iana = ""
    abuse_email = ""
    abuse_phone = ""
    for entity in payload.get("entities") or []:
        roles = [str(r).lower() for r in (entity.get("roles") or [])]
        fields = _vcard_fields(entity)
        if "registrar" in roles:
            registrar = fields.get("fn", "") or registrar
            for public_id in entity.get("publicIds") or []:
                if str(public_id.get("type", "")).lower().startswith("iana"):
                    registrar_iana = str(public_id.get("identifier", ""))
        for sub in entity.get("entities") or []:
            sub_roles = [str(r).lower() for r in (sub.get("roles") or [])]
            if "abuse" in sub_roles:
                sub_fields = _vcard_fields(sub)
                abuse_email = sub_fields.get("email", "") or abuse_email
                abuse_phone = sub_fields.get("tel", "") or abuse_phone
        if not registrar:
            registrar = fields.get("fn", "") or registrar

    secure_dns = payload.get("secureDNS") or {}
    delegation_signed = bool(secure_dns.get("delegationSigned"))
    final_host = ""
    try:
        from urllib.parse import urlsplit

        final_host = urlsplit(response.final_url).hostname or ""
    except Exception:  # pragma: no cover - defensive
        final_host = ""

    data = {
        "domain": (payload.get("ldhName") or domain).lower(),
        "registrar": registrar,
        "registrar_iana_id": registrar_iana,
        "registered_at": registered_at,
        "expires_at": expires_at,
        "changed_at": changed_at,
        "statuses": statuses,
        "nameservers": nameservers,
        "dnssec_delegation_signed": delegation_signed,
        "abuse_email": abuse_email,
        "abuse_phone": abuse_phone,
        "rdap_server": final_host,
        "handle": payload.get("handle", ""),
        "rdap_url": url,
    }

    findings: list[Finding] = []
    src, src_name = "rdap", "RDAP registration data"
    now = datetime.now(timezone.utc)

    evidence = [Evidence("Domain", data["domain"])]
    if registrar:
        evidence.append(Evidence("Registrar", registrar + (f" (IANA ID {registrar_iana})" if registrar_iana else "")))
    if registered_at:
        evidence.append(Evidence("Registered", registered_at))
    if expires_at:
        evidence.append(Evidence("Expires", expires_at))
    if changed_at:
        evidence.append(Evidence("Last changed", changed_at))
    if statuses:
        evidence.append(Evidence("Registry status codes", ", ".join(statuses[:8])))
    if nameservers:
        evidence.append(Evidence("Nameservers", ", ".join(nameservers[:8])))
    if abuse_email or abuse_phone:
        evidence.append(Evidence("Registrar abuse contact", abuse_email or abuse_phone))
    links = [Evidence("RDAP record", f"https://rdap.org/domain/{domain}")]

    findings.append(Finding(
        source_id=src, source_name=src_name, severity="info", category="registry",
        title="Domain registration record found",
        summary=f"{data['domain']} is registered"
                + (f" through {registrar}." if registrar else "."),
        evidence=evidence, links=links, observed_at=registered_at,
        interpretation="Registration data is public by ICANN policy. Since 2018 most personal registrant details are redacted, "
                       "so a registrar name is not the owner's name.",
    ))

    registered_dt = _parse_iso(registered_at)
    expires_dt = _parse_iso(expires_at)

    if registered_dt:
        age_days = (now - registered_dt).days
        data["age_days"] = age_days
        if age_days <= 90:
            findings.append(Finding(
                source_id=src, source_name=src_name, severity="medium", category="registry",
                title=f"Recently registered domain ({age_days} days old)",
                summary=f"Registration date is {registered_at}. New domains are common in phishing and scam campaigns, "
                        "although most new domains are entirely legitimate.",
                evidence=[Evidence("Registered", registered_at), Evidence("Age", f"{age_days} days")],
                links=links, observed_at=registered_at,
                interpretation="Age alone is not a verdict: it is one weak signal that should be weighed against other evidence.",
            ))
        else:
            findings.append(Finding(
                source_id=src, source_name=src_name, severity="info", category="registry",
                title=f"Long-standing domain (registered {age_days // 365}+ years ago)",
                summary=f"Registration date is {registered_at}, which makes this an established name.",
                evidence=[Evidence("Registered", registered_at), Evidence("Age", f"{age_days} days")],
                links=links, observed_at=registered_at,
                interpretation="Old registration dates are frequently abused too (expired domains get re-registered), so this is weak positive evidence only.",
            ))

    if expires_dt:
        # NOTE: expiry comparisons must read "expires_at < now => expired".
        if expires_dt < now:
            days = (now - expires_dt).days
            findings.append(Finding(
                source_id=src, source_name=src_name, severity="medium", category="registry",
                title=f"Registration expired {days} days ago",
                summary=f"The registry reports an expiration date of {expires_at}, which is already in the past. "
                        "The domain may be in a redemption period, dropped, or about to become available.",
                evidence=[Evidence("Expires", expires_at), Evidence("Days past expiry", str(days))],
                links=links, observed_at=expires_at,
                interpretation="An expired registration can be taken over by someone else, so historical records about the old owner may no longer apply.",
            ))
        else:
            days_left = (expires_dt - now).days
            data["expires_in_days"] = days_left
            if days_left <= 30:
                findings.append(Finding(
                    source_id=src, source_name=src_name, severity="low", category="registry",
                    title=f"Registration expires in {days_left} days",
                    summary=f"Expiration date is {expires_at}. If it lapses, the name could be re-registered by someone else.",
                    evidence=[Evidence("Expires", expires_at), Evidence("Days remaining", str(days_left))],
                    links=links, observed_at=expires_at,
                    interpretation="Relevant for domain owners (renewal risk) and for anyone relying on the domain staying under the same control.",
                ))

    if delegation_signed:
        findings.append(Finding(
            source_id=src, source_name=src_name, severity="info", category="registry",
            title="DNSSEC delegation signed at the registry",
            summary="The registry holds a DS record for this domain, so DNSSEC can be validated end-to-end.",
            evidence=[Evidence("DNSSEC", "delegationSigned = true")], links=links,
            interpretation="This is a registry-level fact; it does not mean every record is correctly signed.",
        ))

    lock_states = [s for s in statuses if "prohibited" in s.lower()]
    if lock_states:
        findings.append(Finding(
            source_id=src, source_name=src_name, severity="info", category="registry",
            title="Registry lock / transfer restrictions present",
            summary=f"Status codes: {', '.join(lock_states[:6])}. These are usually set by the registrar to prevent unauthorised transfers.",
            evidence=[Evidence("Status codes", ", ".join(statuses[:8]))], links=links,
            interpretation="Locks reduce hijacking risk; 'clientHold' or 'serverHold' would instead mean the domain is suspended.",
        ))
    if any("hold" in s.lower() for s in statuses):
        findings.append(Finding(
            source_id=src, source_name=src_name, severity="medium", category="registry",
            title="Domain is on hold at the registry",
            summary=f"Status codes include {', '.join(s for s in statuses if 'hold' in s.lower())}, which means the domain is suspended and will not resolve.",
            evidence=[Evidence("Status codes", ", ".join(statuses[:8]))], links=links,
            interpretation="A hold can follow abuse complaints, non-payment or a legal dispute; it is not proof of wrongdoing.",
        ))

    return {
        "status": STATUS_OK,
        "message": f"RDAP record retrieved for {data['domain']}"
                   + (f" from {final_host}." if final_host else "."),
        "findings": findings,
        "data": data,
        "upstream_host": final_host or "rdap.org",
    }


SPF_INCLUDE_RE = re.compile(r"include:([^\s]+)", re.IGNORECASE)
