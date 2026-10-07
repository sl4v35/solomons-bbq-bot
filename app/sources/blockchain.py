"""Public blockchain sources (Bitcoin via public explorers, Ethereum via public JSON-RPC).

Blockchain data is public by design: anyone can see balances and transaction
history.  These sources only read public chain state - they never broadcast
transactions and never touch private keys.
"""

from __future__ import annotations

import json
import urllib.parse
from typing import Any

from ..config import SETTINGS, ethereum_rpc_endpoints
from ..http_client import UpstreamError
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

SATOSHIS = 100_000_000
WEI = 10 ** 18

BTC_EXPLORERS = (
    ("blockstream.info", "https://blockstream.info/api/address/{}"),
    ("mempool.space", "https://mempool.space/api/address/{}"),
)


def _format_sats(sats: int) -> str:
    sign = "-" if sats < 0 else ""
    sats = abs(int(sats))
    return f"{sign}{sats // SATOSHIS}.{sats % SATOSHIS:08d}".rstrip("0").rstrip(".") + " BTC"


def _format_wei(wei: int) -> str:
    sign = "-" if wei < 0 else ""
    wei = abs(int(wei))
    whole, frac = divmod(wei, WEI)
    text = f"{sign}{whole}.{frac:018d}".rstrip("0").rstrip(".")
    return text + " ETH"


@source(
    id="blockstream_btc",
    name="Bitcoin address (Blockstream)",
    category="blockchain",
    applies_to=("bitcoin",),
    sends="The Bitcoin address (public blockchain lookup).",
    # The REST API is documented in the electrs README (the old doc/rest.md is gone).
    docs="https://github.com/Blockstream/electrs",
    description="Transaction count, funded/spent totals and current balance for a mainnet Bitcoin address.",
)
def blockstream_btc(ctx: SourceContext) -> dict[str, Any]:
    address = ctx.identifier.value.strip()
    payload: dict[str, Any] | None = None
    used_host = ""
    errors: list[str] = []
    for host, template in BTC_EXPLORERS:
        url = template.format(urllib.parse.quote(address))
        try:
            payload = ctx.fetcher.get_json(url, timeout=SETTINGS.limits.per_source_timeout,
                                           cache_key=f"btc:{host}:{address}",
                                           cache_ttl=SETTINGS.limits.cache_default_ttl)
            used_host = host
            break
        except UpstreamError as exc:
            errors.append(f"{host}: {exc}")
    if payload is None:
        raise SourceOutcome(
            STATUS_UNAVAILABLE,
            "No public Bitcoin explorer could be reached (" + "; ".join(errors) + ").",
            data={"address": address, "errors": errors},
        )
    if not isinstance(payload, dict) or "chain_stats" not in payload:
        raise SourceOutcome(STATUS_UNAVAILABLE, f"{used_host} returned an unexpected response for this address.",
                            data={"address": address})

    chain = payload.get("chain_stats") or {}
    mempool = payload.get("mempool_stats") or {}
    funded = int(chain.get("funded_txo_sum") or 0)
    spent = int(chain.get("spent_txo_sum") or 0)
    tx_count = int(chain.get("tx_count") or 0)
    balance = funded - spent
    unconfirmed = int(mempool.get("tx_count") or 0)

    data = {
        "address": address, "explorer": used_host, "tx_count": tx_count,
        "funded_sats": funded, "spent_sats": spent, "balance_sats": balance,
        "balance_btc": _format_sats(balance), "mempool_tx_count": unconfirmed,
        "address_kind": ctx.identifier.meta.get("address_kind", ""),
        "explorer_url": f"https://{used_host}/address/{address}",
        "errors": errors,
    }

    links = [Evidence(f"{used_host} explorer", data["explorer_url"]),
             Evidence("mempool.space view", f"https://mempool.space/address/{address}"),
             Evidence("Blockchair view", f"https://blockchair.com/bitcoin/address/{address}")]

    if tx_count == 0 and unconfirmed == 0:
        return {
            "status": STATUS_NO_MATCH,
            "message": f"{address} has never appeared in a confirmed Bitcoin transaction (balance 0 BTC).",
            "findings": [Finding(
                source_id="blockstream_btc", source_name="Bitcoin address (Blockstream)", severity="info",
                category="blockchain",
                title="Address has no on-chain history",
                summary="The address is valid but has never received or sent bitcoin on mainnet. It may be unused, "
                        "newly generated, mistyped, or used on another chain.",
                evidence=[Evidence("Address", address), Evidence("Confirmed transactions", "0"),
                          Evidence("Balance", "0 BTC")],
                links=links,
                interpretation="An unused address says nothing about its owner. Blockchain data is public and permanent, "
                               "so a used address cannot be 'cleaned up' - there is no removal process for ledger entries.",
            )],
            "data": data, "upstream_host": used_host,
        }

    evidence = [
        Evidence("Address", address),
        Evidence("Address type", data["address_kind"] or "unknown"),
        Evidence("Confirmed transactions", str(tx_count)),
        Evidence("Total received", _format_sats(funded)),
        Evidence("Total spent", _format_sats(spent)),
        Evidence("Current balance", _format_sats(balance)),
        Evidence("Unconfirmed transactions", str(unconfirmed)),
    ]
    severity = "high" if balance > 0 else "medium"
    findings = [Finding(
        source_id="blockstream_btc", source_name="Bitcoin address (Blockstream)", severity=severity,
        category="blockchain",
        title=f"Bitcoin address has public activity ({tx_count} transaction(s), balance {_format_sats(balance)})",
        summary=f"The full history of {address} is public on the blockchain: {_format_sats(funded)} received, "
                f"{_format_sats(spent)} spent, {_format_sats(balance)} currently held.",
        evidence=evidence, links=links,
        interpretation="Balance and history are visible to anyone, forever. This identifies an address, not a person - "
                       "addresses are frequently exchange wallets, custodians or mixers. There is no removal or "
                       "deletion process for blockchain data.",
    )]
    if balance > 0:
        findings.append(Finding(
            source_id="blockstream_btc", source_name="Bitcoin address (Blockstream)", severity="medium",
            category="blockchain",
            title="Address currently holds funds",
            summary=f"{_format_sats(balance)} is held at this address right now, which is visible to anyone who has it.",
            evidence=[Evidence("Balance", _format_sats(balance))], links=links,
            interpretation="Publishing an address (for donations, invoices, profiles) makes the balance permanently public.",
        ))
    return {"status": STATUS_OK, "message": f"{tx_count} confirmed transaction(s); balance {_format_sats(balance)}.",
            "findings": findings, "data": data, "upstream_host": used_host}


@source(
    id="ethereum_rpc",
    name="Ethereum address (public JSON-RPC)",
    category="blockchain",
    applies_to=("ethereum",),
    sends="The Ethereum address (public eth_getBalance / eth_getTransactionCount / eth_getCode calls).",
    docs="https://ethereum.org/en/developers/docs/apis/json-rpc/",
    description="Balance, outbound transaction count and contract/EOA status via keyless public JSON-RPC endpoints.",
)
def ethereum_rpc(ctx: SourceContext) -> dict[str, Any]:
    address = ctx.identifier.value
    endpoints = ethereum_rpc_endpoints()
    results: dict[str, Any] = {}
    used_endpoint = ""
    errors: list[str] = []

    for endpoint in endpoints:
        host = urllib.parse.urlsplit(endpoint).hostname or ""
        local_errors: list[str] = []
        local_results: dict[str, Any] = {}
        ok = True
        for idx, method in enumerate(("eth_getBalance", "eth_getTransactionCount", "eth_getCode")):
            body = {"jsonrpc": "2.0", "id": idx + 1, "method": method, "params": [address, "latest"]}
            try:
                payload = ctx.fetcher.post_json(endpoint, body, timeout=min(10.0, SETTINGS.limits.per_source_timeout))
            except UpstreamError as exc:
                local_errors.append(f"{method}: {exc}")
                ok = False
                break
            if not isinstance(payload, dict):
                local_errors.append(f"{method}: unexpected response")
                ok = False
                break
            if payload.get("error"):
                local_errors.append(f"{method}: {json.dumps(payload['error'])[:160]}")
                ok = False
                break
            local_results[method] = payload.get("result")
        if ok and len(local_results) == 3:
            results = local_results
            used_endpoint = host
            break
        errors.append(f"{host} ({'; '.join(local_errors)})")

    if not results:
        raise SourceOutcome(
            STATUS_UNAVAILABLE,
            "No public Ethereum JSON-RPC endpoint answered. Public endpoints are rate limited and come and go; "
            "tried: " + ", ".join(urllib.parse.urlsplit(e).hostname or e for e in endpoints) + ".",
            data={"address": address, "errors": errors},
        )

    balance_wei = int(str(results.get("eth_getBalance", "0x0")), 16)
    nonce = int(str(results.get("eth_getTransactionCount", "0x0")), 16)
    code = str(results.get("eth_getCode", "0x"))
    is_contract = code not in ("0x", "0x0", "")
    data = {
        "address": address, "rpc_endpoint": used_endpoint, "balance_wei": balance_wei,
        "balance_eth": _format_wei(balance_wei), "outbound_tx_count": nonce,
        "is_contract": is_contract, "code_size_bytes": (len(code) - 2) // 2 if is_contract else 0,
        "explorer_url": f"https://etherscan.io/address/{address}", "errors": errors,
        "checksum_note": (ctx.identifier.notes[0] if ctx.identifier.notes else ""),
    }
    links = [Evidence("Etherscan view", data["explorer_url"]),
             Evidence("Blockscout view", f"https://eth.blockscout.com/address/{address}")]
    evidence = [Evidence("Address", address), Evidence("Balance", data["balance_eth"]),
                Evidence("Transactions sent (nonce)", str(nonce)),
                Evidence("Type", "smart contract" if is_contract else "externally owned account (EOA)"),
                Evidence("RPC endpoint used", used_endpoint)]

    findings: list[Finding] = []
    if is_contract:
        findings.append(Finding(
            source_id="ethereum_rpc", source_name="Ethereum address (public JSON-RPC)", severity="medium",
            category="blockchain",
            title="Address is a deployed smart contract",
            summary=f"eth_getCode returned {data['code_size_bytes']} bytes of bytecode, so this is a contract, "
                    "not a personal wallet.",
            evidence=evidence, links=links,
            interpretation="Do not read contract activity as an individual's behaviour: contracts are often multisigs, "
                           "exchanges, tokens or DAOs controlled by many parties.",
        ))
    if balance_wei > 0 or nonce > 0:
        severity = "high" if balance_wei > 0 else "medium"
        findings.append(Finding(
            source_id="ethereum_rpc", source_name="Ethereum address (public JSON-RPC)", severity=severity,
            category="blockchain",
            title=f"Ethereum address has public activity (balance {data['balance_eth']}, {nonce} outbound tx)",
            summary=f"On mainnet this address holds {data['balance_eth']} and has sent {nonce} transaction(s). "
                    "All of it is visible to anyone.",
            evidence=evidence, links=links,
            interpretation="This is mainnet only - the same address on other EVM chains (Polygon, Arbitrum, BSC, "
                           "Base, ...) is not queried here. On-chain data cannot be deleted or removed.",
        ))
        status = STATUS_OK
        message = f"Balance {data['balance_eth']}, nonce {nonce} via {used_endpoint}."
    else:
        findings.append(Finding(
            source_id="ethereum_rpc", source_name="Ethereum address (public JSON-RPC)", severity="info",
            category="blockchain",
            title="Address has no mainnet activity",
            summary="Zero balance and a zero nonce: this address has never sent a transaction on Ethereum mainnet.",
            evidence=evidence, links=links,
            interpretation="It may still hold tokens or activity on other EVM chains, which this check does not query.",
        ))
        status = STATUS_NO_MATCH
        message = f"No mainnet activity for {address} (balance 0 ETH, nonce 0) via {used_endpoint}."

    return {"status": status, "message": message, "findings": findings, "data": data,
            "upstream_host": used_endpoint}
