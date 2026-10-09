"""Minimal, dependency-free crypto helpers used for local identifier checks.

* :func:`keccak256` -- the *original* Keccak-256 (not NIST SHA3-256) needed for
  Ethereum EIP-55 address checksum validation.
* :func:`sha256` / :func:`sha1` / :func:`md5` -- thin wrappers.
* :func:`base58check_valid` -- Bitcoin legacy (1.../3...) address checksum.
* :func:`bech32_decode` -- Bitcoin SegWit (bc1...) address validation.

Only public data is ever processed here; nothing in this module sends anything
over the network.
"""

from __future__ import annotations

import hashlib

# ---------------------------------------------------------------------------
# Keccak-256 (pre-NIST padding, as used by Ethereum)
# ---------------------------------------------------------------------------

_KECCAK_ROUND_CONSTANTS = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]

_ROTATION_OFFSETS = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
]

_MASK64 = (1 << 64) - 1


def _rotl64(value: int, shift: int) -> int:
    shift %= 64
    return ((value << shift) | (value >> (64 - shift))) & _MASK64


def _keccak_f1600(state: list[list[int]]) -> None:
    for round_constant in _KECCAK_ROUND_CONSTANTS:
        # theta
        c = [state[x][0] ^ state[x][1] ^ state[x][2] ^ state[x][3] ^ state[x][4] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rotl64(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                state[x][y] ^= d[x]
        # rho and pi
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                b[y][(2 * x + 3 * y) % 5] = _rotl64(state[x][y], _ROTATION_OFFSETS[x][y])
        # chi
        for x in range(5):
            for y in range(5):
                state[x][y] = b[x][y] ^ ((~b[(x + 1) % 5][y] & _MASK64) & b[(x + 2) % 5][y])
        # iota
        state[0][0] ^= round_constant


def keccak256(data: bytes) -> bytes:
    """Return the Keccak-256 digest of ``data`` (Ethereum's hash function)."""
    rate = 136  # (1600 - 2*256) / 8
    state = [[0] * 5 for _ in range(5)]
    padded = bytearray(data)
    padded.append(0x01)  # Keccak padding (NOT SHA3's 0x06)
    while len(padded) % rate != 0:
        padded.append(0x00)
    padded[-1] |= 0x80

    for offset in range(0, len(padded), rate):
        block = padded[offset:offset + rate]
        for i in range(rate // 8):
            lane = int.from_bytes(block[i * 8:(i + 1) * 8], "little")
            state[i % 5][i // 5] ^= lane
        _keccak_f1600(state)

    out = bytearray()
    for i in range(4):  # 256 bits / 64
        out += state[i % 5][i // 5].to_bytes(8, "little")
    return bytes(out)


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def sha1_hex(data: bytes) -> str:
    return hashlib.sha1(data).hexdigest().upper()


def md5_hex(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


# ---------------------------------------------------------------------------
# Bitcoin address validation
# ---------------------------------------------------------------------------

_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def base58check_valid(address: str) -> bool:
    """Validate a legacy Base58Check Bitcoin address (P2PKH / P2SH)."""
    if not address or any(ch not in _B58_ALPHABET for ch in address):
        return False
    if not 25 <= len(address) <= 34:
        return False
    num = 0
    for ch in address:
        num = num * 58 + _B58_ALPHABET.index(ch)
    raw = num.to_bytes(25, "big")
    payload, checksum = raw[:-4], raw[-4:]
    if sha256(sha256(payload))[:4] != checksum:
        return False
    version = payload[0]
    return version in (0x00, 0x05)  # mainnet P2PKH / P2SH


_BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_BECH32_CONST = 1
_BECH32M_CONST = 0x2BC830A3


def _bech32_polymod(values: list[int]) -> int:
    generator = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for value in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ value
        for i in range(5):
            chk ^= generator[i] if ((top >> i) & 1) else 0
    return chk


def _bech32_hrp_expand(hrp: str) -> list[int]:
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def _convert_bits(data: list[int], from_bits: int, to_bits: int, pad: bool = True) -> list[int] | None:
    acc = 0
    bits = 0
    ret: list[int] = []
    max_v = (1 << to_bits) - 1
    for value in data:
        if value < 0 or (value >> from_bits):
            return None
        acc = (acc << from_bits) | value
        bits += from_bits
        while bits >= to_bits:
            bits -= to_bits
            ret.append((acc >> bits) & max_v)
    if pad:
        if bits:
            ret.append((acc << (to_bits - bits)) & max_v)
    elif bits >= from_bits or ((acc << (to_bits - bits)) & max_v):
        return None
    return ret


def bech32_decode(address: str) -> tuple[str, list[int], str] | None:
    """Decode a Bech32/Bech32m string.

    Returns ``(hrp, data_without_checksum, spec)`` where spec is ``"bech32"``
    or ``"bech32m"``, or ``None`` when the string is not valid.
    """
    if not address or len(address) > 90:
        return None
    if address != address.lower() and address != address.upper():
        return None  # mixed case is invalid
    lowered = address.lower()
    if "1" not in lowered:
        return None
    hrp, _, data_part = lowered.rpartition("1")
    if len(hrp) < 1 or len(hrp) > 83 or len(data_part) < 6:
        return None
    if any(ord(ch) < 33 or ord(ch) > 126 for ch in hrp):
        return None
    try:
        data = [_BECH32_CHARSET.index(ch) for ch in data_part]
    except ValueError:
        return None
    polymod = _bech32_polymod(_bech32_hrp_expand(hrp) + data)
    if polymod == _BECH32_CONST:
        spec = "bech32"
    elif polymod == _BECH32M_CONST:
        spec = "bech32m"
    else:
        return None
    return hrp, data[:-6], spec


def bitcoin_address_kind(address: str) -> str | None:
    """Return a human label for a valid mainnet Bitcoin address, else ``None``."""
    candidate = address.strip()
    if candidate.lower().startswith("bc1"):
        decoded = bech32_decode(candidate)
        if not decoded:
            return None
        hrp, data, spec = decoded
        if hrp != "bc" or not data:
            return None  # testnet/regtest or empty
        witness_version = data[0]
        if witness_version > 16:
            return None
        # BIP-141/BIP-350: v0 uses bech32, v1+ uses bech32m.
        if witness_version == 0 and spec != "bech32":
            return None
        if witness_version >= 1 and spec != "bech32m":
            return None
        program = _convert_bits(data[1:], 5, 8, False)
        if program is None or not 2 <= len(program) <= 40:
            return None
        if witness_version == 0 and len(program) not in (20, 32):
            return None
        if witness_version == 0:
            return "SegWit v0 (P2WPKH)" if len(program) == 20 else "SegWit v0 (P2WSH)"
        if witness_version == 1 and len(program) == 32:
            return "SegWit v1 (Taproot / P2TR)"
        return f"SegWit v{witness_version}"
    if candidate[:1] in ("1", "3") and base58check_valid(candidate):
        return "Legacy (P2PKH)" if candidate[0] == "1" else "Legacy (P2SH / wrapped SegWit)"
    return None


# ---------------------------------------------------------------------------
# Ethereum address validation (EIP-55 mixed-case checksum)
# ---------------------------------------------------------------------------


def ethereum_address_checksum(address: str) -> str | None:
    """Return the EIP-55 checksummed form of a 0x address, or ``None``."""
    if not address.startswith("0x") or len(address) != 42:
        return None
    body = address[2:].lower()
    if any(ch not in "0123456789abcdef" for ch in body):
        return None
    digest = keccak256(body.encode("ascii")).hex()
    out = []
    for i, ch in enumerate(body):
        if ch.isdigit():
            out.append(ch)
        else:
            out.append(ch.upper() if int(digest[i], 16) >= 8 else ch)
    return "0x" + "".join(out)


def ethereum_address_status(address: str) -> str:
    """``valid-checksum``, ``valid-no-checksum`` (all lower/upper) or ``invalid``."""
    checksummed = ethereum_address_checksum(address)
    if checksummed is None:
        return "invalid"
    body = address[2:]
    if body == body.lower() or body == body.upper():
        return "valid-no-checksum"
    return "valid-checksum" if body == checksummed[2:] else "invalid"
