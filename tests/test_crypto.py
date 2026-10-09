"""Unit tests for the local crypto helpers, checked against published vectors."""

from __future__ import annotations

import unittest

from stubs import *  # noqa: F401,F403

from app.crypto import (
    base58check_valid,
    bech32_decode,
    bitcoin_address_kind,
    ethereum_address_checksum,
    ethereum_address_status,
    keccak256,
    md5_hex,
    sha1_hex,
)


class KeccakTests(unittest.TestCase):
    def test_known_vectors(self):
        # Keccak-256 (original padding), not NIST SHA3-256.
        self.assertEqual(keccak256(b"").hex(),
                         "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
        self.assertEqual(keccak256(b"abc").hex(),
                         "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45")
        self.assertEqual(keccak256(b"hello").hex(),
                         "1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8")

    def test_differs_from_sha3(self):
        import hashlib

        self.assertNotEqual(keccak256(b"abc").hex(), hashlib.sha3_256(b"abc").hexdigest())


class Eip55Tests(unittest.TestCase):
    def test_reference_addresses(self):
        for address in (
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
            "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
            "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
            "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
        ):
            self.assertEqual(ethereum_address_checksum(address), address)
            self.assertEqual(ethereum_address_status(address), "valid-checksum")

    def test_all_lowercase_is_valid_without_checksum(self):
        self.assertEqual(ethereum_address_status("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed"),
                         "valid-no-checksum")

    def test_broken_checksum_is_invalid(self):
        self.assertEqual(ethereum_address_status("0x5AAEB6053F3E94C9b9A09f33669435E7Ef1BeAed"), "invalid")

    def test_wrong_length_or_charset(self):
        self.assertEqual(ethereum_address_status("0x1234"), "invalid")
        self.assertEqual(ethereum_address_status("0xzz" + "a" * 38), "invalid")


class Bech32Tests(unittest.TestCase):
    def test_bip350_bech32m_vectors(self):
        for value in ("A1LQFN3A", "a1lqfn3a",
                      "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx",
                      "split1checkupstagehandshakeupstreamerranterredcaperredlc445v",
                      "?1v759aa"):
            decoded = bech32_decode(value)
            self.assertIsNotNone(decoded, value)
            self.assertEqual(decoded[2], "bech32m", value)

    def test_bip173_bech32_vectors(self):
        # Verbatim from BIP-173's "valid Bech32" test vectors.
        for value in ("A12UEL5L", "a12uel5l",
                      "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs",
                      "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
                      "11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j",
                      "split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w",
                      "?1ezyfcl"):
            decoded = bech32_decode(value)
            self.assertIsNotNone(decoded, value)
            self.assertEqual(decoded[2], "bech32", value)

    def test_bip173_invalid_vectors(self):
        # Verbatim from BIP-173's "not valid Bech32" list.
        for value in ("pzry9x0s0muk",  # no separator
                      "1pzry9x0s0muk",  # empty HRP
                      "x1b4n0q5v",  # invalid data character
                      "li1dgmt3",  # too short checksum
                      "A1G7SGD8",  # checksum over uppercase HRP
                      "10a06t8", "1qzzfhee",  # empty HRP
                      "an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx"):
            self.assertIsNone(bech32_decode(value), value)

    def test_invalid_strings(self):
        for value in ("", "pzry9x0s0muk", "1pzry9x0s0muk", "x1b4n0q5v", "li1dgmt3", "A1G7SGD8",
                      "11llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllludsr8"):
            self.assertIsNone(bech32_decode(value), value)

    def test_mixed_case_rejected(self):
        self.assertIsNone(bech32_decode("Bc1Qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"))


class BitcoinAddressTests(unittest.TestCase):
    def test_mainnet_addresses(self):
        cases = {
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4": "SegWit v0 (P2WPKH)",
            "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq": "SegWit v0 (P2WPKH)",
            "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr": "SegWit v1 (Taproot / P2TR)",
            "bc1p4qhjn9zdvkux4e44uhx8tc55attvtyu358kutcqkudyccelu0was9fqzwh": "SegWit v1 (Taproot / P2TR)",
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa": "Legacy (P2PKH)",
            "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy": "Legacy (P2SH / wrapped SegWit)",
        }
        for address, expected in cases.items():
            self.assertEqual(bitcoin_address_kind(address), expected, address)

    def test_invalid_addresses(self):
        for address in ("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5",  # bad checksum
                        "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb",  # bad checksum
                        "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7",  # testnet
                        "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
                        "", "not-an-address"):
            self.assertIsNone(bitcoin_address_kind(address), address)

    def test_base58check(self):
        self.assertTrue(base58check_valid("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"))
        self.assertFalse(base58check_valid("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfN0"))
        self.assertFalse(base58check_valid("O0l1"))  # ambiguous characters are not in the alphabet


class HashHelpersTests(unittest.TestCase):
    def test_sha1_uppercase(self):
        self.assertEqual(sha1_hex(b"password"), "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8")

    def test_md5_gravatar_style(self):
        self.assertEqual(md5_hex(b"test@example.com"), "55502f40dc8b7c769880b10874abc9d0")
        # Gravatar lowercases and trims before hashing - the caller must do the same.
        self.assertNotEqual(md5_hex(b" test@example.com "), "55502f40dc8b7c769880b10874abc9d0")


if __name__ == "__main__":
    unittest.main()
