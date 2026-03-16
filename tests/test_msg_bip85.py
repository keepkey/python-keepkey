# BIP-85 child mnemonic derivation tests.
#
# Tests GetBip85Mnemonic message which derives deterministic child
# mnemonics from the device seed per the BIP-85 specification.
#
# Uses the "all" x12 mnemonic as the master seed.

import unittest
import common

import keepkeylib.messages_pb2 as proto

# BIP-39 English wordlist (2048 words)
# We load it inline to avoid external file dependencies.
BIP39_WORDLIST = None

def _load_bip39_wordlist():
    """Load BIP-39 English wordlist from mnemonic package or fallback."""
    global BIP39_WORDLIST
    if BIP39_WORDLIST is not None:
        return BIP39_WORDLIST

    # Try the mnemonic package first (ships with python-keepkey deps)
    try:
        from mnemonic import Mnemonic
        m = Mnemonic("english")
        BIP39_WORDLIST = m.wordlist
        return BIP39_WORDLIST
    except ImportError:
        pass

    # Fallback: accept any lowercase alpha words and skip strict validation
    BIP39_WORDLIST = None
    return None


def _validate_mnemonic_words(mnemonic_str):
    """Validate that each word in the mnemonic is in the BIP-39 wordlist.

    Returns (is_valid, bad_words) tuple. If wordlist unavailable, returns
    (True, []) -- we still validate word count and format elsewhere.
    """
    wordlist = _load_bip39_wordlist()
    words = mnemonic_str.split()
    if wordlist is None:
        # No wordlist available; just check words are lowercase alpha
        bad = [w for w in words if not w.isalpha() or not w.islower()]
        return (len(bad) == 0, bad)
    bad = [w for w in words if w not in wordlist]
    return (len(bad) == 0, bad)


class TestMsgBip85(common.KeepKeyTest):
    """Test BIP-85 child mnemonic derivation from the device."""

    def test_bip85_12word(self):
        """Derive a 12-word child mnemonic at index 0."""
        self.requires_firmware("7.14.0")
        self.setup_mnemonic_allallall()

        resp = self.client.call(proto.GetBip85Mnemonic(word_count=12, index=0))

        # Response must be a Bip85Mnemonic message
        self.assertTrue(
            isinstance(resp, proto.Bip85Mnemonic),
            "Expected Bip85Mnemonic response, got %s" % type(resp).__name__
        )

        mnemonic = resp.mnemonic
        words = mnemonic.split()

        # Must have exactly 12 words
        self.assertTrue(
            len(words) == 12,
            "Expected 12 words, got %d: %s" % (len(words), mnemonic)
        )

        # Each word must be a valid BIP-39 word
        is_valid, bad_words = _validate_mnemonic_words(mnemonic)
        self.assertTrue(
            is_valid,
            "Invalid BIP-39 words found: %s" % bad_words
        )

    def test_bip85_24word(self):
        """Derive a 24-word child mnemonic at index 0."""
        self.requires_firmware("7.14.0")
        self.setup_mnemonic_allallall()

        resp = self.client.call(proto.GetBip85Mnemonic(word_count=24, index=0))

        self.assertTrue(
            isinstance(resp, proto.Bip85Mnemonic),
            "Expected Bip85Mnemonic response, got %s" % type(resp).__name__
        )

        mnemonic = resp.mnemonic
        words = mnemonic.split()

        # Must have exactly 24 words
        self.assertTrue(
            len(words) == 24,
            "Expected 24 words, got %d: %s" % (len(words), mnemonic)
        )

        # Each word must be a valid BIP-39 word
        is_valid, bad_words = _validate_mnemonic_words(mnemonic)
        self.assertTrue(
            is_valid,
            "Invalid BIP-39 words found: %s" % bad_words
        )

    def test_bip85_different_indices(self):
        """Index 0 and index 1 must produce different child mnemonics."""
        self.requires_firmware("7.14.0")
        self.setup_mnemonic_allallall()

        resp0 = self.client.call(proto.GetBip85Mnemonic(word_count=12, index=0))
        resp1 = self.client.call(proto.GetBip85Mnemonic(word_count=12, index=1))

        self.assertTrue(
            isinstance(resp0, proto.Bip85Mnemonic),
            "Expected Bip85Mnemonic for index 0, got %s" % type(resp0).__name__
        )
        self.assertTrue(
            isinstance(resp1, proto.Bip85Mnemonic),
            "Expected Bip85Mnemonic for index 1, got %s" % type(resp1).__name__
        )

        # Different indices must yield different mnemonics
        self.assertTrue(
            resp0.mnemonic != resp1.mnemonic,
            "Index 0 and index 1 produced identical mnemonics: %s" % resp0.mnemonic
        )

    def test_bip85_deterministic(self):
        """Same parameters must produce the same child mnemonic every time."""
        self.requires_firmware("7.14.0")
        self.setup_mnemonic_allallall()

        resp1 = self.client.call(proto.GetBip85Mnemonic(word_count=12, index=0))
        resp2 = self.client.call(proto.GetBip85Mnemonic(word_count=12, index=0))

        self.assertTrue(
            isinstance(resp1, proto.Bip85Mnemonic),
            "Expected Bip85Mnemonic (call 1), got %s" % type(resp1).__name__
        )
        self.assertTrue(
            isinstance(resp2, proto.Bip85Mnemonic),
            "Expected Bip85Mnemonic (call 2), got %s" % type(resp2).__name__
        )

        self.assertTrue(
            resp1.mnemonic == resp2.mnemonic,
            "Determinism violated: '%s' != '%s'" % (resp1.mnemonic, resp2.mnemonic)
        )


if __name__ == '__main__':
    unittest.main()
