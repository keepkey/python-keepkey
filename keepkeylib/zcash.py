"""Zcash helpers for client-side computations.

Mirrors the firmware's ZIP-32 §6.1 seed fingerprint so callers can build the
expected_seed_fingerprint they pass to display/sign messages without having to
ask the device.
"""

from hashlib import blake2b


_PERSONAL = b"Zcash_HD_Seed_FP"


def calculate_seed_fingerprint(seed):
    """Compute the ZIP-32 §6.1 seed fingerprint.

        SeedFingerprint := BLAKE2b-256(
            "Zcash_HD_Seed_FP", I2LEBSP_8(len(seed)) || seed
        )

    The 1-byte length prefix domain-separates seeds of different lengths
    that happen to share a prefix; per the spec.

    Args:
        seed: bytes, length 32-252.

    Returns:
        32-byte fingerprint.

    Raises:
        ValueError: if seed length is out of range or the seed is trivially
            all-zero or all-0xFF (matches firmware's rejection per §6.1).
    """
    if not isinstance(seed, (bytes, bytearray)):
        raise TypeError("seed must be bytes")
    if len(seed) < 32 or len(seed) > 252:
        raise ValueError("seed length must be in [32, 252]")
    if all(b == 0x00 for b in seed) or all(b == 0xFF for b in seed):
        raise ValueError("trivial seed (all-zero or all-0xFF) rejected")

    h = blake2b(digest_size=32, person=_PERSONAL)
    h.update(bytes([len(seed)]))
    h.update(bytes(seed))
    return h.digest()
