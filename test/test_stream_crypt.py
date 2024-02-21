import hypothesis as hyp

import stream_crypt as sc
from . import strategies


@hyp.given(
    key=strategies.binary(min_size=16, max_size=16),
    nonce=strategies.integers(min_value=0, max_value=2 ** 64 - 1),
    plaintext=strategies.binary()
)
def test_ctr_roundtrip(key, nonce, plaintext):
    encrypted = sc.ctr_transcrypt(key, nonce, plaintext)
    decrypted = sc.ctr_transcrypt(key, nonce, encrypted)
    assert plaintext == decrypted
