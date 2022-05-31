import hypothesis as hyp
import pytest

import block_crypt as bc
from . import strategies


def test_find_potential_ecb_empty():
    assert bc.find_potential_ecb([]) is None


class TestPadPkcs7:
    def test_example(self):
        assert bc.pad_pkcs_7(b'blabla', 8) == b'blabla\x02\x02'

    def test_rest_0(self):
        assert \
            bc.pad_pkcs_7(b'YELLOW SUBMARINE', 16) == \
            b'YELLOW SUBMARINE' + \
            b'\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10'

    @hyp.given(
        blob=strategies.binary(),
        blocksize=strategies.integers(min_value=1, max_value=255)
    )
    def test_roundtrip(self, blob, blocksize):
        padded = bc.pad_pkcs_7(blob, blocksize)
        assert (len(padded) % blocksize) == 0
        stripped = bc.strip_pkcs_7(padded)
        assert blob == stripped

    @hyp.given(
        args=strategies.non_pkcs7_padded_blocksize_and_blob()
    )
    def test_invalid_exception(self, args):
        with pytest.raises(bc.InvalidPaddingError):
            bc.strip_pkcs_7(args[1])


@hyp.given(
    key=strategies.binary(min_size=16, max_size=16),
    plaintext=strategies.binary()
)
def test_ecb_roundtrip(key, plaintext):
    encrypted = bc.ecb_encrypt(key, plaintext)
    decrypted = bc.ecb_decrypt(key, encrypted)
    assert decrypted == plaintext


@hyp.given(
    key=strategies.binary(min_size=16, max_size=16),
    iv=strategies.binary(min_size=16, max_size=16),
    plaintext=strategies.binary()
)
def test_cbc_roundtrip(key, iv, plaintext):
    encrypted = bc.cbc_encrypt(key, iv, plaintext)
    decrypted = bc.cbc_decrypt(key, iv, encrypted)
    assert plaintext == decrypted
