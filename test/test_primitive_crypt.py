import hypothesis as hyp
import pytest

import primitive_crypt as pc
from . import strategies


class TestXorBuffers:

    def test_constraints(self):
        with pytest.raises(TypeError):
            pc.xor_buffers("bla", "bla")
        with pytest.raises(TypeError):
            pc.xor_buffers(42, 42)
        with pytest.raises(ValueError):
            pc.xor_buffers([1, 2, 3], [512, 8, 15])

    def test_identical(self):
        assert pc.xor_buffers(b"bla", b"bla") == b"\0\0\0"


class TestAttemptDecode:

    def test_non_bytes(self):
        with pytest.raises(AttributeError):
            pc._attempt_decode(42)
        with pytest.raises(AttributeError):
            pc._attempt_decode("bla")

    def test_decode(self):
        assert "bla" == pc._attempt_decode(b"bla")

    def test_undecodable(self):
        not_utf8 = b"\xf0\xf0"
        assert pc._attempt_decode(not_utf8) is None


def test_rate_keysize():
    assert pc._rate_repeating_xor_keysize(b"blabla", 3) == 0
    assert pc._rate_repeating_xor_keysize(b"blabla", 2) != 0


class TestTransposeBlock:
    def test_example(self):
        assert pc._transpose_blocks([b"bla", b"blo", b"bli"]) == \
               [b"bbb", b"lll", b"aoi"]

    def test_remainder(self):
        assert pc._transpose_blocks([b"bla", b"blo", b"bl"]) == \
               [b"bbb", b"lll", b"ao"]

    @hyp.given(strategies.binary_and_possible_blocksize())
    def test_round_trip(self, args):
        blob = args[0]
        block_size = args[1]
        split = pc.brake_into_keysize_blocks(blob, block_size)
        transpose1 = pc._transpose_blocks(split)
        transpose2 = pc._transpose_blocks(transpose1)
        assert transpose2 == split
        assert b"".join(transpose2) == blob


def test_guess_xor_key_forgiven_size():
    plaintext = "When in danger or in doubt, run in cricles, scream, " \
                "and shout!".encode()
    key = b"bla"
    ciphertext = pc.xor_buffers(plaintext, key)
    guessed_key = pc._guess_xor_key_for_given_size(ciphertext, len(key))
    assert guessed_key == key
