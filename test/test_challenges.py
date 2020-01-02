import base64

import pytest
from Crypto.Cipher import AES

import bitfiddle as bf
import block_crypt as bc
import challenge_specific as cs
import primitive_crypt as pc
import util


class TestChallenge1:

    @pytest.fixture(autouse=True)
    def set_up(self):
        self.hex_ = util.bytes_from_file("inputs/1_hexexample.txt").decode()
        self.b64 = util.bytes_from_file("inputs/1_base64result.txt")

    def test_hex_to_base64(self):
        assert self.b64 == base64.b64encode(bytes.fromhex(self.hex_))

    def test_base64_to_hex(self):
        assert base64.b64decode(self.b64).hex() == self.hex_


def test_challenge2():
    input1 = bytes.fromhex(util.string_from_file("inputs/2_input1.txt"))
    input2 = bytes.fromhex(util.string_from_file("inputs/2_input2.txt"))
    result = bytes.fromhex(util.string_from_file("inputs/2_result.txt"))
    assert pc.xor_buffers(input1, input2) == result


def test_challenge3():
    encrypted = bytes.fromhex(util.string_from_file("inputs/3_input.txt"))
    solution = util.bytes_from_file("inputs/3_solution.txt")
    decrypted = pc.break_single_byte_xor(encrypted)[1]
    assert decrypted == solution


def test_challenge4():
    with open("inputs/4_input.txt", "r") as file:
        haystack = list(bytes.fromhex(line.strip()) for line in
                        file.readlines())
    solution = util.bytes_from_file("inputs/4_solution.txt")
    needle = pc.find_single_byte_xor(haystack)[1]
    assert solution == needle


def test_challenge5():
    input_ = util.bytes_from_file("inputs/5_input.txt")
    solution = util.string_from_file("inputs/5_encrypted.txt").replace("\n",
                                                                       "")
    encrypted = pc.xor_buffers(input_, b"ICE").hex()
    assert solution == encrypted


class TestChallenge6:

    def test_hamming_distance(self):
        assert bf.hamming_distance(b"this is a test", b"wokka wokka!!!") == 37

    @pytest.mark.slow
    def test_decrypt(self):
        encrypted_b64 = util.string_from_file("inputs/6_input.txt")
        encrypted = base64.b64decode(encrypted_b64)
        key, decryption = pc.break_repeating_key_xor(encrypted, 40)
        solution = util.bytes_from_file("inputs/6_solution.txt")
        assert decryption == solution


def test_challenge7():
    encrypted = base64.b64decode(util.bytes_from_file("inputs/7_input.txt"))
    key = b"YELLOW SUBMARINE"
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted = cipher.decrypt(encrypted)
    solution = util.bytes_from_file("inputs/7_solution.dat")
    assert decrypted == solution


def test_challenge8():
    lines = util.lines_from_file("inputs/8_input.txt")
    blobs = [bytes.fromhex(line.rstrip('\n')) for line in lines]
    ecb_blob = bc.find_potential_ecb(blobs)
    solution_str = util.string_from_file("inputs/8_solution.txt").rstrip('\n')
    solution = bytes.fromhex(solution_str)
    assert ecb_blob == solution


def test_challenge9():
    assert \
        bc.pad_pkcs_7(b'YELLOW SUBMARINE', 20) == \
        b'YELLOW SUBMARINE\x04\x04\x04\x04'


def test_challenge10():
    ciphertext = base64.b64decode(util.bytes_from_file("inputs/10_input.txt"))
    plaintext = bc.cbc_decrypt(b'YELLOW SUBMARINE', bytes(16), ciphertext)
    solution = util.bytes_from_file("inputs/10_solution.txt")
    assert plaintext == solution


def test_challenge11():
    for ii in range(100):
        true_mode, detected_mode = cs.challenge_11_test()
        assert true_mode == detected_mode


class TestChallenge12:
    @pytest.fixture(autouse=True)
    def set_up(self):
        self.solver = cs.Challenge12Solver()

    def test_blocksize(self):
        assert self.solver.blocksize == 16

    def test_is_ecb(self):
        assert self.solver.is_ecb()

    def test_solve(self):
        correct_input = base64.b64decode(
            util.bytes_from_file('inputs/12_input.txt'))
        solved = self.solver.solve()
        assert solved == correct_input


class TestChallenge13:
    def test_transcode(self):
        encoded_profile = cs.challenge_13_profile_for('bla@bla.bla')
        assert not cs.challenge_13_is_admin(encoded_profile)

    def test_escape(self):
        encoded_profile = cs.challenge_13_profile_for('bla@bla.bla&role=admin')
        assert not cs.challenge_13_is_admin(encoded_profile)

    def test_forge(self):
        assert cs.challenge_13_is_admin(cs.challenge_13_forge())
