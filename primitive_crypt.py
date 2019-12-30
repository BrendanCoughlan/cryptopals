__all__ = [
    "xor_buffers",
    "break_single_byte_xor",
    "find_single_byte_xor"
]

import operator

from bitfiddle import xor_pairs, hamming_distance, byte_from_int, \
    brake_into_keysize_blocks
from english_distance import english_distance
from util import repeating_zip, find_minimal, remove_nones


def xor_buffers(left, right):
    """Xor two bytes-like objects, repeating the shorter as needed"""
    return bytes(xor_pairs(repeating_zip(left, right)))


def _attempt_decode(blob):
    """Decode bytes as utf8 and return string, or None if that is impossible"""
    try:
        return blob.decode()
    except UnicodeDecodeError:
        return None


def break_single_byte_xor(encrypted):
    """
    Brute-force single-byte xor

    :param: encrypted UTF-8 encoded english text encrypted with single
    byte xor using an unknown key byte
    :return: A pair of the key leading to the best decryption based on
    similarity to English and that decryption. None if no decryption
    could be found.
    """

    keys = (byte_from_int(ii) for ii in range(256))

    def add_decryption(key):
        return key, xor_buffers(key, encrypted)

    candidates = (add_decryption(key) for key in keys)

    def score(candidate):
        return english_distance(candidate[1])

    return find_minimal(candidates, score)


def find_single_byte_xor(haystack):
    """
    Find and decrypt single-byte xor ciphertext

    :param haystack: a collection of bytes objects one of which is an
    UTF-8 encoded English text encrypte with single-byte xor using an
    unknown key byte
    :return: The decrypted text most similar to English or none if none
    was found
    """

    candidate_decryptions = (break_single_byte_xor(blob) for blob in
                             haystack)

    def score(decryption):
        return english_distance(decryption[1])

    return find_minimal(candidate_decryptions, score)


def _rate_repeating_xor_keysize(ciphertext, size):
    block1 = ciphertext[:size]
    block2 = ciphertext[size:2 * size]
    return hamming_distance(block1, block2) / size


def _transpose_blocks(blocks):
    num_blocks = len(blocks)
    if num_blocks == 0:
        len_blocks = 1
    else:
        len_blocks = len(blocks[0])

    def get(ii, jj):
        if ii >= len(blocks[jj]):
            return None
        return blocks[jj][ii]

    def create_block(ii):
        return bytes(remove_nones(get(ii, jj) for jj in range(num_blocks)))

    return [create_block(ii) for ii in range(len_blocks)]


def _guess_xor_key_for_given_size(ciphertext, size):
    sections = _transpose_blocks(brake_into_keysize_blocks(ciphertext, size))
    decryptions = [break_single_byte_xor(section) for section in sections]
    key_bytes = (decryption[0] for decryption in decryptions)
    return b"".join(key_bytes)


def break_repeating_key_xor(ciphertext, max_size):
    rated = [(size, _rate_repeating_xor_keysize(ciphertext, size)) for
             size in range(1, max_size)]
    candidate_pairs = sorted(rated, key=operator.itemgetter(1))
    candidates_sizes = [pair[0] for pair in candidate_pairs]
    candidate_keys = [_guess_xor_key_for_given_size(ciphertext, size) for
                      size in candidates_sizes]
    candidate__decryptions = (
        (key, xor_buffers(key, ciphertext)) for key in candidate_keys)

    def score(candidate):
        plaintext = candidate[1]
        return english_distance(plaintext)

    return find_minimal(candidate__decryptions, score)
