import base64
import secrets

from block_crypt import cbc_encrypt, \
    ecb_encrypt, \
    detect_potential_repeating_ecb_blocks, \
    strip_pkcs_7
from util import bytes_from_file
from util import random_blob


def challenge_11_oracle(input_blob):
    key = secrets.token_bytes(16)
    mode = secrets.choice(['ECB', 'CBC'])
    prefix = random_blob(5, 10)
    postfix = random_blob(5, 10)
    plaintext = prefix + input_blob + postfix
    if mode == 'ECB':
        return ecb_encrypt(key, plaintext), mode
    iv = secrets.token_bytes(16)
    return cbc_encrypt(key, iv, plaintext), mode


def challenge_11_test():
    input_blob = bytes([0] * 43)
    ciphertext, true_mode = challenge_11_oracle(input_blob)
    if detect_potential_repeating_ecb_blocks(ciphertext):
        detected_mode = 'ECB'
    else:
        detected_mode = 'CBC'
    return true_mode, detected_mode


class Challenge12Oracle:
    def __init__(self):
        self._key = secrets.token_bytes(16)
        self._suffix = base64.b64decode(bytes_from_file('inputs/12_input.txt'))

    def __call__(self, input_blob):
        return ecb_encrypt(self._key, input_blob + self._suffix)


class Challenge12Solver:

    def __init__(self):
        self.oracle = Challenge12Oracle()
        self.known_bytes = b''
        self.blocksize = self._find_blocksize()
        self._init_padding_blob_accessors()

    def _find_blocksize(self):
        # Basic idea:
        # Try increasing number of zeros as prefixes
        # We know we have reached the second block once the first one no
        # longer changes
        previous_first_block = None
        max_possible_blocksize = len(self.oracle(b''))
        for prefix_size in range(1, max_possible_blocksize + 1):
            input_ = bytes([0] * prefix_size)
            output = self.oracle(input_)
            first_block_previous_size = output[:prefix_size - 1]
            if first_block_previous_size == previous_first_block:
                return prefix_size - 1
            else:
                previous_first_block = output[:prefix_size]

    def _init_padding_blob_accessors(self):

        padding_blobs = [bytes([0] * ii) for ii in range(self.blocksize)]

        def next_padding_blob():
            """All zero padding putting next byte in position for decryption"""
            return padding_blobs[self._next_empty_length()]

        self._next_padding_blob = next_padding_blob

        padding_encryptions = [self.oracle(blob) for blob in padding_blobs]

        def oracle_value_for_next_padding_blob():
            return padding_encryptions[self._next_empty_length()]

        self._oracle_value_for_next_padding_blob = \
            oracle_value_for_next_padding_blob

    def _next_empty_length(self):
        """Calculate length of needed all-zero prefix blob for next byte

        The length is chosen to put the first unknown byte of the secret
        suffix into the last byte of an otherwise known plaintext block
        """
        position = len(self.known_bytes)
        return self.blocksize - 1 - (position % self.blocksize)

    def solve(self):
        while True:
            next_byte = self._decrypt_next_byte()
            if next_byte is None:
                break
            self.known_bytes += bytes([next_byte])
        return strip_pkcs_7(self.known_bytes)

    def _decrypt_next_byte(self):
        for byte in range(256):
            if self._test_guessed_byte(byte):
                return byte

    def _test_guessed_byte(self, byte):
        return self._guessed_next_encrypted_prefix(byte) == \
               self._next_desired_encrypted_prefix()

    def _guessed_next_encrypted_prefix(self, guessed_byte):
        input_ = self._make_next_test_plaintext_prefix(guessed_byte)
        encryption = self.oracle(input_)
        return encryption[:self._next_test_prefix_length()]

    def _next_desired_encrypted_prefix(self):
        """Cipertext prefix for correctly guessed next byte"""
        ciphertext = self._oracle_value_for_next_padding_blob()
        length = self._next_test_prefix_length()
        return ciphertext[:length]

    def _make_next_test_plaintext_prefix(self, guessed_byte):
        return self._next_padding_blob() + \
               self.known_bytes + \
               bytes([guessed_byte])

    def _next_test_prefix_length(self):
        position = len(self.known_bytes)
        return self._next_empty_length() + position + 1

    def is_ecb(self):
        prefix = bytes([0] * 2 * self.blocksize)
        return detect_potential_repeating_ecb_blocks(
            prefix, blocksize=self.blocksize)
