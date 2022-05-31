import base64
import secrets

import kvserialize
from bitfiddle import \
    brake_into_keysize_blocks, \
    get_block
from block_crypt import \
    InvalidPaddingError, \
    cbc_encrypt, \
    cbc_encrypt_prepadded, \
    ecb_decrypt, \
    ecb_encrypt, \
    detect_potential_repeating_ecb_blocks, \
    cbc_decrypt, \
    strip_pkcs_7
from primitive_crypt import xor_buffers
from util import bytes_from_file
from util import equal_prefix_length
from util import lines_from_file
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


class Challenge14Oracle:
    def __init__(self, prefix, suffix):
        self._key = secrets.token_bytes(16)
        self._prefix = prefix
        self._suffix = suffix

    def __call__(self, input_blob):
        return ecb_encrypt(self._key, self._prefix + input_blob + self._suffix)


class Challenge12Oracle(Challenge14Oracle):
    def __init__(self):
        Challenge14Oracle.__init__(
            self, b'', base64.b64decode(bytes_from_file('inputs/12_input.txt')))


class Challenge14Solver:

    def __init__(self, oracle):
        self.oracle = oracle
        min_noticable_arg_length = self._min_noticable_arg_length()
        self.blocksize = self._find_blocksize(min_noticable_arg_length)
        num_prefix_only_blocks = self._num_prefix_only_blocks()
        self.prefix_length = self._find_prefix_length(num_prefix_only_blocks)
        self.suffix_length = self._find_suffix_length(min_noticable_arg_length)

    def _min_noticable_arg_length(self):
        """Find minimum arg size to change ciphertext length."""
        length_for_0 = len(self.oracle(b''))
        ii = 0
        while True:
            ii += 1
            length_for_ii = len(self.oracle(b'A' * ii))
            if length_for_ii != length_for_0:
                return ii

    def _find_blocksize(self, min_noticable_arg_length):
        length1 = len(self.oracle(b''))
        length2 = len(self.oracle(b'A' * min_noticable_arg_length))
        return length2 - length1

    def _num_prefix_only_blocks(self):
        """Whole blocks containing only prefix"""
        # We find this by inserting different arguments and seeing how many
        # blocks are identical in both cyphertexts
        return \
            (equal_prefix_length(self.oracle(b'A'), self.oracle(b'B'))
             // self.blocksize)

    def _find_prefix_length(self, num_prefix_only_blocks):
        """Find length of the oracle's inserted prefix."""
        # Basic idea: Find out how much padding is needed to completely fill
        # the rest of the block containing the end of the prefix.
        assert self._is_ecb()
        for ii in range(self.blocksize):
            length = self._try_prefix_padding_length(num_prefix_only_blocks, ii)
            if length is not None:
                return length

    def _try_prefix_padding_length(self, num_prefix_only_blocks, padlength):
        """Prefix length if this is the padding length for _find_prefix_length()"""
        # Basic idea: If we insert a blob of equal bytes long enough to fill
        # both the padding and the next two blocks of plaintext, then the next
        # two blocks of cyphertext become equal.
        test_blob_length = 2 * self.blocksize + padlength
        if padlength == 0:
            block_idx = num_prefix_only_blocks
        else:
            block_idx = num_prefix_only_blocks + 1
        # We actually need to test two different filler bytes, because
        # otherwise we might be fooled by the suffix starting with the filler
        # bytes we try
        for test_blob in [b'A' * test_blob_length, b'B' * test_blob_length]:
            encrypted = self.oracle(test_blob)
            first_block = \
                get_block(encrypted, self.blocksize, block_idx)
            second_block = \
                get_block(encrypted, self.blocksize, block_idx + 1)
            if first_block != second_block:
                return None
        return block_idx * self.blocksize - padlength

    def _find_suffix_length(self, min_noticeable_arg_length):
        """Find length of the oracle's appended suffix."""
        # Basic idea: if we know the minimum number of plaintext bytes leading
        # to an increase of the cyphertext length and also the blocksize, then
        # we know the total length of plaintext not under our control.
        # Subtract the previously calculated prefix length from that, and the
        # rest is suffix.
        return \
            (len(self.oracle(b'A' * min_noticeable_arg_length))
             - self.blocksize
             - min_noticeable_arg_length
             - self.prefix_length)

    def _is_ecb(self):
        input_blob = bytes([0] * 3 * self.blocksize)
        # Two blocks to find repeating cyphertext, the third because we may not
        # start at a block border
        return detect_potential_repeating_ecb_blocks(
            input_blob, blocksize=self.blocksize)

    def solve(self):
        known_bytes = b''
        while len(known_bytes) < self.suffix_length:
            known_bytes += bytes([self.guess_next_byte(known_bytes)])
        return known_bytes

    def guess_next_byte(self, known_bytes):
        for ii in range(256):
            if self.try_next_byte(known_bytes, ii):
                return ii

    def try_next_byte(self, known_bytes, byte):
        # Basic idea same as in challenge 12:
        # Inject enough padding to put the first unknown byte at the end of
        # a block. Then try if it matches byte by alternatively injecting the
        # known part of the suffix and the guessed byte, which should result
        # in the same block.
        fixed_bytes_length = self.prefix_length + len(known_bytes)
        num_prior_blocks = fixed_bytes_length // 16
        used_in_block = fixed_bytes_length % self.blocksize
        padlength = self.blocksize - used_in_block - 1
        testarg = b'A' * padlength
        encrypted_block = get_block(
            self.oracle(testarg),
            self.blocksize,
            num_prior_blocks)
        comparison_block = get_block(
            self.oracle(testarg + known_bytes + bytes([byte])),
            self.blocksize,
            num_prior_blocks)
        return encrypted_block == comparison_block


class Challenge12Solver(Challenge14Solver):

    def __init__(self):
        Challenge14Solver.__init__(self, Challenge12Oracle())


challenge_13_key = secrets.token_bytes(16)


def challenge_13_profile_for(email):
    profile = {
        'email': email,
        'uid': '10',
        'role': 'user'
    }
    encoded = kvserialize.serialize_dict(profile).encode()
    return ecb_encrypt(challenge_13_key, encoded)


def challenge_13_is_admin(encrypted_profile):
    decrypted = ecb_decrypt(challenge_13_key, encrypted_profile).decode()
    profile = kvserialize.parse_kv_string(decrypted)
    return profile['role'] == 'admin'


def challenge_13_forge():
    admin_block_input = \
        'xxxxxxxxxxadmin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b'
    admin_block = challenge_13_profile_for(admin_block_input)[16:32]
    intro_blocks_input = 'xxxxx@bla.com'
    intro_blocks = challenge_13_profile_for(intro_blocks_input)[:32]
    return intro_blocks + admin_block


class Challenge16Oracle:
    def __init__(self):
        self._key = secrets.token_bytes(16)
        self._prefix = 'comment1=cooking%20MCs;userdata='
        self._suffix = ';comment2=%20like%20a%20pound%20of%20bacon'

    @staticmethod
    def _escape(string):
        return string.replace(';', '%3B').replace('=', '%3D')

    def encrypt(self, string):
        plaintext = self._prefix + self._escape(string) + self._suffix
        return cbc_encrypt(self._key, bytes(16), plaintext.encode())

    def is_admin(self, cyphertext):
        plaintext = cbc_decrypt(self._key, bytes(16), cyphertext)
        return b';admin=true' in plaintext


def challenge_16_forge(oracle):
    good = oracle.encrypt('')
    block2 = b'%20MCs;userdata='
    want = b';admin=true'
    delta = xor_buffers(block2, want)
    evil = xor_buffers(good[0:16], delta) + good[16:]
    return evil


class Challenge17Oracle:
    def __init__(self):
        self._key = secrets.token_bytes(16)
        encoded_lines = lines_from_file("inputs/17_input.txt")
        self._possible_lines = list(map(base64.b64decode, encoded_lines))

    def get_encrypted(self):
        line = secrets.choice(self._possible_lines)
        iv = secrets.token_bytes(16)
        return iv, cbc_encrypt(self._key, iv, line)

    def encrypt_prepadded_input(self, input_):
        assert len(input_) % 16 == 0
        iv = secrets.token_bytes(16)
        return iv, cbc_encrypt_prepadded(self._key, iv, input_)

    def check_padding(self, iv, encrypted):
        try:
            cbc_decrypt(self._key, iv, encrypted)
            return True
        except InvalidPaddingError:
            return False

    def check_line_possible(self, line):
        return line in self._possible_lines


def cbc_padding_crack_check_iv_suffix(oracle, suffix, block):
    suffix_length = len(suffix)
    if suffix_length == 0:
        return True
    prefix_length = len(block) - suffix_length
    test_iv = bytes(prefix_length * [0]) + suffix
    return oracle.check_padding(test_iv, block)


def cbc_padding_crack_extend_iv_suffix(oracle, old_suffix, block):
    old_length = len(old_suffix)
    new_length = old_length + 1
    if old_length == 0:
        new_susuffix = b''
    else:
        trafo_byte = new_length ^ old_length
        new_susuffix = xor_buffers(old_suffix, bytes(old_length * [trafo_byte]))
    for i in range(256):
        candidate = bytes([i]) + new_susuffix
        if cbc_padding_crack_check_iv_suffix(oracle, candidate, block):
            yield candidate


def cbc_padding_crack_single_block(oracle, block, previous_block):
    possible_iv_suffixes = [b""]
    for i in range(16):
        possible_iv_suffixes = [new_suffix
                                for old_suffix in possible_iv_suffixes
                                for new_suffix in
                                cbc_padding_crack_extend_iv_suffix(
                                    oracle, old_suffix, block)]
    forged_iv = possible_iv_suffixes[0]
    oracle.check_padding(forged_iv, block)
    mask = xor_buffers(bytes(16 * [16]), previous_block)
    return xor_buffers(forged_iv, mask)


def cbc_padding_crack(oracle, iv, encrypted):
    assert len(encrypted) % 16 == 0
    encrypted_blocks = [iv] + brake_into_keysize_blocks(encrypted, 16)

    def plainblocks():
        for i in range(1, len(encrypted_blocks)):
            yield cbc_padding_crack_single_block(
                oracle, encrypted_blocks[i], encrypted_blocks[i - 1])

    return strip_pkcs_7(b''.join([block for block in plainblocks()]))
