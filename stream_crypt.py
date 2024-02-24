__all__ = [
    "ctr_transcrypt",
    "guess_shared_keystream_by_subst"
]

# noinspection PyPackageRequirements
# false alert, is in requirements as pycryptodome
from Crypto.Cipher import AES

from bitfiddle import brake_into_keysize_blocks
from primitive_crypt import xor_buffers
from primitive_crypt import xor_buffers_nonrepeating
from util import find_minimal


def ctr_keystream(key, nonce, block_count):
    if nonce < 0 or nonce > 2 ** 64 or block_count < 0 or block_count > 2 ** 64:
        raise ValueError()
    plain_nonce = nonce.to_bytes(8, byteorder="little", signed=False)
    plain_count = block_count.to_bytes(8, byteorder="little", signed=False)
    plain = plain_nonce + plain_count
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(plain)


def ctr_transcrypt(key, nonce, data):
    instream = brake_into_keysize_blocks(data, 16)
    num_blocks = len(instream)
    if num_blocks == 0:
        return b''
    keystream = [ctr_keystream(key, nonce, i) for i in range(num_blocks)]
    keystream[-1] = keystream[-1][:len(instream[-1])]
    outstream = [xor_buffers(instream[i], keystream[i])
                 for i in range(num_blocks)]
    return b''.join(outstream)


def guess_shared_keystream_by_subst(cyphertexts, guesses):
    def negative_length_criterion(text):
        return -len(text)
    longest_cyphertext = find_minimal(cyphertexts, negative_length_criterion)
    guessed_keystream = bytearray(longest_cyphertext)
    for guess in guesses:
        guess_bytes = guess["guess"].encode("utf-8")
        guess_line = guess["line"]
        guess_pos = guess["pos"]
        keystream_bytes = xor_buffers_nonrepeating(guess_bytes, cyphertexts[guess_line][guess_pos:])
        guessed_keystream = (
                guessed_keystream[:guess_pos] + keystream_bytes + guessed_keystream[guess_pos+len(guess_bytes):])

    return bytes(guessed_keystream)

