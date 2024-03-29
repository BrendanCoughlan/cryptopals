__all__ = [
    "InvalidPaddingError",
    "find_potential_ecb",
    "pad_pkcs_7",
    "strip_pkcs_7",
    "detect_potential_repeating_ecb_blocks",
    "ecb_encrypt",
    "cbc_encrypt_prepadded",
    "ecb_decrypt",
    "cbc_encrypt",
    "cbc_decrypt",
]

# noinspection PyPackageRequirements
# false alert, is in requirements as pycryptodome
from Crypto.Cipher import AES

from bitfiddle import brake_into_keysize_blocks
from primitive_crypt import xor_buffers


def detect_potential_repeating_ecb_blocks(ciphertext, blocksize=16):
    seen = set()
    for block in brake_into_keysize_blocks(ciphertext, blocksize):
        if block in seen:
            return True
        else:
            seen.add(block)
    return False


def find_potential_ecb(cyphertexts):
    for cyphertext in cyphertexts:
        if detect_potential_repeating_ecb_blocks(cyphertext):
            return cyphertext
    return None


def pad_pkcs_7(blob, blocksize):
    num_pad_bytes = blocksize - (len(blob) % blocksize)
    padding = bytes([num_pad_bytes] * num_pad_bytes)
    return blob + padding


class InvalidPaddingError(ValueError):
    pass


def strip_pkcs_7(blob):
    length = len(blob)
    if length == 0:
        raise InvalidPaddingError()
    num_padding = blob[-1]
    if num_padding == 0 or length < num_padding:
        raise InvalidPaddingError()
    for byte in blob[-num_padding:]:
        if byte != num_padding:
            raise InvalidPaddingError()
    return blob[:-num_padding]


def ecb_encrypt(key, plaintext):
    cipher = AES.new(key, AES.MODE_ECB)
    input_blob = pad_pkcs_7(plaintext, 16)
    return cipher.encrypt(input_blob)


def ecb_decrypt(key, ciphertext):
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted = cipher.decrypt(ciphertext)
    return strip_pkcs_7(decrypted)


def cbc_encrypt_prepadded(key, iv, plaintext):
    blocks = brake_into_keysize_blocks(plaintext, 16)
    cipher = AES.new(key, AES.MODE_ECB)

    def cryptoblocks():
        last_block = iv
        for block in blocks:
            chained = xor_buffers(last_block, block)
            last_block = cipher.encrypt(chained)
            yield last_block

    return b''.join([cb for cb in cryptoblocks()])


def cbc_encrypt(key, iv, plaintext):
    return cbc_encrypt_prepadded(key, iv, pad_pkcs_7(plaintext, 16))


def cbc_decrypt(key, iv, ciphertext):
    assert len(ciphertext) % 16 == 0
    blocks = brake_into_keysize_blocks(ciphertext, 16)
    cipher = AES.new(key, AES.MODE_ECB)

    def plainblocks():
        last_block = iv
        for block in blocks:
            decrypted_block = cipher.decrypt(block)
            plain_block = xor_buffers(last_block, decrypted_block)
            last_block = block
            yield plain_block

    return strip_pkcs_7(b''.join(pb for pb in plainblocks()))
