import secrets

from block_crypt import cbc_encrypt, \
    ecb_encrypt, \
    detect_potential_repeating_ecb_blocks
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
