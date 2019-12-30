__all__ = [
    "xor_pairs",
    "byte_from_int",
    "hamming_distance",
    "brake_into_keysize_blocks"
]

from math import ceil


def xor_pairs(pairs):
    """Generate the XOR of the elements of the given pairs"""
    for left, right in pairs:
        yield left ^ right


def byte_from_int(int_):
    return int_.to_bytes(1, byteorder="big")


def _single_byte_hamming_distance(pair):
    distance = 0
    left, right = pair
    if left >= 256 or right >= 256:
        raise ValueError("Not a byte")
    if left < 0 or right < 0:
        raise ValueError("Not an (unsigned) byte")
    for ii in range(8):
        mask = 1 << ii
        if (mask & left) != (mask & right):
            distance += 1
    return distance


def hamming_distance(left, right):
    """Hamming distance between two equal length bytes objects"""
    if len(left) != len(right):
        raise ValueError("Blobs must have same length")
    return sum(
        _single_byte_hamming_distance(pair) for pair in zip(left, right))


def brake_into_keysize_blocks(blob, keysize):
    num_blocks = ceil(len(blob) / keysize)
    # noinspection PyTypeChecker
    return [blob[ii * keysize:(ii + 1) * keysize] for ii in range(num_blocks)]
