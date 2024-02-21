from hypothesis.strategies import *

from block_crypt import pad_pkcs_7


@composite
def lists_of_integers(draw):
    return draw(lists(elements=integers()))


@composite
def pairs_of_integers(draw):
    return draw(tuples(integers(), integers()))


@composite
def list_of_same_size_binaries(
        draw,
        min_length=None,
        max_length=None,
        min_size=0,
        max_size=1024
):
    size = draw(integers(min_value=min_size, max_value=max_size))
    return draw(lists(
        elements=binary(min_size=size, max_size=size),
        min_size=min_length,
        max_size=max_length
    ))


@composite
def its_of_pairs_of_integers(draw):
    return draw(iterables(elements=pairs_of_integers()))


@composite
def byte_sized_integers(draw):
    return draw(integers(min_value=0, max_value=0xff))


@composite
def negative_integers(draw):
    return draw(integers(max_value=-1))


@composite
def integers_greater_than_byte(draw):
    return draw(integers(min_value=0x100))


@composite
def non_byte_sized_integers(draw):
    return draw(one_of(negative_integers(), integers_greater_than_byte()))


@composite
def lists_of_non_byte_sized_integers(draw):
    return draw(lists(elements=non_byte_sized_integers()))


@composite
def single_bytes(draw):
    return draw(binary(min_size=1, max_size=1))


@composite
def binary_and_string_same_length(draw):
    blob = draw(binary())
    length = len(blob)
    string = draw(text(min_size=length, max_size=length))
    return blob, string


@composite
def binary_and_possible_blocksize(draw):
    blob = draw(binary())
    blob_length = len(blob)
    int_ = draw(integers(min_value=1, max_value=max(blob_length, 1)))
    return blob, int_


@composite
def non_pkcs7_padded_blob(draw, blocksize):
    blob = draw(binary())
    padded_good = pad_pkcs_7(blob, blocksize)
    padding = bytearray(padded_good[len(blob):])
    assert padded_good == blob + padding
    num_padding_bytes = len(padding)
    assert num_padding_bytes > 0
    change_loc = draw(integers(min_value=0, max_value=num_padding_bytes - 1))
    if change_loc == num_padding_bytes - 1:
        min_replacement_byte = 2
        # because 1 in the last place would always be a valid padding
    else:
        min_replacement_byte = 1
        # because 0 is never the last byte of a validly padded block
    replacement_byte_strat = integers(
        min_value=min_replacement_byte,
        max_value=255). \
        filter(lambda x: x != padding[change_loc])
    replacement_byte = draw(replacement_byte_strat)
    padding[change_loc] = replacement_byte
    return blob + padding


@composite
def non_pkcs7_padded_blocksize_and_blob(draw):
    blocksize = draw(integers(min_value=1, max_value=255))
    blob = draw(non_pkcs7_padded_blob(blocksize=blocksize))
    return blocksize, blob
