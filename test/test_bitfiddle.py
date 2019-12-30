import hypothesis as hyp
import pytest

import bitfiddle as bf
from . import strategies


class TestXorPairs:

    def test_empty(self):
        assert list(bf.xor_pairs([])) == []

    def test_not_xorable(self):
        with pytest.raises(TypeError):
            list(bf.xor_pairs([(1, "bla"), (2, "blo"), (3, "bli")]))

    def test_not_pairs(self):
        with pytest.raises(TypeError):
            list(bf.xor_pairs(iter([1, 2, 3])))

    def test_known_values(self):
        pairs = [(1, 1), (7, 0), (3, 1), (512, 1), (-1, 3), (-7, 6)]
        result = list(bf.xor_pairs(pairs))
        assert result == [0, 7, 2, 513, -4, -1]

    @hyp.given(strategies.its_of_pairs_of_integers())
    def test_length_preserved(self, pairs):
        list_ = list(pairs)
        assert len(list_) == len(list(bf.xor_pairs(list_)))

    @hyp.given(strategies.lists_of_integers())
    def test_self_xor_yields_zero(self, ints):
        length = len(ints)
        pairs = [(el, el) for el in ints]
        result = list(bf.xor_pairs(pairs))
        should_be = [0] * length
        assert result == should_be

    @hyp.given(strategies.its_of_pairs_of_integers())
    def test_symmetrical(self, pairs):
        pairs = [pair for pair in pairs]
        flipped = [pair[::-1] for pair in pairs]
        assert list(bf.xor_pairs(pairs)) == list(bf.xor_pairs(flipped))


class TestByteFromInt:

    @hyp.given(strategies.non_byte_sized_integers())
    def test_out_of_range(self, arg):
        with pytest.raises(OverflowError):
            bf.byte_from_int(arg)

    @hyp.given(strategies.byte_sized_integers())
    def test_round_trip_start_int(self, arg):
        assert bf.byte_from_int(arg)[0] == arg

    @hyp.given(strategies.single_bytes())
    def test_round_trip_start_byte(self, arg):
        assert bf.byte_from_int(arg[0]) == arg


class TestSingleByteHamming:

    @hyp.given(
        byte=strategies.byte_sized_integers(),
        non_byte=strategies.non_byte_sized_integers()
    )
    def test_range(self, byte, non_byte):
        with pytest.raises(ValueError):
            bf._single_byte_hamming_distance((byte, non_byte))
        with pytest.raises(ValueError):
            bf._single_byte_hamming_distance((non_byte, byte))

    @hyp.given(strategies.byte_sized_integers())
    def test_identical(self, arg):
        assert bf._single_byte_hamming_distance((arg, arg)) == 0

    @hyp.given(
        left=strategies.byte_sized_integers(),
        right=strategies.byte_sized_integers()
    )
    def test_symmetric(self, left, right):
        assert bf._single_byte_hamming_distance((left, right)) == \
               bf._single_byte_hamming_distance((right, left))

    @hyp.given(
        arg1=strategies.byte_sized_integers(),
        arg2=strategies.byte_sized_integers(),
        arg3=strategies.byte_sized_integers()
    )
    def test_subadditive(self, arg1, arg2, arg3):
        dist12 = bf._single_byte_hamming_distance((arg1, arg2))
        dist23 = bf._single_byte_hamming_distance((arg2, arg3))
        dist13 = bf._single_byte_hamming_distance((arg1, arg3))
        assert dist13 <= dist12 + dist23

    def test_adjacent(self):
        assert bf._single_byte_hamming_distance((1, 0)) == 1

    def test_example(self):
        assert bf._single_byte_hamming_distance((3, 16)) == 3

    def test_all_bits(self):
        assert bf._single_byte_hamming_distance((0, 255)) == 8


class TestHammingDistance:

    @hyp.given(
        left=strategies.binary(),
        right=strategies.binary()
    )
    def test_different_length(self, left, right):
        hyp.assume(len(left) != len(right))
        with pytest.raises(ValueError):
            bf.hamming_distance(left, right)

    def test_empty(self):
        assert bf.hamming_distance([], []) == 0
        assert bf.hamming_distance(b"", b"") == 0

    @hyp.given(strategies.binary_and_string_same_length())
    def test_unencoded(self, args):
        blob = args[0]
        hyp.assume(len(blob) != 0)
        string = args[1]
        with pytest.raises(TypeError):
            bf.hamming_distance(string, blob)
        with pytest.raises(TypeError):
            bf.hamming_distance(blob, string)

    def test_lists(self):
        assert bf.hamming_distance([1, 2, 3], [1, 2, 3]) == 0

    @hyp.given(strategies.lists_of_non_byte_sized_integers())
    def test_out_of_range(self, list_):
        hyp.assume(len(list_) != 0)
        with pytest.raises(ValueError):
            bf.hamming_distance(list_, list_)

    @hyp.given(strategies.binary())
    def test_identical(self, arg):
        assert bf.hamming_distance(arg, arg) == 0

    @hyp.given(strategies.list_of_same_size_binaries(
        min_length=2,
        max_length=2)
    )
    def test_symmetrical(self, list_):
        left = list_[0]
        right = list_[1]
        assert bf.hamming_distance(left, right) == \
               bf.hamming_distance(right, left)

    @hyp.given(strategies.list_of_same_size_binaries(
        min_length=3,
        max_length=3
    ))
    def test_subadditive(self, list_):
        dist01 = bf.hamming_distance(list_[0], list_[1])
        dist12 = bf.hamming_distance(list_[1], list_[2])
        dist02 = bf.hamming_distance(list_[0], list_[2])
        assert dist02 <= dist01 + dist12

    def test_example_distances(self):
        assert bf.hamming_distance(b"bla", b"alb") == 4
        assert bf.hamming_distance(b"bla", b"BLA") == 3
        assert bf.hamming_distance([1, 2, 3], [0, 5, 5]) == 6


class TestBrakeIntoKeysizeBlocks:

    def test_example(self):
        assert bf.brake_into_keysize_blocks(b"blablobliblu", 3) == \
               [b"bla", b"blo", b"bli", b"blu"]

    def test_rest(self):
        assert bf.brake_into_keysize_blocks(b"blablobl", 3) == \
               [b"bla", b"blo", b"bl"]
