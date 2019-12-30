from math import sqrt

import hypothesis as hyp
import pytest

import english_distance as ed
from . import strategies


class TestCountByteOccurrences:

    def test_non_blob(self):
        with pytest.raises(TypeError):
            ed._count_byte_occurrences(42)
        with pytest.raises(TypeError):
            ed._count_byte_occurrences("eee")

    @hyp.given(strategies.byte_sized_integers())
    def test_empty(self, byte):
        assert ed._count_byte_occurrences("")[byte] == 0

    @hyp.given(strategies.single_bytes())
    def test_repeated_letters(self, byte):
        counts = ed._count_byte_occurrences(b"eeeeeaaa")
        count = counts[int.from_bytes(byte, "big")]
        assert counts[int.from_bytes(b"e", "big")] == 5
        hyp.assume(byte != b"e")
        assert counts[int.from_bytes(b"a", "big")] == 3
        hyp.assume(byte != b"a")
        assert count == 0

    def test_word(self):
        counts = ed._count_byte_occurrences(b"trallala")
        assert counts[int.from_bytes(b"t", "big")] == 1
        assert counts[int.from_bytes(b"r", "big")] == 1
        assert counts[int.from_bytes(b"a", "big")] == 3
        assert counts[int.from_bytes(b"l", "big")] == 3
        assert counts[int.from_bytes(b"u", "big")] == 0


class TestGetByteFrequencies:
    def test_empty(self):
        assert ed._get_byte_frequencies("")[int.from_bytes(b"e", "big")] == 0

    def test_example(self):
        counts = ed._get_byte_frequencies(b"eeeeeaaa")
        assert counts[int.from_bytes(b"e", "big")] == 5 / 8
        assert counts[int.from_bytes(b"a", "big")] == 3 / 8
        assert counts[int.from_bytes(b"n", "big")] == 0


class TestByteFreqDistance:
    def test_identical(self):
        dict_ = ed._get_byte_frequencies(b"bla")
        assert ed._byte_frequency_distance(dict_, dict_) == 0

    def test_empty_and_populated(self):
        freq_empty = ed._get_byte_frequencies(b"")
        freq_only_e = ed._get_byte_frequencies(b"eeee")
        assert ed._byte_frequency_distance(freq_empty, freq_only_e) == \
               sqrt(1 / 256)

    def test_different_letter(self):
        only_a = ed._get_byte_frequencies(b"a")
        only_b = ed._get_byte_frequencies(b"b")
        assert ed._byte_frequency_distance(only_a, only_b) == sqrt(2 / 256)


class TestByteFreqPrototypeDistance:

    def test(self):
        comparator = ed._TypeFrequencyPrototypeDistance(b"eeee")
        assert comparator("") == sqrt(1 / 256)


class TestEnglishDistance:

    def test_identical(self):
        english = ed.bytes_from_file("inputs/english_sample.txt")
        assert ed.english_distance(english) == 0

    def test_different(self):
        assert ed.english_distance("xq\t\0%~".encode()) != 0
