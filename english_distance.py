"""Compare strings (to English) by byte frequency"""
__all__ = ["english_distance"]

from math import sqrt, pow

from util import bytes_from_file


def _count_byte_occurrences(blob):
    counts = [0] * 256
    byteiter = (int.from_bytes(blob[ii:ii + 1], "big") for ii in
                range(len(blob)))
    for byte in byteiter:
        counts[byte] += 1
    return counts


def _get_byte_frequencies(blob):
    counts = _count_byte_occurrences(blob)
    sum_ = sum(counts)
    if sum_ == 0:
        return [0] * 256
    return [value / sum_ for value in counts]


def _byte_frequency_distance(left, right):
    num_byte_states = 256
    sum_ = 0
    for ii in range(num_byte_states):
        sum_ += pow(left[ii] - right[ii], 2)
    return sqrt(sum_ / num_byte_states)


class _TypeFrequencyPrototypeDistance:

    def __init__(self, prototype):
        self.prototype = _get_byte_frequencies(prototype)

    def __call__(self, blob):
        return _byte_frequency_distance(_get_byte_frequencies(blob),
                                        self.prototype)


english_distance = _TypeFrequencyPrototypeDistance(
    bytes_from_file("inputs/english_sample.txt"))
english_distance.__doc__ = \
    "Rms byte frequency distance of utf8 encoding to an english sample text "
