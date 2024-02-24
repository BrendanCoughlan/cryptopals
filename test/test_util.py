import hypothesis as hyp
import hypothesis.strategies as strat
import pytest

import util


class TestNonrepeatingZip:

    def test_inputs_need_length(self):
        with pytest.raises(TypeError):
            list(util.repeating_zip(8, 15))

    def test_both_empty(self):
        assert list(util.nonrepeating_zip([], [])) == []

    def test_left_empty(self):
        assert list(util.nonrepeating_zip([], [1, 2, 3])) == []

    def test_right_empty(self):
        assert list(util.nonrepeating_zip([1, 2, 3], [])) == []

    def test_zip_left_longer(self):
        assert list(util.nonrepeating_zip([1, 2, 3], [1])) == [(1, 1)]

    def test_zip_right_longer(self):
        assert list(util.nonrepeating_zip([1], [1, 2, 3])) == [(1, 1)]

    def test_zip_equal_length(self):
        assert list(util.nonrepeating_zip([1, 2, 3], [3, 2, 1])) == \
               [(1, 3), (2, 2), (3, 1)]

    def test_different_lengths_greater_one(self):
        assert list(util.nonrepeating_zip([1, 2], [1, 2, 3, 4, 5])) == \
               [(1, 1), (2, 2)]

    def test_zip_equal_length_one(self):
        assert list(util.nonrepeating_zip([42], [42])) == [(42, 42)]

    def test_works_with_strings(self):
        assert list(util.nonrepeating_zip([42, 42], ["forty-two"])) == \
               [(42, "forty-two")]


class TestRepeatingZip:

    def test_inputs_need_length(self):
        with pytest.raises(TypeError):
            list(util.repeating_zip(8, 15))

    def test_both_empty(self):
        with pytest.raises(ValueError):
            list(util.repeating_zip([], []))

    def test_left_empty(self):
        with pytest.raises(ValueError):
            list(util.repeating_zip([], [1, 2, 3]))

    def test_right_empty(self):
        with pytest.raises(ValueError):
            list(util.repeating_zip([1, 2, 3], []))

    def test_zip_left_longer(self):
        assert list(util.repeating_zip([1, 2, 3], [1])) == \
               [(1, 1), (2, 1), (3, 1)]

    def test_zip_right_longer(self):
        assert list(util.repeating_zip([1], [1, 2, 3])) == \
               [(1, 1), (1, 2), (1, 3)]

    def test_zip_equal_length(self):
        assert list(util.repeating_zip([1, 2, 3], [3, 2, 1])) == \
               [(1, 3), (2, 2), (3, 1)]

    def test_different_lengths_greater_one(self):
        assert list(util.repeating_zip([1, 2], [1, 2, 3, 4, 5])) == \
               [(1, 1), (2, 2), (1, 3), (2, 4), (1, 5)]

    def test_zip_equal_length_one(self):
        assert list(util.repeating_zip([42], [42])) == [(42, 42)]

    def test_works_with_strings(self):
        assert list(util.repeating_zip([42, 42], ["forty-two"])) == \
               [(42, "forty-two"), (42, "forty-two")]


class TestFindMinimal:
    def test_trivial_case(self):
        assert util.find_minimal([3, 1, 2], lambda x: x) == 1

    def test_square_sign(self):
        assert util.find_minimal([-2, 1, 2], lambda x: x * x) == 1

    def test_first_arg_must_be_gen(self):
        with pytest.raises(TypeError):
            util.find_minimal(42, lambda x: x)

    def test_second_arg_must_be_callable(self):
        with pytest.raises(TypeError):
            util.find_minimal([1, 2, 3], 42)

    def test_empty_gen(self):
        assert util.find_minimal([], lambda x: 42) is None

    def test_none_in_criterion_gives_none(self):
        assert util.find_minimal([1, 2, 3], lambda x: None) is None

    def test_nones(self):
        assert util.find_minimal([None, None, None], lambda x: 42) is None

    def test_first_element_if_equal(self):
        assert util.find_minimal([5, 4, 3, 2, 1], lambda x: 42) == 5


class TestRemoveNones:
    def test_example(self):
        unfiltered_list = [None, 1, 2, None, 3, None]
        filtered = util.remove_nones(iter(unfiltered_list))
        filtered_list = list(filtered)
        assert filtered_list == [1, 2, 3]

    def test_empty(self):
        assert list(util.remove_nones(iter([]))) == []

    def test_all_nones(self):
        assert list(util.remove_nones(iter([None, None, None]))) == []


class TestRandIntFromTo:
    @hyp.given(
        min_val=strat.integers(),
        max_val=strat.integers()
    )
    def test_in_range(self, min_val, max_val):
        if max_val < min_val:
            with pytest.raises(ValueError):
                util.rand_int_from_to(min_val, max_val)
        else:
            val = util.rand_int_from_to(min_val, max_val)
            assert min_val <= val
            assert val <= max_val

    @hyp.given(
        min_value=strat.integers(min_value=-5, max_value=5),
        increment=strat.integers(min_value=0, max_value=10)
    )
    def test_range_inclusive(self, min_value, increment):
        max_value = min_value + increment
        seen_min = False
        seen_max = False
        for ii in range(10 ** 9):
            val = util.rand_int_from_to(min_value, max_value)
            if val == min_value:
                seen_min = True
            if val == max_value:
                seen_max = True
            if seen_min and seen_max:
                return
        assert False


class TestRandomBlob:
    @hyp.given(
        min_val=strat.integers(min_value=-5, max_value=50),
        max_val=strat.integers(min_value=-5, max_value=50)
    )
    def test_in_range(self, min_val, max_val):
        if min_val < 0 or max_val < 0:
            with pytest.raises(ValueError):
                util.random_blob(min_val, max_val)
        elif max_val < min_val:
            with pytest.raises(ValueError):
                util.random_blob(min_val, max_val)
        else:
            length = len(util.random_blob(min_val, max_val))
            assert min_val <= length
            assert length <= max_val

    @hyp.given(
        min_value=strat.integers(min_value=0, max_value=5),
        increment=strat.integers(min_value=0, max_value=10)
    )
    def test_range_inclusive(self, min_value, increment):
        max_value = min_value + increment
        seen_min = False
        seen_max = False
        for ii in range(10 ** 9):
            length = len(util.random_blob(min_value, max_value))
            if length == min_value:
                seen_min = True
            if length == max_value:
                seen_max = True
            if seen_min and seen_max:
                return
        assert False


@hyp.given(
    common=strat.binary(),
    left_extra=strat.binary(),
    right_extra=strat.binary())
def test_equal_prefix_length(common, left_extra, right_extra):
    assert util.equal_prefix_length(common + left_extra, common + right_extra) \
           == len(common) + util.equal_prefix_length(left_extra, right_extra)
