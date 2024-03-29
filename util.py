__all__ = ["bytes_from_file",
           "equal_prefix_length",
           "find_minimal",
           "lines_from_file",
           "nonrepeating_zip",
           "obj_from_json_file",
           "random_blob",
           "repeating_zip",
           "remove_nones",
           "string_from_file"]

import json
import secrets


def bytes_from_file(file_name):
    with open(file_name, "br") as file:
        return file.read()


def string_from_file(file_name):
    return bytes_from_file(file_name).decode()


def lines_from_file(file_name):
    with open(file_name, "r") as file:
        return file.readlines()


def obj_from_json_file(file_name):
    with open(file_name, "r") as file:
        return json.load(file)


def nonrepeating_zip(left, right):
    length = min(len(left), len(right))
    for ii in range(length):
        yield left[ii], right[ii]


def repeating_zip(left, right):
    """Zip, repeating the shorter as necessary"""
    left_len = len(left)
    right_len = len(right)
    if left_len == 0 or right_len == 0:
        raise ValueError("Inputs can't be empty")
    for ii in range(max(left_len, right_len)):
        left_index = ii % left_len
        right_index = ii % right_len
        yield left[left_index], right[right_index]


def find_minimal(gen, criterion):
    minimum = None
    best = None
    for element in gen:
        if element is None:
            continue
        score = criterion(element)
        if score is None:
            continue
        if minimum is None or score < minimum:
            minimum = score
            best = element
    return best


# noinspection PyPep8Naming
class remove_nones:
    def __init__(self, gen):
        self.gen = gen

    def __iter__(self):
        return self

    def __next__(self):
        next_ = None
        while next_ is None:
            next_ = next(self.gen)
        return next_


def rand_int_from_to(smallest, largest):
    if largest < smallest:
        raise ValueError('Maximum smaller than minimum')
    elif largest == smallest:
        return smallest
    else:
        return smallest + secrets.randbelow(largest - smallest + 1)


def random_blob(min_bytes, max_bytes):
    if min_bytes < 0 or max_bytes < 0:
        raise ValueError('Negative e lengths are impossible')
    return secrets.token_bytes(rand_int_from_to(min_bytes, max_bytes))


def equal_prefix_length(left, right):
    max_possible = min(len(left), len(right))
    for ii in range(max_possible):
        if left[ii] != right[ii]:
            return ii
    return max_possible
