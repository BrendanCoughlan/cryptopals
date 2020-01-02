"""Serializer and parser for challenge 13

For a real application, urllib.parse.parse_qs might come to mind.
That is actually doing too good a job for the challenge, because it also
escapes padding bytes.

So I'm doing an own version where the only escapes are

& -> -a
= -> -e
- -> --
"""


def escape_string(string):
    return string.replace('-', '--').replace('&', '-a').replace('=', '-e')


def parse_escaped_string(input_):
    length = len(input_)
    rv = ''
    in_escape = False
    for ii in range(length):
        next_char = input_[ii]
        if in_escape:
            if next_char == '-':
                rv += '-'
            elif next_char == 'a':
                rv += '&'
            elif next_char == 'e':
                rv += '='
            else:
                raise ValueError('Invalid escape sequence')
            in_escape = False
        else:
            if next_char == '-':
                in_escape = True
            elif next_char in ['&', '=']:
                return rv, input_[ii:]
            else:
                rv += next_char
    return rv, ''


def serialize_dict(dict_):
    itemstrings = []
    for key, value in dict_.items():
        itemstring = escape_string(key) + '=' + escape_string(value)
        itemstrings.append(itemstring)
    return '&'.join(itemstrings)


def parse_kv_string(input_):
    rest = input_
    rv = {}
    while True:
        key, rest = parse_escaped_string(rest)
        if rest[0] != '=':
            raise ValueError('Expected =')
        value, rest = parse_escaped_string(rest[1:])
        rv[key] = value
        if not rest:
            return rv
        if rest[0] != '&':
            raise ValueError('Expected &')
        rest = rest[1:]
