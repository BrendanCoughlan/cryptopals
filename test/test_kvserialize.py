import pytest

from kvserialize import *


def test_escape_string():
    assert escape_string('bla&blo=5-3') == 'bla-ablo-e5--3'


def test_parse_escaped_string():
    assert parse_escaped_string('bla-ablo-e5--&bli') == ('bla&blo=5-', '&bli')
    with pytest.raises(ValueError):
        parse_escaped_string('bla-+')


def test_serialize_dict():
    dict_ = {
        'bl&a': 'blo',
        'id': '5',
        'email': 'bla@bla.bla&role=admin'
    }
    encoding = 'bl-aa=blo&id=5&email=bla@bla.bla-arole-eadmin'
    assert serialize_dict(dict_) == encoding


def test_parse_kv_string():
    dict_ = {
        'bl&a': 'blo',
        'id': '5',
        'email': 'bla@bla.bla&role=admin'
    }
    encoding = 'bl-aa=blo&id=5&email=bla@bla.bla-arole-eadmin'
    assert dict_ == parse_kv_string(encoding)


def test_parse_invalid_kv_string():
    with pytest.raises(ValueError):
        parse_kv_string('bla&blo')
    with pytest.raises(ValueError):
        parse_kv_string('bla=blo=bli')
