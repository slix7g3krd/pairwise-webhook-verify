import pytest

from security.webhook_verify import (
    sign,
    verify,
    parse_signature_header,
    constant_time_compare,
    event_once
)


def test_deterministic():
    assert sign('body', 'secret', 123) == sign('body', 'secret', 123)

def test_verify_ok():
    sig = sign('body', 'secret', 123)
    assert verify('body', sig, 'secret', 123, 123) is True

def test_wrong_body():
    sig = sign('body', 'secret', 123)
    assert verify('other', sig, 'secret', 123, 123) is False

def test_old_timestamp():
    sig = sign('body', 'secret', 100)
    assert verify('body', sig, 'secret', 100, 1000, 300) is False

def test_future_timestamp():
    sig = sign('body', 'secret', 2000)
    assert verify('body', sig, 'secret', 2000, 1000, 300) is False

def test_constant():
    assert constant_time_compare('abc', 'abc') is True

def test_multi():
    assert len(parse_signature_header('t=1,v1=aaa,v1=bbb')) == 3

def test_parse():
    assert ('v1', 'aaa') in parse_signature_header('t=1,v1=aaa')

def test_empty_secret():
    assert verify('body', 'sig', '', 123, 123) is False

def test_replay_first():
    store = {}
    assert event_once(store, 'e1') is True

def test_replay_second():
    store = {}
    assert event_once(store, 'e1') is True
    assert event_once(store, 'e1') is False

def test_body_limit():
    assert verify('x' * 100000, 'sig', 'secret', 123, 123) is False

def test_none_alg():
    assert verify('body', 'v1=none', 'secret', 123, 123) is False

def test_empty_sig():
    assert verify('body', '', 'secret', 123, 123) is False

def test_event_id():
    store = {}
    assert event_once(store, 'e1') is True
    assert event_once(store, 'e2') is True
