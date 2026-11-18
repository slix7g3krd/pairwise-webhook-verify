"""Webhook signature verification with the known defects fixed.

Fixes vs. the original integration:
- HMAC is computed over the *raw* request body (never a re-serialized JSON),
  so field ordering / URL-encoding of the parsed payload cannot desync it.
- Timestamp is validated against a tolerance window, and future timestamps
  beyond the window are rejected (no "1 hour in the future" allowance).
- Signature comparison is constant-time (hmac.compare_digest), never ==.
- Multiple signatures in the header are each tried (key rotation window),
  and multiple secrets (old/new key) are supported during rotation.
- The signature header is parsed as key=value pairs; a value containing a
  comma is not silently truncated into a bogus pair.
- Request body size is capped before the HMAC is computed.
- The algorithm is fixed to HMAC-SHA256 (v1); a request-supplied algorithm
  such as "none" is rejected.
- Empty secrets are rejected instead of returning True.
- Replay cache keys on event id + timestamp, not a forgeable id alone.
- verify() returns only True/False; it never leaks the expected signature
  and never mutates any order state — callers must only act on True.
"""

import hashlib
import hmac

# Fixed algorithm: HMAC-SHA256. The request does not get to choose.
_ALGORITHM = hashlib.sha256
_SCHEME = 'v1'

# Reject bodies larger than this before doing any work (DoS guard).
MAX_BODY_BYTES = 64 * 1024

# Default timestamp tolerance in seconds (applies to past AND future).
DEFAULT_TOLERANCE = 300


def _to_bytes(value):
    """Encode consistently: str -> utf-8 bytes; bytes pass through."""
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode('utf-8')
    raise TypeError('expected str or bytes, got %r' % type(value).__name__)


def _as_key_list(secret):
    """Accept a single key or a rotation list of keys; drop empties."""
    if isinstance(secret, (list, tuple)):
        return [s for s in secret if s]
    return [secret] if secret else []


def constant_time_compare(a, b):
    """Constant-time string comparison; never leaks length via ==."""
    try:
        return hmac.compare_digest(_to_bytes(a), _to_bytes(b))
    except (TypeError, ValueError):
        return False


def parse_signature_header(header):
    """Parse 't=123,v1=sig1,v1=sig2' into [('t','123'),('v1','sig1'),...].

    Pairs without '=' are ignored rather than treated as truncated
    signatures, and all v1 values are kept (rotation sends several).
    """
    pairs = []
    if not header:
        return pairs
    for part in str(header).split(','):
        part = part.strip()
        if not part or '=' not in part:
            continue
        key, _, value = part.partition('=')
        key = key.strip()
        value = value.strip()
        if key and value:
            pairs.append((key, value))
    return pairs


def sign(body, secret, timestamp):
    """Compute the v1 signature: HMAC-SHA256(secret, '<ts>.<raw body>').

    The raw body bytes are signed as-is; nothing is re-serialized.
    """
    keys = _as_key_list(secret)
    if not keys:
        raise ValueError('secret must not be empty')
    payload = b'%d.%s' % (int(timestamp), _to_bytes(body))
    return hmac.new(_to_bytes(keys[0]), payload, _ALGORITHM).hexdigest()


def _candidate_signatures(signature):
    """Yield candidate v1 signatures from a raw sig or a full header."""
    if not signature:
        return
    text = signature.decode('utf-8', 'replace') if isinstance(signature, bytes) else str(signature)
    if '=' in text:
        for key, value in parse_signature_header(text):
            # Fixed scheme: only v1 (HMAC-SHA256). 'none' or any other
            # request-supplied algorithm is ignored, never honored.
            if key == _SCHEME:
                yield value
    else:
        yield text.strip()


def verify(body, signature, secret, timestamp, now, tolerance=DEFAULT_TOLERANCE):
    """Verify a webhook signature. Returns only True/False (no detail leak).

    Checks, in order: non-empty secret, body size cap, timestamp window
    (past and future), then constant-time compare of every candidate
    signature against every active key. No state is mutated here.
    """
    keys = _as_key_list(secret)
    if not keys:
        return False

    try:
        body_bytes = _to_bytes(body)
    except TypeError:
        return False
    if len(body_bytes) > MAX_BODY_BYTES:
        return False

    try:
        ts = int(timestamp)
        now = int(now)
        tolerance = int(tolerance)
    except (TypeError, ValueError):
        return False
    # Window applies symmetrically: old replays and far-future
    # timestamps are both rejected.
    if abs(now - ts) > tolerance:
        return False

    payload = b'%d.%s' % (ts, body_bytes)
    expected = [
        hmac.new(_to_bytes(key), payload, _ALGORITHM).hexdigest()
        for key in keys
    ]

    for candidate in _candidate_signatures(signature):
        if not candidate:
            continue
        for exp in expected:
            if constant_time_compare(candidate, exp):
                return True
    return False


def event_once(store, event_id, timestamp=None, now=None, ttl=86400):
    """Idempotency guard: True the first time an event is seen, False after.

    The replay key combines the event id with its timestamp, so a forged
    id alone cannot replay an event, and retries of the same delivery
    (same id + same timestamp) are still deduplicated. Entries older than
    ttl seconds are pruned when `now` is provided.
    """
    if not event_id:
        return False
    if now is not None:
        cutoff = now - ttl
        for key in [k for k, v in store.items() if isinstance(v, (int, float)) and v < cutoff]:
            del store[key]
    key = (str(event_id), None if timestamp is None else int(timestamp))
    if key in store:
        return False
    store[key] = int(timestamp) if timestamp is not None else (int(now) if now is not None else 0)
    return True
