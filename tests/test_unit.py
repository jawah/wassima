from __future__ import annotations

import time
from typing import Iterator

import pytest

import wassima
from wassima import (
    DEFAULT_CACHE_TTL_SECONDS,
    generate_ca_bundle,
    register_ca,
    root_der_certificates,
    root_pem_certificates,
    set_cache_ttl,
)
from wassima._os._embed import root_der_certificates as fallback_der_certificates


@pytest.fixture(autouse=True)
def _reset_caches() -> Iterator[None]:
    """Make sure each test starts on a clean slate."""
    wassima._MANUALLY_REGISTERED_CA.clear()
    root_der_certificates.cache_clear()
    root_pem_certificates.cache_clear()
    # Restore the default TTL after each test in case one mutated it.
    yield
    set_cache_ttl(DEFAULT_CACHE_TTL_SECONDS)
    wassima._MANUALLY_REGISTERED_CA.clear()
    root_der_certificates.cache_clear()
    root_pem_certificates.cache_clear()


def test_no_duplicate_der() -> None:
    certs = root_der_certificates()
    assert len(certs) == len(set(certs))


def test_register_ca_does_not_introduce_duplicate(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """A CA already present in the OS bundle must not be appended twice when
    the user also registers it via ``register_ca``."""
    sample = fallback_der_certificates()[0]

    # Make the OS layer expose `sample` exactly once (each OS backend is
    # contracted to return a deduplicated list, so we don't need to fake a
    # buggy backend here).
    monkeypatch.setattr("wassima._root_der_certificates", lambda: [sample])
    root_der_certificates.cache_clear()

    register_ca(sample)
    certs = root_der_certificates()
    assert certs.count(sample) == 1


def test_hybrid_store_does_not_introduce_duplicate(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """When the OS bundle and the embedded CCADB bundle overlap (which is
    the common case), ``hybrid_store=True`` must not duplicate the shared
    roots."""
    embed = fallback_der_certificates()
    overlapping = embed[0]
    monkeypatch.setattr("wassima._root_der_certificates", lambda: [overlapping])
    root_der_certificates.cache_clear()

    out = root_der_certificates(hybrid_store=True)
    assert out.count(overlapping) == 1
    assert len(out) == len(set(out))


def test_hybrid_store_merges_ccadb(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    sample = b"\x01\x02\x03not-a-real-cert"
    monkeypatch.setattr("wassima._root_der_certificates", lambda: [sample])

    # Without hybrid_store: only the OS-provided cert.
    root_der_certificates.cache_clear()
    assert root_der_certificates(hybrid_store=False) == [sample]

    # With hybrid_store: includes embedded CCADB roots too.
    embed = fallback_der_certificates()
    out = root_der_certificates(hybrid_store=True)
    assert sample in out
    for c in embed:
        assert c in out
    # Still no duplicates.
    assert len(out) == len(set(out))


def test_hybrid_store_propagates_through_pem_and_bundle(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    sample = b"\x10not-real"
    monkeypatch.setattr("wassima._root_der_certificates", lambda: [sample])
    root_der_certificates.cache_clear()
    root_pem_certificates.cache_clear()

    # generate_ca_bundle() with hybrid -> at least as long as without.
    bundle_plain = generate_ca_bundle(hybrid_store=False)
    bundle_hybrid = generate_ca_bundle(hybrid_store=True)
    assert len(bundle_hybrid) > len(bundle_plain)

    pem_hybrid = root_pem_certificates(hybrid_store=True)
    assert len(pem_hybrid) >= 1


def test_create_default_ssl_context_hybrid() -> None:
    ctx = wassima.create_default_ssl_context(hybrid_store=True)
    # At least the embedded CCADB bundle should be loaded.
    stats = ctx.cert_store_stats()
    assert stats["x509_ca"] >= 1


def test_set_cache_ttl_invalid() -> None:
    with pytest.raises(ValueError):
        set_cache_ttl(-1)


def test_set_cache_ttl_zero_disables_cache(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    calls = {"n": 0}

    def fake_os_certs() -> list[bytes]:
        calls["n"] += 1
        return [b"\xaa"]

    monkeypatch.setattr("wassima._root_der_certificates", fake_os_certs)

    set_cache_ttl(0)
    root_der_certificates()
    root_der_certificates()
    # TTL of zero -> every call recomputes.
    assert calls["n"] >= 2


def test_cache_expires_after_ttl(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    calls = {"n": 0}

    def fake_os_certs() -> list[bytes]:
        calls["n"] += 1
        return [b"\xbb"]

    monkeypatch.setattr("wassima._root_der_certificates", fake_os_certs)

    # Use a virtual clock to deterministically jump past the TTL.
    fake_now = {"t": 1000.0}
    monkeypatch.setattr(
        "wassima.time.monotonic",
        lambda: fake_now["t"],
    )

    set_cache_ttl(10)
    root_der_certificates()
    initial = calls["n"]

    # Within TTL -> cached.
    fake_now["t"] += 5
    root_der_certificates()
    assert calls["n"] == initial

    # Past TTL -> recomputed.
    fake_now["t"] += 100
    root_der_certificates()
    assert calls["n"] == initial + 1


def test_linux_stale_trust_store_implicitly_merges(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    # Force the wassima top-level to take the Linux/BSD branch even on
    # platforms where it would not naturally.
    monkeypatch.setattr("wassima.IS_LINUX", True)
    monkeypatch.setattr("wassima.IS_BSD", False)

    sample = b"\x42single-os-cert"
    monkeypatch.setattr("wassima._root_der_certificates", lambda: [sample])

    from wassima._os import _linux as linux_mod

    monkeypatch.setattr(linux_mod, "is_trust_store_stale", lambda *a, **kw: True)
    root_der_certificates.cache_clear()

    certs = root_der_certificates()

    # Stale -> CCADB bundle was merged in even without hybrid_store=True.
    embed = fallback_der_certificates()
    for c in embed:
        assert c in certs


def test_is_trust_store_stale_helper(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from wassima._os import _linux as linux_mod

    # When no mtime has been collected -> never considered stale.
    monkeypatch.setattr(linux_mod, "_LAST_NEWEST_MTIME", None)
    assert linux_mod.is_trust_store_stale() is False

    # A mtime older than the threshold -> stale.
    monkeypatch.setattr(
        linux_mod,
        "_LAST_NEWEST_MTIME",
        time.time() - linux_mod.STALE_TRUST_STORE_THRESHOLD_SECONDS - 1,
    )
    assert linux_mod.is_trust_store_stale() is True

    # A recent mtime -> not stale.
    monkeypatch.setattr(linux_mod, "_LAST_NEWEST_MTIME", time.time())
    assert linux_mod.is_trust_store_stale() is False


def test_cache_concurrent_access_collapses_misses(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """Under contention at the TTL boundary, only one thread should recompute
    for a given key (single-lock design, no thundering herd)."""
    import threading

    calls = {"n": 0}
    started = threading.Event()

    def slow_os_certs() -> list[bytes]:
        calls["n"] += 1
        # Yield so other threads have a chance to pile up if locking is wrong.
        started.wait(timeout=0.5)
        return [b"\xcc"]

    monkeypatch.setattr("wassima._root_der_certificates", slow_os_certs)
    set_cache_ttl(60)
    root_der_certificates.cache_clear()

    threads = [threading.Thread(target=root_der_certificates) for _ in range(8)]
    for t in threads:
        t.start()
    started.set()
    for t in threads:
        t.join()

    assert calls["n"] == 1

