from __future__ import annotations

from socket import AF_INET, SOCK_STREAM, socket
from ssl import SSLError

import pytest

from wassima import create_default_ssl_context


@pytest.mark.parametrize(
    "host, port, expect_failure",
    [
        ("1.1.1.1", 443, False),
        ("google.com", 443, False),
        (
            "self-signed.badssl.com",
            443,
            True,
        ),
        (
            "untrusted-root.badssl.com",
            443,
            True,
        ),
        (
            "tls-v1-2.badssl.com",
            1012,
            False,
        ),
        (
            "sha1-intermediate.badssl.com",
            443,
            True,
        ),
        ("one.one.one.one", 443, False),
        ("edellroot.badssl.com", 443, True),
        ("developer.mozilla.org", 443, False),
        ("letsencrypt.org", 443, False),
    ],
)
def test_ctx_use_system_store(host: str, port: int, expect_failure: bool) -> None:
    ctx = create_default_ssl_context()

    s = socket(AF_INET, SOCK_STREAM)
    s = ctx.wrap_socket(s, server_hostname=host)

    if expect_failure:
        with pytest.raises(SSLError) as exc:
            s.connect((host, port))
        ssl_err = exc.value.args[1]
        assert (
            "self-signed" in ssl_err
            or "self signed" in ssl_err
            or "unable to get local issuer certificate" in ssl_err
        )
    else:
        s.connect((host, port))
        assert s.getpeercert() is not None

    s.close()
