from __future__ import annotations

import http.server
import threading
from os.path import exists
from socket import AF_INET, SOCK_STREAM, socket
from socket import timeout as SocketTimeout
from ssl import PROTOCOL_TLS_SERVER, SSLContext, SSLError
from time import sleep

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
    s.settimeout(5)

    i = 0

    while True:
        try:
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

            break
        except (
            ConnectionResetError,
            ConnectionRefusedError,
            TimeoutError,
            SocketTimeout,
        ):
            i += 1
            if i >= 15:
                assert False

            s.close()
            s = socket(AF_INET, SOCK_STREAM)
            s = ctx.wrap_socket(s, server_hostname=host)
            s.settimeout(1)

            continue

    s.close()


def serve(server: http.server.HTTPServer):
    context = SSLContext(PROTOCOL_TLS_SERVER)
    context.load_cert_chain(
        certfile="./example.test.pem", keyfile="./example.test-key.pem"
    )

    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


@pytest.mark.skipif(not exists("./example.test.pem"), reason="test requires mkcert")
def test_ctx_access_local_trusted_root() -> None:
    ctx = create_default_ssl_context()

    server_address = ("127.0.0.1", 47476)
    httpd = http.server.HTTPServer(server_address, http.server.SimpleHTTPRequestHandler)

    t = threading.Thread(target=serve, args=(httpd,))
    t.daemon = True
    t.start()

    s = socket(AF_INET, SOCK_STREAM)
    s = ctx.wrap_socket(s, server_hostname="example.test")
    s.settimeout(5)

    i = 0

    while True:
        sleep(1)

        if i >= 10:
            assert False

        try:
            s.connect(("127.0.0.1", 47476))
        except (ConnectionError, TimeoutError, SocketTimeout):
            i += 1
            s.close()
            s = socket(AF_INET, SOCK_STREAM)
            s = ctx.wrap_socket(s, server_hostname="example.test")
            s.settimeout(5)
        except SSLError as e:
            if "timeout" in str(e):
                s.close()
                s = socket(AF_INET, SOCK_STREAM)
                s = ctx.wrap_socket(s, server_hostname="example.test")
                s.settimeout(5)
                continue
            assert False
        else:
            break

    assert s.getpeercert() is not None
    s.close()

    httpd.shutdown()
