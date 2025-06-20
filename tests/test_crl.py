import sys

import pytest

from wassima import certificate_revocation_lists_der

IS_WINDOWS = sys.platform == "win32"
IS_MACOS = sys.platform == "darwin"


@pytest.mark.skipif(not (IS_WINDOWS or IS_MACOS), reason="test requires Windows or MacOS")
def test_crl_are_fetched() -> None:
    assert len(certificate_revocation_lists_der()) > 1


@pytest.mark.skipif(IS_WINDOWS or IS_MACOS, reason="test requires not Windows and not MacOS")
def test_crl_are_not_fetched() -> None:
    assert not certificate_revocation_lists_der()
