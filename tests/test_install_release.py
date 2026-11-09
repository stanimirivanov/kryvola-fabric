import hashlib
import io
import tempfile
import unittest
from email.message import Message
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError, URLError

from tools import install_release

URL = "https://example.invalid/tool"
PAYLOAD = b"pinned tool"
DIGEST = hashlib.sha256(PAYLOAD).hexdigest()


def http_error(status: int) -> HTTPError:
    return HTTPError(URL, status, "fixture failure", Message(), io.BytesIO())


class InstallReleaseTests(unittest.TestCase):
    def test_transient_errors_retry_and_install_verified_bytes(self):
        for failure in (http_error(504), TimeoutError(), URLError(TimeoutError())):
            with (
                self.subTest(failure=type(failure).__name__),
                tempfile.TemporaryDirectory() as directory,
                patch.object(install_release, "ROOT", Path(directory)),
                patch.dict(install_release.PINS, {"cosign": (URL, DIGEST, DIGEST)}, clear=True),
                patch.object(install_release.platform, "system", return_value="Linux"),
                patch.object(install_release.platform, "machine", return_value="x86_64"),
                patch.object(
                    install_release.urllib.request,
                    "urlopen",
                    side_effect=[failure, io.BytesIO(PAYLOAD)],
                ) as download,
            ):
                install_release.main()
                self.assertEqual(install_release.tool("cosign").read_bytes(), PAYLOAD)
                self.assertEqual(download.call_count, 2)
                self.assertEqual(download.call_args_list[0].args, (URL,))
                self.assertTrue(
                    download.call_args_list[1].args[0].startswith(URL + "?download=1&retry=")
                )

    def test_persistent_gateway_failure_stops_and_permanent_errors_do_not_retry(self):
        for status, count in ((504, 3), (404, 1)):
            with (
                self.subTest(status=status),
                patch.object(
                    install_release.urllib.request, "urlopen", side_effect=http_error(status)
                ) as download,
            ):
                with self.assertRaises(HTTPError):
                    install_release.download(URL)
                self.assertEqual(download.call_count, count)

    def test_digest_mismatch_is_not_retried_or_installed(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.object(install_release, "ROOT", Path(directory)),
            patch.dict(install_release.PINS, {"cosign": (URL, DIGEST, DIGEST)}, clear=True),
            patch.object(install_release.platform, "system", return_value="Linux"),
            patch.object(install_release.platform, "machine", return_value="x86_64"),
            patch.object(
                install_release.urllib.request, "urlopen", return_value=io.BytesIO(b"wrong")
            ) as download,
        ):
            with self.assertRaisesRegex(ValueError, "RELEASE_TOOL_DOWNLOAD"):
                install_release.main()
            self.assertEqual(download.call_count, 1)
            self.assertFalse((Path(directory) / "build").exists())
