import unittest
from unittest.mock import MagicMock, patch
from urllib.error import URLError

from tools import install_temporal


class InstallTemporalTests(unittest.TestCase):
    def test_retries_timeout_before_headers_or_during_download(self) -> None:
        for failed_download in (TimeoutError(), URLError(TimeoutError()), MagicMock()):
            with self.subTest(failure=type(failed_download).__name__):
                if isinstance(failed_download, MagicMock):
                    failed_download.__enter__.return_value.read.side_effect = TimeoutError()
                response = MagicMock()
                response.__enter__.return_value.read.return_value = b"archive"
                with (
                    patch.object(
                        install_temporal.urllib.request,
                        "urlopen",
                        side_effect=[failed_download, response],
                    ) as download,
                    patch.object(install_temporal.platform, "system", return_value="Linux"),
                    patch.object(install_temporal.platform, "machine", return_value="x86_64"),
                ):
                    with self.assertRaisesRegex(ValueError, "TEMPORAL_CLI_DIGEST_MISMATCH"):
                        install_temporal.main()
                self.assertEqual(download.call_count, 2)

    def test_persistent_timeout_is_bounded(self) -> None:
        with (
            patch.object(
                install_temporal.urllib.request, "urlopen", side_effect=TimeoutError
            ) as download,
            patch.object(install_temporal.platform, "system", return_value="Linux"),
            patch.object(install_temporal.platform, "machine", return_value="x86_64"),
        ):
            with self.assertRaises(TimeoutError):
                install_temporal.main()
        self.assertEqual(download.call_count, 3)
