import tempfile
import unittest
from email.message import Message
from pathlib import Path
from unittest.mock import Mock, patch

import main


def saved_filename(content_disposition: str) -> str | None:
    """Filename an RFC 6266 client saves as (filename* takes precedence)."""
    message = Message()
    message["Content-Disposition"] = content_disposition
    return message.get_filename()


class DownloadFilenameTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(temp_dir.cleanup)
        self.upload_dir = Path(temp_dir.name)
        for patcher in (
            patch.object(main, "UPLOAD_DIR", self.upload_dir),
            patch.object(main, "record"),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    async def content_disposition_for(self, filename: str) -> str:
        (self.upload_dir / filename).write_bytes(b"contents")

        response = await main.download(Mock(), filename, Mock())

        self.assertEqual(response.status_code, 200)
        return response.headers["content-disposition"]

    async def test_plain_name_is_sent_unchanged(self):
        header = await self.content_disposition_for("report.pdf")

        self.assertEqual(header, 'attachment; filename="report.pdf"')

    async def test_name_with_space_is_not_saved_percent_encoded(self):
        header = await self.content_disposition_for("my report.pdf")

        self.assertTrue(header.startswith("attachment;"), header)
        self.assertEqual(saved_filename(header), "my report.pdf")

    async def test_non_ascii_name_round_trips(self):
        header = await self.content_disposition_for("résumé.pdf")

        self.assertTrue(header.startswith("attachment;"), header)
        self.assertTrue(header.isascii(), header)
        self.assertEqual(saved_filename(header), "résumé.pdf")

    async def test_name_with_double_quote_round_trips(self):
        header = await self.content_disposition_for('say "hi".txt')

        self.assertTrue(header.startswith("attachment;"), header)
        self.assertEqual(saved_filename(header), 'say "hi".txt')


if __name__ == "__main__":
    unittest.main()
