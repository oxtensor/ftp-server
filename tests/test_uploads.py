import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from fastapi import HTTPException
from starlette.datastructures import UploadFile

import main


class FailingUpload(UploadFile):
    """Return one chunk, then simulate a client/stream read failure."""

    def __init__(self, filename: str):
        super().__init__(io.BytesIO(), filename=filename)
        self.read_calls = 0

    async def read(self, size: int = -1) -> bytes:
        self.read_calls += 1
        if self.read_calls == 1:
            return b"partial contents"
        raise OSError("simulated upload failure")


class UploadTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.upload_dir = Path(self.temp_dir.name)
        self.upload_dir_patcher = patch.object(main, "UPLOAD_DIR", self.upload_dir)
        self.record_patcher = patch.object(main, "record")
        self.upload_dir_patcher.start()
        self.record = self.record_patcher.start()
        self.request = Mock()
        self.db = Mock()

    def tearDown(self):
        self.record_patcher.stop()
        self.upload_dir_patcher.stop()
        self.temp_dir.cleanup()

    async def test_successful_upload_replaces_existing_file(self):
        target = self.upload_dir / "report.txt"
        target.write_bytes(b"old contents that are longer")
        contents = b"new contents"
        upload = UploadFile(io.BytesIO(contents), filename="report.txt")

        response = await main.upload(self.request, upload, "alice", self.db)

        self.assertEqual(response.status_code, 303)
        self.assertEqual(target.read_bytes(), contents)
        self.assertEqual([target], list(self.upload_dir.iterdir()))
        self.assertTrue(upload.file.closed)
        self.record.assert_called_once_with(
            self.db,
            self.request,
            "UPLOAD",
            username="alice",
            filename="report.txt",
            size=len(contents),
        )

    async def test_failed_upload_preserves_existing_file_and_cleans_up(self):
        target = self.upload_dir / "report.txt"
        original = b"original contents"
        target.write_bytes(original)
        upload = FailingUpload("report.txt")

        with self.assertRaisesRegex(OSError, "simulated upload failure"):
            await main.upload(self.request, upload, "alice", self.db)

        self.assertEqual(target.read_bytes(), original)
        self.assertEqual([target], list(self.upload_dir.iterdir()))
        self.assertTrue(upload.file.closed)
        self.record.assert_not_called()

    async def test_failed_new_upload_leaves_no_file(self):
        upload = FailingUpload("new.txt")

        with self.assertRaisesRegex(OSError, "simulated upload failure"):
            await main.upload(self.request, upload, "alice", self.db)

        self.assertEqual([], list(self.upload_dir.iterdir()))
        self.record.assert_not_called()

    async def test_invalid_filenames_are_rejected(self):
        for filename in ("", ".", "..", "../", "bad\x00name.txt"):
            with self.subTest(filename=filename):
                upload = UploadFile(io.BytesIO(b"contents"), filename=filename)

                with self.assertRaises(HTTPException) as raised:
                    await main.upload(self.request, upload, "alice", self.db)

                self.assertEqual(raised.exception.status_code, 400)
                self.assertTrue(upload.file.closed)

        self.assertEqual([], list(self.upload_dir.iterdir()))
        self.record.assert_not_called()


if __name__ == "__main__":
    unittest.main()
