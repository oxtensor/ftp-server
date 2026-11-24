import tempfile
import unittest
from html.parser import HTMLParser
from pathlib import Path
from unittest.mock import Mock, patch
from urllib.parse import quote, unquote, urlsplit

import main
from db import get_db

TRICKY_NAMES = [
    "a#b?.txt",
    "a%41.txt",
    "my report.pdf",
    "résumé.pdf",
    'say "hi".txt',
    "x');alert(document.domain);('.txt",
]


class FileTableParser(HTMLParser):
    """Collect file links and delete forms with attributes decoded as a browser would."""

    def __init__(self):
        super().__init__()
        self.links = []
        self.delete_forms = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "a" and attrs.get("href", "").startswith("/files/"):
            self.links.append(attrs["href"])
        elif tag == "form" and attrs.get("action", "").startswith("/delete/"):
            self.delete_forms.append(attrs)


def parse_file_table(html: str) -> FileTableParser:
    parser = FileTableParser()
    parser.feed(html)
    parser.close()
    return parser


class IndexTemplateTests(unittest.TestCase):
    def render(self, names):
        files = [{"name": name, "size": 1, "modified": "-"} for name in names]
        html = main.templates.get_template("index.html").render(
            request=None, user="alice", files=files
        )
        return parse_file_table(html)

    def test_links_and_delete_actions_encode_the_name_as_a_path_segment(self):
        table = self.render(TRICKY_NAMES)

        expected = [quote(name, safe="") for name in TRICKY_NAMES]
        self.assertEqual(table.links, ["/files/" + e for e in expected])
        self.assertEqual(
            [form["action"] for form in table.delete_forms],
            ["/delete/" + e for e in expected],
        )
        for href in table.links:
            self.assertEqual(urlsplit(href).fragment, "")
            self.assertEqual(urlsplit(href).query, "")

    def test_delete_confirmation_does_not_splice_the_name_into_script(self):
        table = self.render(TRICKY_NAMES)

        handlers = {form["onsubmit"] for form in table.delete_forms}
        self.assertEqual(len(handlers), 1, handlers)
        handler = handlers.pop()
        self.assertNotIn("alert", handler)
        self.assertEqual(
            [form["data-name"] for form in table.delete_forms], TRICKY_NAMES
        )


class FileLinkRequestTests(unittest.IsolatedAsyncioTestCase):
    """Follow the rendered links the way a browser would, through the ASGI app."""

    def setUp(self):
        temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(temp_dir.cleanup)
        root = Path(temp_dir.name).resolve()
        self.upload_dir = root / "uploads"
        self.upload_dir.mkdir()
        self.outside_file = root / "secret.txt"
        self.outside_file.write_bytes(b"outside the upload dir")

        for patcher in (
            patch.object(main, "UPLOAD_DIR", self.upload_dir),
            patch.object(main, "record"),
            # Simulate a logged-in session for the index page and /delete.
            patch.object(main, "current_user", return_value="alice"),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

        def override_get_db():
            yield Mock()

        main.app.dependency_overrides[get_db] = override_get_db
        self.addCleanup(main.app.dependency_overrides.pop, get_db, None)

    async def browser_request(self, method, url):
        """Send `url` the way a browser does: drop the fragment, send the query
        separately, and let the server percent-decode the path (as uvicorn does)."""
        parts = urlsplit(url)
        scope = {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": method,
            "scheme": "http",
            "path": unquote(parts.path),
            "raw_path": parts.path.encode(),
            "query_string": parts.query.encode(),
            "root_path": "",
            "headers": [],
            "client": ("127.0.0.1", 40000),
            "server": ("127.0.0.1", 3050),
        }
        incoming = [{"type": "http.request", "body": b"", "more_body": False}]
        sent = []

        async def receive():
            return incoming.pop(0) if incoming else {"type": "http.disconnect"}

        async def send(message):
            sent.append(message)

        await main.app(scope, receive, send)
        status = sent[0]["status"]
        body = b"".join(m.get("body", b"") for m in sent[1:])
        return status, body

    async def test_download_and_delete_name_with_hash_and_question_mark(self):
        name = "a#b?.txt"
        contents = b"hash and question mark"
        (self.upload_dir / name).write_bytes(contents)

        status, page = await self.browser_request("GET", "/")
        self.assertEqual(status, 200)
        table = parse_file_table(page.decode())
        [href] = table.links
        [form] = table.delete_forms

        status, body = await self.browser_request("GET", href)
        self.assertEqual(status, 200)
        self.assertEqual(body, contents)

        status, _ = await self.browser_request("POST", form["action"])
        self.assertEqual(status, 303)
        self.assertFalse((self.upload_dir / name).exists())

    async def test_encoded_traversal_is_still_rejected(self):
        for method, url in (
            ("GET", "/files/%2E%2E"),
            ("POST", "/delete/%2E%2E"),
            ("GET", "/files/%2E%2E%2Fsecret.txt"),
            ("POST", "/delete/%2E%2E%2Fsecret.txt"),
        ):
            with self.subTest(method=method, url=url):
                status, body = await self.browser_request(method, url)

                self.assertIn(status, (400, 404))
                self.assertNotIn(b"outside the upload dir", body)

        self.assertTrue(self.outside_file.exists())


if __name__ == "__main__":
    unittest.main()
