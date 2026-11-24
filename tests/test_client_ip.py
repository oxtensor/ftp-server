import unittest
from urllib.parse import urlencode

from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from starlette.requests import Request
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

import main
from db import ActivityLog, Base, get_db

SPOOFED_IP = "6.6.6.6"


def make_scope(method, path, *, client, headers=()):
    return {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": method,
        "scheme": "http",
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "root_path": "",
        "headers": [
            (name.lower().encode("latin-1"), value.encode("latin-1"))
            for name, value in headers
        ],
        "client": client,
        "server": ("127.0.0.1", 3050),
    }


class ClientIpTests(unittest.TestCase):
    def test_forwarded_for_header_is_not_trusted_on_its_own(self):
        request = Request(
            make_scope(
                "GET",
                "/",
                client=("198.51.100.5", 51515),
                headers=[("X-Forwarded-For", SPOOFED_IP)],
            )
        )

        self.assertEqual(main.client_ip(request), "198.51.100.5")

    def test_missing_client_address_is_reported_as_unknown(self):
        request = Request(make_scope("GET", "/", client=None))

        self.assertEqual(main.client_ip(request), "?")


class ActivityLogIpTests(unittest.IsolatedAsyncioTestCase):
    """Drive the app the way uvicorn serves it: behind its default
    ProxyHeadersMiddleware, which trusts X-Forwarded-For only from 127.0.0.1."""

    def setUp(self):
        engine = create_engine(
            "sqlite://",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(engine)
        self.addCleanup(engine.dispose)
        self.Session = sessionmaker(bind=engine, autoflush=False, autocommit=False)

        def override_get_db():
            db = self.Session()
            try:
                yield db
            finally:
                db.close()

        main.app.dependency_overrides[get_db] = override_get_db
        self.addCleanup(main.app.dependency_overrides.pop, get_db, None)
        self.server = ProxyHeadersMiddleware(main.app, trusted_hosts="127.0.0.1")

    async def failed_login(self, *, client, forwarded_for):
        body = urlencode({"username": "nobody", "password": "wrong"}).encode()
        scope = make_scope(
            "POST",
            "/login",
            client=client,
            headers=[
                ("Content-Type", "application/x-www-form-urlencoded"),
                ("Content-Length", str(len(body))),
                ("X-Forwarded-For", forwarded_for),
            ],
        )
        incoming = [{"type": "http.request", "body": body, "more_body": False}]
        sent = []

        async def receive():
            return incoming.pop(0) if incoming else {"type": "http.disconnect"}

        async def send(message):
            sent.append(message)

        await self.server(scope, receive, send)
        self.assertEqual(sent[0]["status"], 303)

    def logged_ips(self):
        with self.Session() as db:
            return db.scalars(
                select(ActivityLog.ip).where(ActivityLog.event == "LOGIN_FAIL")
            ).all()

    async def test_spoofed_forwarded_for_behind_local_proxy_logs_real_client(self):
        # A local reverse proxy (e.g. nginx with $proxy_add_x_forwarded_for)
        # appends the real peer address to whatever the client sent.
        await self.failed_login(
            client=("127.0.0.1", 40000),
            forwarded_for=f"{SPOOFED_IP}, 203.0.113.7",
        )

        self.assertEqual(self.logged_ips(), ["203.0.113.7"])

    async def test_spoofed_forwarded_for_from_direct_client_logs_peer(self):
        await self.failed_login(
            client=("198.51.100.5", 51515),
            forwarded_for=SPOOFED_IP,
        )

        self.assertEqual(self.logged_ips(), ["198.51.100.5"])


if __name__ == "__main__":
    unittest.main()
