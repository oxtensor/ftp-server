# File Server (FastAPI)

HTTP file server with a custom HTML UI.

- **Public download** — anyone can list and download files at `/`.
- **Authenticated upload/delete** — must log in first.
- **Authenticated log viewer** — `/logs` shows recent activity.

> Note: this serves files over HTTP, not the FTP protocol. Use a browser, `curl`, or `wget` — not an FTP client.

## Run

```powershell
pip install -r requirements.txt
python main.py
```

Open http://localhost:8000

Default credentials: `admin` / `admin123` (change `USERS` in `main.py`).

## Layout

- `main.py` — FastAPI app (routes, auth, logging)
- `templates/` — Jinja2 HTML pages
- `static/style.css` — styling
- `uploads/` — uploaded files (auto-created)
- `server.log` — activity log
