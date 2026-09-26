"""
demo_app/app.py — Minimal stdlib HTTP to-do API.

Routes:
  GET    /todos          Return all to-do items as JSON.
  POST   /todos          Create a new item.  Body: {"title": "..."}
  DELETE /todos/<id>     Delete item by integer id.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

_store: dict[int, dict] = {}
_next_id: int = 1
_lock = threading.Lock()


# ---------------------------------------------------------------------------
# Business logic (testable without HTTP)
# ---------------------------------------------------------------------------


def list_todos() -> list[dict]:
    with _lock:
        return list(_store.values())


def create_todo(title: str) -> dict:
    global _next_id
    with _lock:
        item = {"id": _next_id, "title": title, "done": False}
        _store[_next_id] = item
        _next_id += 1
        return item


def delete_todo(todo_id: int) -> bool:
    with _lock:
        if todo_id in _store:
            del _store[todo_id]
            return True
        return False


def reset_store() -> None:
    """Test helper — clears all items and resets the id counter."""
    global _next_id
    with _lock:
        _store.clear()
        _next_id = 1


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------

_JSON = "application/json"


class TodoHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:
        pass  # suppress access-log noise

    def _send(self, code: int, body: object) -> None:
        payload = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", _JSON)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _read_body(self) -> dict:
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length)
        return json.loads(raw) if raw else {}

    def do_GET(self) -> None:
        if self.path == "/todos":
            self._send(200, list_todos())
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self) -> None:
        if self.path == "/todos":
            body = self._read_body()
            title = body.get("title", "").strip()
            if not title:
                self._send(400, {"error": "title required"})
                return
            self._send(201, create_todo(title))
        else:
            self._send(404, {"error": "not found"})

    def do_DELETE(self) -> None:
        prefix = "/todos/"
        if self.path.startswith(prefix):
            try:
                todo_id = int(self.path[len(prefix):])
            except ValueError:
                self._send(400, {"error": "invalid id"})
                return
            if delete_todo(todo_id):
                self._send(200, {"deleted": todo_id})
            else:
                self._send(404, {"error": "not found"})
        else:
            self._send(404, {"error": "not found"})


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def make_server(host: str = "127.0.0.1", port: int = 8080) -> HTTPServer:
    return HTTPServer((host, port), TodoHandler)


if __name__ == "__main__":
    server = make_server()
    print("Serving on http://127.0.0.1:8080 — Ctrl-C to stop")
    server.serve_forever()
