"""Локальный статический сервер для разработки FlowGuard.

Запуск из корня проекта:  python scripts/serve.py [порт]
Открыть: http://127.0.0.1:8000/
"""

import http.server
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent


class Handler(http.server.SimpleHTTPRequestHandler):
    extensions_map = {
        **http.server.SimpleHTTPRequestHandler.extensions_map,
        ".js": "text/javascript; charset=utf-8",
        ".mjs": "text/javascript; charset=utf-8",
        ".css": "text/css; charset=utf-8",
        ".html": "text/html; charset=utf-8",
        ".svg": "image/svg+xml",
        ".json": "application/json; charset=utf-8",
        ".webmanifest": "application/manifest+json",
        ".pcap": "application/vnd.tcpdump.pcap",
        ".pcapng": "application/octet-stream",
        ".csv": "text/csv; charset=utf-8",
        ".ndjson": "application/x-ndjson",
        ".txt": "text/plain; charset=utf-8",
    }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT), **kwargs)

    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        super().end_headers()


def main() -> None:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    with http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler) as server:
        print(f"FlowGuard: http://127.0.0.1:{port}/  (Ctrl+C — остановить)")
        server.serve_forever()


if __name__ == "__main__":
    main()
