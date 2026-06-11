"""
Secure static server for the local SecureMeet lab page.

The default Python http.server is useful for quick testing, but it does not
emit the browser security headers that OWASP ZAP checks. This wrapper keeps the
same static-file behavior while adding the headers used in the final report.
"""
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from os import PathLike
from pathlib import Path
import argparse


SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; "
        "base-uri 'self'; "
        "object-src 'none'; "
        "frame-ancestors 'none'; "
        "frame-src https://meet.jit.si; "
        "connect-src 'self' https://meet.jit.si wss://meet.jit.si; "
        "img-src 'self' data: https://meet.jit.si; "
        "style-src 'self'; "
        "script-src 'self'; "
        "form-action 'self'"
    ),
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": (
        'camera=(self "https://meet.jit.si"), '
        'microphone=(self "https://meet.jit.si"), '
        'fullscreen=(self "https://meet.jit.si"), '
        'display-capture=(self "https://meet.jit.si"), '
        "geolocation=(), payment=(), usb=()"
    ),
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Embedder-Policy": "credentialless",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Cache-Control": "no-store",
    "Pragma": "no-cache",
}


class SecureStaticHandler(SimpleHTTPRequestHandler):
    """SimpleHTTPRequestHandler with explicit security headers."""

    def version_string(self) -> str:
        return "SecureMeetLab"

    def guess_type(self, path: str | PathLike[str]) -> str:
        content_type = super().guess_type(path)
        if content_type in {"text/html", "text/css", "text/javascript", "application/javascript"}:
            return f"{content_type}; charset=utf-8"
        return content_type

    def end_headers(self) -> None:
        for name, value in SECURITY_HEADERS.items():
            self.send_header(name, value)
        super().end_headers()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Serve SecureMeet with security headers.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8082)
    parser.add_argument(
        "--directory",
        type=Path,
        default=Path(__file__).resolve().parent,
        help="Static file directory to serve.",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    directory = args.directory.resolve()
    if not directory.is_dir():
        raise SystemExit(f"Static directory does not exist: {directory}")
    if not 1 <= args.port <= 65535:
        raise SystemExit("Port must be between 1 and 65535")

    handler = partial(SecureStaticHandler, directory=str(directory))

    with ThreadingHTTPServer((args.host, args.port), handler) as server:
        print(f"Serving {directory} at http://{args.host}:{args.port}/")
        server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
