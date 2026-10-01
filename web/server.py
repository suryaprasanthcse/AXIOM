"""Serves the AXIOM arena page from Lambda behind the HTTP API.

The page and the arena API share the API Gateway invoke URL as one origin,
so the browser makes same-origin requests and no CORS is needed. Only the
three files below are ever served.
"""

from pathlib import Path

HERE = Path(__file__).resolve().parent

PAGES = {
    "/": ("index.html", "text/html; charset=utf-8", "no-cache"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8", "public, max-age=300"),
    "/style.css": ("style.css", "text/css; charset=utf-8", "public, max-age=300"),
}
BODIES = {route: (HERE / name).read_text(encoding="utf-8") for route, (name, _, _) in PAGES.items()}

SECURITY_HEADERS = {
    "content-security-policy": (
        "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
        "img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
    ),
    "strict-transport-security": "max-age=31536000",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "no-referrer",
}


def handler(event, context):
    route = event.get("rawPath") or "/"
    if route not in PAGES:
        return {"statusCode": 404, "headers": {"content-type": "text/plain"}, "body": "not found"}
    _, content_type, cache = PAGES[route]
    return {
        "statusCode": 200,
        "headers": {"content-type": content_type, "cache-control": cache, **SECURITY_HEADERS},
        "body": BODIES[route],
    }
