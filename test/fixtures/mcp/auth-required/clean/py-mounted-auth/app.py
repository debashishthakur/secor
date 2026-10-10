import os

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.responses import JSONResponse
from starlette.routing import Mount

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("notes")


@mcp.tool()
def list_notes(folder: str) -> str:
    """List the notes in a folder."""
    return f"notes in {folder}"


class BearerTokenMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            headers = dict(scope["headers"])
            if headers.get(b"authorization") != f"Bearer {os.environ['NOTES_TOKEN']}".encode():
                await JSONResponse({"error": "unauthorized"}, status_code=401)(scope, receive, send)
                return
        await self.app(scope, receive, send)


app = Starlette(
    routes=[Mount("/", app=mcp.streamable_http_app())],
    middleware=[Middleware(BearerTokenMiddleware)],
)
