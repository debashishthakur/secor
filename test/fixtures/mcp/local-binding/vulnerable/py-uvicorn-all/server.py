import os

import uvicorn
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("desktop-notes")


@mcp.tool()
def ping() -> str:
    """Health check."""
    return "pong"


if __name__ == "__main__":
    uvicorn.run(mcp.streamable_http_app(), host=os.environ.get("HOST", "0.0.0.0"), port=8765)
