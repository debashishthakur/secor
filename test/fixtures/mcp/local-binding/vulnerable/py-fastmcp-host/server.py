from mcp.server.fastmcp import FastMCP

mcp = FastMCP("desktop-notes", host="0.0.0.0", port=8765)


@mcp.tool()
def ping() -> str:
    """Health check."""
    return "pong"


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
