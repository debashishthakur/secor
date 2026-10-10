from mcp.server.fastmcp import FastMCP

mcp = FastMCP("desktop-notes")


@mcp.tool()
def ping() -> str:
    """Health check."""
    return "pong"


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
