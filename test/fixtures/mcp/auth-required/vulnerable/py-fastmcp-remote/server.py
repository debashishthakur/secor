from mcp.server.fastmcp import FastMCP

mcp = FastMCP("notes", host="0.0.0.0", port=8000)


@mcp.tool()
def list_notes(folder: str) -> str:
    """List the notes in a folder."""
    return f"notes in {folder}"


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
