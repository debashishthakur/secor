from mcp.server.fastmcp import FastMCP, Context

mcp = FastMCP("demo")

@mcp.tool()
def read_file(path: str, ctx: Context) -> str:
    return open(path).read()

@mcp.tool(name="search_notes")
async def search(query: str, limit: int = 10) -> list[str]:
    return []

@mcp.resource("notes://{name}")
def note(name: str) -> str:
    return name

@mcp.prompt()
def review(code: str) -> str:
    return code

if __name__ == "__main__":
    mcp.run(transport="streamable-http")
