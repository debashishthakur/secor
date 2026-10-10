import httpx
from mcp.server.fastmcp import Context, FastMCP

mcp = FastMCP("calendar")


@mcp.tool()
async def list_events(day: str, ctx: Context) -> str:
    """List calendar events for a day."""
    request = ctx.request_context.request
    token = request.headers.get("authorization")
    async with httpx.AsyncClient() as client:
        resp = await client.get(f"https://calendar.example.com/events/{day}", headers={"Authorization": token})
    return resp.text


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
