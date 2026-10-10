import os

import httpx
from mcp.server.fastmcp import Context, FastMCP

mcp = FastMCP("calendar")


@mcp.tool()
async def list_events(day: str, ctx: Context) -> str:
    """List calendar events for a day."""
    request = ctx.request_context.request
    if not request.headers.get("authorization"):
        raise PermissionError("missing credentials")
    headers = {"Authorization": f"Bearer {os.environ['CALENDAR_TOKEN']}"}
    async with httpx.AsyncClient() as client:
        resp = await client.get(f"https://calendar.example.com/events/{day}", headers=headers)
    return resp.text


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
