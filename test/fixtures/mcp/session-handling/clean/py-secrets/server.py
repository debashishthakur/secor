import secrets

from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("shop")
carts: dict[str, list[str]] = {}


@mcp.tool()
def new_cart() -> str:
    """Start a cart."""
    session_id = secrets.token_urlsafe(32)
    carts[session_id] = []
    return session_id


@mcp.tool()
def my_orders() -> str:
    """List the orders of the authenticated user."""
    token = get_access_token()
    if token is None:
        raise PermissionError("authentication required")
    user = token.client_id
    return f"orders for {user}"


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
