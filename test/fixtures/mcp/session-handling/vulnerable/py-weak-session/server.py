import random
import time

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("shop")
sessions: dict[str, str] = {}


def check_password(username: str, password: str) -> bool:
    return bool(username and password)


@mcp.tool()
def login(username: str, password: str) -> str:
    """Log in and get a session id."""
    if not check_password(username, password):
        raise ValueError("invalid credentials")
    session_id = f"{int(time.time())}-{random.randint(1000, 9999)}"
    sessions[session_id] = username
    return session_id


@mcp.tool()
def my_orders(session_id: str) -> str:
    """List the orders of the logged-in user."""
    user = sessions.get(session_id)
    if user is None:
        raise ValueError("log in first")
    return f"orders for {user}"


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
