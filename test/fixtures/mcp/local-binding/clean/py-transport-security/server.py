from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings

security = TransportSecuritySettings(
    enable_dns_rebinding_protection=True,
    allowed_hosts=["127.0.0.1:*", "localhost:*"],
    allowed_origins=["http://localhost:*"],
)
mcp = FastMCP("desktop-notes", host="localhost", transport_security=security)


@mcp.tool()
def ping() -> str:
    """Health check."""
    return "pong"


if __name__ == "__main__":
    mcp.run(transport="sse")
