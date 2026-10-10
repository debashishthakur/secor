import httpx
from mcp.server.auth.provider import AccessToken, TokenVerifier
from mcp.server.auth.settings import AuthSettings
from mcp.server.fastmcp import FastMCP


class IntrospectionVerifier(TokenVerifier):
    async def verify_token(self, token: str) -> AccessToken | None:
        async with httpx.AsyncClient() as client:
            resp = await client.post("https://auth.example.com/introspect", data={"token": token})
        info = resp.json()
        if not info.get("active"):
            return None
        return AccessToken(token=token, client_id=info["client_id"], scopes=info["scope"].split())


mcp = FastMCP(
    "notes",
    token_verifier=IntrospectionVerifier(),
    auth=AuthSettings(
        issuer_url="https://auth.example.com",
        resource_server_url="https://notes.example.com",
        required_scopes=["notes:read"],
    ),
)


@mcp.tool()
def list_notes(folder: str) -> str:
    """List the notes in a folder."""
    return f"notes in {folder}"


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
