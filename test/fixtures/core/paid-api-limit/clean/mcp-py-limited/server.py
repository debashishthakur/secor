from anthropic import Anthropic
from mcp.server.fastmcp import FastMCP

from quota import check_quota

mcp = FastMCP("writer")
client = Anthropic()


@mcp.tool()
def draft(topic: str) -> str:
    check_quota("draft")
    msg = client.messages.create(model="claude-x", max_tokens=300, messages=[{"role": "user", "content": topic}])
    return msg.content[0].text


if __name__ == "__main__":
    mcp.run()
