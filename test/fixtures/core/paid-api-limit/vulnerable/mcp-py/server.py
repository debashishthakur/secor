from mcp.server.fastmcp import FastMCP
from openai import OpenAI

mcp = FastMCP("writer")
client = OpenAI()


@mcp.tool()
def draft(topic: str) -> str:
    resp = client.responses.create(model="gpt-4o-mini", input=f"Write about {topic}")
    return resp.output_text


if __name__ == "__main__":
    mcp.run()
