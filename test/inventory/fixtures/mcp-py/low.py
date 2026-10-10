from mcp.server.lowlevel import Server

server = Server("low")

@server.call_tool()
async def call_tool(name: str, arguments: dict):
    if name == "add":
        return []
    elif name == "delete_note":
        return []
    raise ValueError(name)
