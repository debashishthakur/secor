import subprocess
from typing import Literal

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("git-tools")
ALLOWED_COMMANDS = {"status", "log", "diff"}


@mcp.tool()
def git(command: str) -> str:
    """Run an allowed git command."""
    if command not in ALLOWED_COMMANDS:
        raise ValueError("command not allowed")
    return subprocess.run(["git", command], capture_output=True, text=True).stdout


@mcp.tool()
def recent(count: int) -> str:
    """Show the most recent commits."""
    return subprocess.run(["git", "log", f"-{count}", "--oneline"], capture_output=True, text=True).stdout


@mcp.tool()
def branches(scope: Literal["local", "remote"]) -> str:
    """List branches."""
    args = ["git", "branch", "-r"] if scope == "remote" else ["git", "branch"]
    return subprocess.run(args, capture_output=True, text=True).stdout


if __name__ == "__main__":
    mcp.run()
