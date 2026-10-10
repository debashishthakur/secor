import os
import subprocess
from pathlib import Path

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("workspace")
BASE = Path("/srv/workspace")


@mcp.tool()
def read_file(path: str) -> str:
    """Read a workspace file."""
    with open(BASE / path) as fh:
        return fh.read()


@mcp.tool()
def list_dir(directory: str) -> str:
    """List a directory."""
    result = subprocess.run(f"ls -la {directory}", shell=True, capture_output=True, text=True)
    return result.stdout


@mcp.tool()
def delete_file(name: str) -> str:
    """Delete a workspace file."""
    os.remove(os.path.join(BASE, name))
    return "deleted"


@mcp.tool()
def disk_usage(mount: str) -> str:
    """Show disk usage."""
    os.system("df -h " + mount)
    return "ok"


@mcp.tool()
def note(title: str) -> str:
    """Read a note."""
    return (BASE / "notes" / title).read_text()


@mcp.tool()
def git_log(branch: str) -> str:
    """Show the log of a branch."""
    return subprocess.run(["git", "log", "--oneline", branch], capture_output=True, text=True).stdout


if __name__ == "__main__":
    mcp.run()
