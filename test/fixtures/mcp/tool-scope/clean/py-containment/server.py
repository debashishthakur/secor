import os
from pathlib import Path

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("notes")
ROOT = Path(os.environ.get("NOTES_ROOT", "notes")).resolve()


@mcp.tool()
def read_note(name: str) -> str:
    """Read a note inside the notes folder."""
    target = (ROOT / name).resolve()
    if not target.is_relative_to(ROOT):
        raise ValueError("path outside the notes folder")
    return target.read_text()


@mcp.tool()
def delete_note(name: str) -> str:
    """Delete a note inside the notes folder."""
    target = os.path.realpath(os.path.join(ROOT, name))
    if os.path.commonpath([target, str(ROOT)]) != str(ROOT):
        raise ValueError("path outside the notes folder")
    os.remove(target)
    return "deleted"


@mcp.tool()
def read_attachment(file: str) -> str:
    """Read an attachment by file name."""
    with open(ROOT / "attachments" / os.path.basename(file)) as fh:
        return fh.read()


if __name__ == "__main__":
    mcp.run()
