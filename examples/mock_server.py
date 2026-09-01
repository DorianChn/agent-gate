"""A tiny in-memory MCP server used by the gateway demo.

Implements the minimal JSON-RPC 2.0 subset of the Model Context Protocol
over stdio: initialize, tools/list, and tools/call. Tools live in a dict
so nothing touches the real filesystem.

Tools:
  file_read(path)   -> {"content": ..., "size": ...}
  file_write(path, content, overwrite) -> {"path": ..., "bytes": ...}
  web_search(query) -> {"results": [...]}
"""

import json
import sys

FILES = {
    "/tmp/report.txt": "Q2 revenue: $1.2M (up 8% QoQ).",
    "/workspace/notes.md": "# Meeting notes\n- Ship the gateway demo.",
    "/etc/passwd": "root:x:0:0:root:/root:/bin/bash",
}

TOOLS = [
    {
        "name": "file_read",
        "description": "Read a text file",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "absolute path"},
                "max_bytes": {"type": "integer", "description": "size cap"},
            },
            "required": ["path"],
        },
    },
    {
        "name": "file_write",
        "description": "Write a text file",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "content": {"type": "string"},
                "overwrite": {"type": "boolean"},
            },
            "required": ["path", "content"],
        },
    },
    {
        "name": "web_search",
        "description": "Search the web",
        "inputSchema": {
            "type": "object",
            "properties": {"query": {"type": "string"}},
            "required": ["query"],
        },
    },
]


def call_tool(name, arguments):
    arguments = arguments or {}
    if name == "file_read":
        path = arguments["path"]
        if path not in FILES:
            return {"isError": True, "content": [{"type": "text",
                    "text": "file not found: %s" % path}]}
        return {"content": [{"type": "text", "text": FILES[path]}],
                "size": len(FILES[path])}
    if name == "file_write":
        path = arguments["path"]
        content = arguments["content"]
        overwrite = bool(arguments.get("overwrite", True))
        if path in FILES and not overwrite:
            return {"isError": True, "content": [{"type": "text",
                    "text": "file exists and overwrite=false"}]}
        FILES[path] = content
        return {"path": path, "bytes": len(content)}
    if name == "web_search":
        return {"results": [{"title": "result for %s" % arguments["query"],
                             "url": "https://example.com"}]}
    return {"isError": True, "content": [{"type": "text", "text": "no such tool"}]}


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        method = msg.get("method")
        rid = msg.get("id")
        if rid is None:  # notification
            continue
        if method == "initialize":
            result = {"protocolVersion": "2025-06-18",
                      "capabilities": {"tools": {}},
                      "serverInfo": {"name": "mock-server", "version": "1.0"}}
        elif method == "tools/list":
            result = {"tools": TOOLS}
        elif method == "tools/call":
            params = msg.get("params") or {}
            result = call_tool(params.get("name"),
                               params.get("arguments"))
        else:
            sys.stdout.write(json.dumps({
                "jsonrpc": "2.0", "id": rid,
                "error": {"code": -32601, "message": "method not found: %s" % method},
            }) + "\n")
            sys.stdout.flush()
            continue
        sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": rid,
                                     "result": result}) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
