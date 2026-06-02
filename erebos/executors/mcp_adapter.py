"""MCP (Model Context Protocol) adapter for remote tool execution."""

import json
import subprocess
from typing import Dict, Generator, List, Optional

from erebos.executors.base import ToolResult, Transport


class MCPAdapter(Transport):
    """MCP protocol transport for executing tools via MCP server."""

    def __init__(
        self,
        server_command: Optional[List[str]] = None,
        server_stdio: bool = True,
    ):
        """Initialize MCP adapter.

        Args:
            server_command: Command to start MCP server (e.g., ["npx", "-y", "mcp-server"])
            server_stdio: Use STDIO mode for local server communication
        """
        self.server_command = server_command
        self.server_stdio = server_stdio
        self._server_process: Optional[subprocess.Popen] = None

    def execute(
        self,
        tool: str,
        args: List[str],
        env: Optional[Dict[str, str]] = None,
        timeout: Optional[int] = None,
    ) -> ToolResult:
        """Execute a tool via MCP protocol."""
        import time

        start_time = time.time()

        # Check if MCP is available
        if not self.available():
            return ToolResult(
                tool=tool,
                exit_code=1,
                stdout="",
                stderr="MCP transport not available. Install MCP server or use CLI adapter.",
                duration_seconds=0.0,
            )

        try:
            # Build MCP request
            mcp_request = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": tool,
                    "arguments": args,
                },
            }

            # Execute via MCP
            result = self._send_request(mcp_request, timeout)

            duration = time.time() - start_time

            if "error" in result:
                return ToolResult(
                    tool=tool,
                    exit_code=1,
                    stdout="",
                    stderr=result.get("error", {}).get("message", "Unknown MCP error"),
                    duration_seconds=duration,
                )

            # Extract result
            tool_result = result.get("result", {})
            return ToolResult(
                tool=tool,
                exit_code=tool_result.get("exitCode", 0),
                stdout=tool_result.get("stdout", ""),
                stderr=tool_result.get("stderr", ""),
                duration_seconds=duration,
            )

        except Exception as e:
            duration = time.time() - start_time
            return ToolResult(
                tool=tool,
                exit_code=1,
                stdout="",
                stderr=f"MCP execution error: {str(e)}",
                duration_seconds=duration,
            )

    def stream(
        self,
        tool: str,
        args: List[str],
        env: Optional[Dict[str, str]] = None,
    ) -> Generator[str, None, None]:
        """Stream output from MCP tool execution."""
        # Check if MCP is available
        if not self.available():
            yield "ERROR: MCP transport not available\n"
            return

        try:
            # Build MCP request for streaming
            mcp_request = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call_stream",
                "params": {
                    "name": tool,
                    "arguments": args,
                },
            }

            # Stream response
            for chunk in self._stream_request(mcp_request):
                yield chunk

        except Exception as e:
            yield f"ERROR: {str(e)}\n"

    def available(self) -> bool:
        """Check if MCP transport is available."""
        # Check if we have a server command configured
        if self.server_command:
            return True

        # Check for common MCP server in PATH
        import shutil

        mcp_servers = ["mcp-server", "mcp-server-npx"]
        for server in mcp_servers:
            if shutil.which(server):
                return True

        return False

    def _send_request(
        self,
        request: dict,
        timeout: Optional[int] = None,
    ) -> dict:
        """Send a JSON-RPC request to MCP server via STDIO."""
        import os
        import tempfile

        # For STDIO mode (local MCP server)
        if self.server_stdio:
            return self._send_stdio_request(request, timeout)

        # Fallback: write request to temp file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as request_file:
            json.dump(request, request_file)
            request_file.flush()
            request_path = request_file.name

        try:
            # Read response from file via npx
            cmd = [
                "npx",
                "-y",
                "@modelcontextprotocol/server-bash",
                "--",
                "cat",
                request_path,
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout or 60,
            )

            if result.returncode != 0:
                return {"error": {"message": result.stderr}}

            return json.loads(result.stdout)

        finally:
            # Clean up temp file
            try:
                os.unlink(request_path)
            except Exception:
                pass

    def _send_stdio_request(
        self,
        request: dict,
        timeout: Optional[int] = None,
    ) -> dict:
        """Send a JSON-RPC request via STDIO to local MCP server.

        This method starts an MCP server as a subprocess and communicates
        with it via STDIO (stdin/stdout), which is the recommended mode
        for local MCP server execution.
        """
        import threading
        import os

        if not self.server_command:
            # Default MCP server command
            self.server_command = ["npx", "-y", "@modelcontextprotocol/server-filesystem", "."]

        # Start MCP server process
        env = os.environ.copy()
        env["MCP_SERVER_STDIO"] = "1"

        try:
            self._server_process = subprocess.Popen(
                self.server_command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
                text=True,
            )

            # Send request
            request_json = json.dumps(request) + "\n"
            self._server_process.stdin.write(request_json)
            self._server_process.stdin.flush()

            # Read response with timeout
            import select

            if timeout:
                ready, _, _ = select.select([self._server_process.stdout], [], [], timeout)
            else:
                ready = [self._server_process.stdout]

            if ready:
                response_line = self._server_process.stdout.readline()
                if response_line:
                    return json.loads(response_line)

            return {"error": {"message": "MCP server timeout or no response"}}

        except subprocess.TimeoutExpired:
            return {"error": {"message": f"MCP request timed out after {timeout}s"}}
        except Exception as e:
            return {"error": {"message": f"MCP STDIO error: {str(e)}"}}
        finally:
            self._stop_server()

    def _stop_server(self):
        """Stop the MCP server process if running."""
        if self._server_process:
            try:
                self._server_process.terminate()
                self._server_process.wait(timeout=5)
            except Exception:
                try:
                    self._server_process.kill()
                except Exception:
                    pass
            finally:
                self._server_process = None

    def _stream_request(self, request: dict) -> Generator[str, None, None]:
        """Stream a JSON-RPC request to MCP server."""
        # For now, implement as non-streaming
        # In a full implementation, this would use proper MCP streaming
        result = self._send_request(request)

        if "result" in result:
            output = result.get("result", {}).get("stdout", "")
            yield output
        elif "error" in result:
            yield f"ERROR: {result.get('error', {}).get('message', 'Unknown error')}\n"


class MCPTransportFactory:
    """Factory for creating MCP transports with fallback."""

    @staticmethod
    def create(
        preferred_transport: str = "cli",
        mcp_server_command: Optional[List[str]] = None,
    ) -> Transport:
        """Create a transport with automatic fallback.

        Args:
            preferred_transport: Preferred transport ("cli" or "mcp")
            mcp_server_command: Optional MCP server command

        Returns:
            Transport instance
        """
        from erebos.executors.cli_adapter import CLIAdapter

        if preferred_transport == "mcp":
            mcp = MCPAdapter(server_command=mcp_server_command)
            if mcp.available():
                return mcp

            # Fallback to CLI
            return CLIAdapter()

        # Default to CLI
        return CLIAdapter()

    @staticmethod
    def get_available_transports() -> List[str]:
        """Get list of available transport names."""
        transports = ["cli"]

        mcp = MCPAdapter()
        if mcp.available():
            transports.append("mcp")

        return transports
