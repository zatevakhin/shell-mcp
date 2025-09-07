# shell-mcp

A Model Context Protocol (MCP) server that provides ~~safe~~ shell command execution with user confirmation and configurable command whitelisting.

## Features

- Execute shell commands via MCP protocol
- Configurable allowed commands via environment variable
- ~~User confirmation for non-whitelisted commands (using MCP elicitation)~~ (WIP)
- Support for multiple transports (stdio, SSE, streamable HTTP)
- Timeout protection for long-running commands

## Installation

### Via Nix

```bash
nix run github:zatevakhin/shell-mcp
```

Or run specific version you need.
```bash
nix run "github:zatevakhin/shell-mcp?ref=<tag|branch|rev>"
```

### Via Cargo

```bash
cargo install --git https://github.com/yourusername/shell-mcp.git
```
> Should work for most systems.

## Usage

### Basic Usage

```bash
# Run with stdio transport (default)
shell-mcp

# Run with SSE server
shell-mcp --transport sse --bind 127.0.0.1:3003

# Run with streamable HTTP
shell-mcp --transport streamable-http --bind 127.0.0.1:3003
```

### Configuration

Set allowed commands via environment variable:

```bash
SHELL_ALLOWED_COMMANDS="ls,cat,grep,find,echo,pwd,git" shell-mcp
```
> If not set, defaults to: `ls,cat,grep,find,echo,pwd`

Set timeout via environment variable:

```bash
SHELL_MCP_TIMEOUT=60 shell-mcp
```
> If not set, defaults to 30 seconds.

Control startup information display:

```bash
SHELL_MCP_STARTUP_INFO=false shell-mcp
```
> If not set, startup information is shown by default.

### MCP Tool

The server provides a `shell` tool that accepts:

- `command`: The shell command to execute
- `args`: Optional array of command arguments
- `cwd`: Optional working directory (defaults to current directory)
> WIP: This will be updated later because some LLMs are inconsistent with `args` and `cwd`.


## Security

- Commands whitelist
- ~~Commands not in the whitelist require explicit user confirmation~~ (WIP)
- Timeout protection prevents hanging processes
- Working directory can be specified to limit scope

## License

MIT License - see [LICENSE](LICENSE) file for details.
