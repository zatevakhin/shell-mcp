# shell-mcp

A Model Context Protocol (MCP) server that provides secure shell command execution with advanced command whitelisting, user confirmation, and comprehensive security controls. Designed for developers and LLM agents, it provides a safe and flexible way to run shell commands over multiple transports.

## Features

- Execute shell commands via MCP protocol with comprehensive validation
- Advanced command whitelisting with flexible allow/deny policies
- User confirmation for non-whitelisted commands (using MCP elicitation, if available on client)
- Support for multiple transports (stdio, SSE, streamable HTTP)
- Timeout protection prevents hanging processes
- Context-aware error messages with detailed information for agents
- Shell feature restrictions (pipes, redirects, substitutions, etc.)

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
cargo install --git https://github.com/zatevakhin/shell-mcp.git
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

#### Command Security Policies

**Traditional Whitelist (Default):**
```bash
SHELL_COMMANDS="ls,cat,grep,find,echo,pwd,git" shell-mcp
```
> If not set, defaults to: `ls,cat,grep,find,echo,pwd`

**Allow All Commands with Exceptions:**
```bash
SHELL_COMMANDS="*" SHELL_DISABLED_COMMANDS="rm,dd,sudo,shutdown" shell-mcp
```

**Enhanced Default Security:**
```bash
SHELL_DISABLED_COMMANDS="rm,dd" shell-mcp
```

#### Shell Feature Controls

**Disable Specific Features:**
```bash
SHELL_DISABLE_FEATURES="pipes,substitutions" shell-mcp
```

**Enable Only Specific Features:**
```bash
SHELL_FEATURES="pipes,logical-ops" shell-mcp
```

#### Other Settings

**Set timeout:**
```bash
SHELL_MCP_TIMEOUT=60 shell-mcp
```
> If not set, defaults to 30 seconds.

**Control startup display:**
```bash
SHELL_MCP_STARTUP_INFO=false shell-mcp
```
> If not set, startup information is shown by default.

**Verbose logging (request/response):**
```bash
# Log each incoming shell command and the returned result
shell-mcp -v

# Also enable debug-level logs (includes validated shell command)
shell-mcp -vv
```
> Logs are written to stderr. `RUST_LOG` takes precedence over `-v/-vv`.

### Error Handling

The server provides detailed, context-aware error messages:

**Command Not Allowed:**
```
Command blocked: Command 'rm' is not in the allowed list

Available Commands:
  cat, echo, find, grep, ls, pwd
```

**Command Explicitly Disabled:**
```
Command blocked: Command 'rm' is explicitly disabled
```

**Feature Disabled:**
```
Command blocked: Pipes are disabled

Shell Features Status:
  Pipes (|): disabled
  Logical operators (&& ||): enabled
  Semicolons (;): enabled
  Input redirects (<): enabled
  Output redirects (>): enabled
  Command substitutions ($(command)): enabled
```

### MCP Tool

The server provides a `shell` tool that accepts:

- `command`: The shell command to execute (with comprehensive validation)

The default working directory for all commands is controlled via the CLI `-w/--workdir` flag.
The tool provides enhanced error reporting with security context and user confirmation via elicitation (if available on client) for non-whitelisted commands.


## Security

- Advanced command whitelisting with flexible allow/deny policies
- User confirmation for non-whitelisted commands via MCP elicitation (if available on client)
- Shell feature restrictions (pipes, redirects, substitutions, etc.)
- Context-aware error messages with detailed information
- Shell commands are executed after parsing the input into an Abstract Syntax Tree (AST) for comprehensive validation and generation into safe shell code.
- Timeout protection prevents hanging processes
- Working directory can be set (**but not limited**) via the CLI `--workdir` flag

**Note:** While robust, the security features are not foolproof and can be bypassed by advanced users with malicious intent (e.g., exploiting misconfigured policies). current implementation should be enough to keep LLM agents guided by policies and prevent misuse by non-advanced users.

## License

MIT License - see [LICENSE](LICENSE) file for details.
