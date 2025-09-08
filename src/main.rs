use clap::{Parser, ValueEnum};
use rmcp::transport::sse_server::{SseServer, SseServerConfig};
use rmcp::{
    ErrorData as McpError, elicit_safe,
    model::{CallToolResult, Content},
    service::{RequestContext, RoleServer},
};
use tracing_subscriber::{
    layer::SubscriberExt,
    util::SubscriberInitExt,
    {self},
};

mod pest_parser;
mod shell;

use pest_parser::parse_shell;
use std::collections::HashSet;
use std::sync::Arc;

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Clone, Debug, ValueEnum, PartialEq)]
enum Transport {
    Sse,
    Stdio,
    StreamableHttp,
}

impl std::fmt::Display for Transport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Transport::Sse => write!(f, "sse"),
            Transport::Stdio => write!(f, "stdio"),
            Transport::StreamableHttp => write!(f, "streamable-http"),
        }
    }
}

#[derive(Parser)]
#[command(name = "shell-mcp")]
struct Args {
    #[arg(short = 'b', long, default_value = "127.0.0.1:3003")]
    bind: String,
    #[arg(short = 't', long, default_value_t = Transport::Stdio)]
    transport: Transport,
}

use rmcp::{
    ServerHandler,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{ServerCapabilities, ServerInfo},
    schemars, serve_server, tool, tool_handler, tool_router,
    transport::io::stdio,
    transport::streamable_http_server::session::local::LocalSessionManager,
    transport::streamable_http_server::tower::{StreamableHttpServerConfig, StreamableHttpService},
};

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct ExecuteCommandRequest {
    #[schemars(description = "The shell command to execute")]
    pub command: String,
    #[schemars(description = "Optional working directory; defaults to current directory")]
    pub cwd: Option<String>,
}

#[derive(Debug, serde::Serialize, schemars::JsonSchema)]
pub struct ExecuteCommandResponse {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
    pub success: bool,
}

#[derive(Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct Confirmation {
    #[schemars(description = "Confirm execution of the command")]
    pub confirm: bool,
}

elicit_safe!(Confirmation);

fn get_allowed_commands() -> HashSet<String> {
    std::env::var("SHELL_ALLOWED_COMMANDS")
        .unwrap_or_else(|_| "ls,cat,grep,find,echo,pwd".to_string())
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

#[derive(Debug, Clone)]
pub struct ShellExecutor {
    tool_router: ToolRouter<Self>,
    timeout_secs: u64,
}

#[tool_router]
impl ShellExecutor {
    pub fn new(timeout_secs: u64) -> Self {
        Self {
            tool_router: Self::tool_router(),
            timeout_secs,
        }
    }

    #[tool(description = "Execute a shell command and return the output")]
    async fn shell(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(ExecuteCommandRequest { command, cwd }): Parameters<ExecuteCommandRequest>,
    ) -> Result<CallToolResult, McpError> {
        // Parse the command into AST
        let ast = match parse_shell(&command) {
            Some(ast) => ast,
            None => {
                return Ok(CallToolResult::success(vec![Content::text(
                    "Failed to parse command".to_string(),
                )]));
            }
        };

        // Get allowed commands from environment variable or use defaults
        let allowed_commands = get_allowed_commands();

        // Validate the AST against allowed commands
        if let Err(validation_error) = shell::validate_ast(&ast, &allowed_commands) {
            // Elicit confirmation for non-whitelisted commands
            match context
                .peer
                .elicit::<Confirmation>(format!("{} Confirm execution?", validation_error))
                .await
            {
                Ok(Some(conf)) if conf.confirm => {
                    // Proceed with execution despite validation error
                }
                Ok(Some(_)) => {
                    return Ok(CallToolResult::success(vec![Content::text(
                        "Command execution cancelled by user.".to_string(),
                    )]));
                }
                Ok(None) => {
                    return Ok(CallToolResult::success(vec![Content::text(
                        "No confirmation provided.".to_string(),
                    )]));
                }
                Err(e) => {
                    return Err(McpError::internal_error(
                        format!("Elicitation error: {}", e),
                        None,
                    ));
                }
            }
        }

        let cwd_str = cwd.filter(|s| !s.is_empty()).unwrap_or_else(|| {
            std::env::current_dir()
                .unwrap()
                .to_string_lossy()
                .to_string()
        });

        // Convert AST back to shell command string
        let shell_command = match shell::ast_to_shell_string(&ast) {
            Ok(cmd) => cmd,
            Err(e) => {
                return Ok(CallToolResult::success(vec![Content::text(format!(
                    "Failed to convert AST to shell command: {}",
                    e
                ))]));
            }
        };

        // Execute the full command through shell
        match tokio::time::timeout(
            std::time::Duration::from_secs(self.timeout_secs),
            shell::execute_through_shell(&shell_command, Some(&cwd_str)),
        )
        .await
        {
            Ok(Ok(result)) => {
                let response = ExecuteCommandResponse {
                    stdout: result.stdout,
                    stderr: result.stderr,
                    exit_code: result.exit_code,
                    success: result.success,
                };
                let json = serde_json::to_string(&response)
                    .unwrap_or_else(|_| "Serialization error".to_string());
                Ok(CallToolResult::success(vec![Content::text(json)]))
            }
            Ok(Err(e)) => {
                let response = ExecuteCommandResponse {
                    stdout: String::new(),
                    stderr: format!("Shell execution error: {}", e),
                    exit_code: 1,
                    success: false,
                };
                let json = serde_json::to_string(&response)
                    .unwrap_or_else(|_| "Serialization error".to_string());
                Ok(CallToolResult::success(vec![Content::text(json)]))
            }
            Err(_) => {
                let response = ExecuteCommandResponse {
                    stdout: String::new(),
                    stderr: format!("Command timed out after {} seconds", self.timeout_secs),
                    exit_code: 1,
                    success: false,
                };
                let json = serde_json::to_string(&response)
                    .unwrap_or_else(|_| "Serialization error".to_string());
                Ok(CallToolResult::success(vec![Content::text(json)]))
            }
        }
    }
}

#[tool_handler]
impl ServerHandler for ShellExecutor {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            instructions: Some(
                "A shell command executor MCP server with elicitation support".into(),
            ),
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            ..Default::default()
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // Read timeout from environment variable or use default
    let timeout = std::env::var("SHELL_MCP_TIMEOUT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(30);

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "warn".to_string().into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Display startup information
    let show_startup_info = std::env::var("SHELL_MCP_STARTUP_INFO")
        .map(|s| s != "false" && s != "0")
        .unwrap_or(true);
    // Disable it on stdio
    if show_startup_info && args.transport != Transport::Stdio {
        println!("\x1b[1;36mShell-MCP v{} Server Starting...\x1b[0m", VERSION);
        println!("\x1b[1mAddress:\x1b[0m {}", args.bind);
        println!("\x1b[1mTransport:\x1b[0m {}", args.transport);
        println!("\x1b[1mTimeout:\x1b[0m {}s", timeout);

        let allowed_commands = get_allowed_commands();
        println!(
            "\x1b[1mAllowed commands:\x1b[0m {}",
            allowed_commands
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );

        println!(
            "\x1b[38;5;196mS\x1b[38;5;202me\x1b[38;5;208mr\x1b[38;5;214mv\x1b[38;5;220me\x1b[38;5;226mr\x1b[38;5;190m \x1b[38;5;154mr\x1b[38;5;118me\x1b[38;5;82ma\x1b[38;5;46md\x1b[38;5;47my\x1b[38;5;48m!\x1b[0m"
        );
    }

    // Read streamable HTTP configuration from environment variables
    let streamable_http_stateful = std::env::var("STREAMABLE_HTTP_STATEFUL")
        .map(|s| s.parse().unwrap_or(true))
        .unwrap_or(true);

    let streamable_http_sse_keep_alive = std::env::var("STREAMABLE_HTTP_SSE_KEEP_ALIVE")
        .ok()
        .and_then(|s| s.parse().ok())
        .map(std::time::Duration::from_secs);

    match args.transport {
        Transport::Stdio => {
            let service = serve_server(ShellExecutor::new(timeout), stdio()).await?;
            tokio::signal::ctrl_c().await?;
            service.cancel().await?;
        }
        Transport::Sse => {
            let config = SseServerConfig {
                bind: args.bind.parse()?,
                sse_path: "/sse".to_string(),
                post_path: "/message".to_string(),
                ct: tokio_util::sync::CancellationToken::new(),
                sse_keep_alive: None,
            };

            let (sse_server, router) = SseServer::new(config);

            let listener = tokio::net::TcpListener::bind(sse_server.config.bind).await?;

            let ct = sse_server.config.ct.child_token();

            let server = axum::serve(listener, router).with_graceful_shutdown(async move {
                ct.cancelled().await;
                tracing::info!("sse server cancelled");
            });

            tokio::spawn(async move {
                if let Err(e) = server.await {
                    tracing::error!(error = %e, "sse server shutdown with error");
                }
            });

            let ct = sse_server.with_service(move || ShellExecutor::new(timeout));

            tokio::signal::ctrl_c().await?;
            ct.cancel();
        }
        Transport::StreamableHttp => {
            let config = StreamableHttpServerConfig {
                sse_keep_alive: streamable_http_sse_keep_alive,
                stateful_mode: streamable_http_stateful,
            };

            let session_manager = Arc::new(LocalSessionManager::default());

            let service = StreamableHttpService::new(
                move || Ok(ShellExecutor::new(timeout)),
                session_manager,
                config,
            );

            let listener = tokio::net::TcpListener::bind(&args.bind).await?;

            let app = axum::Router::new().fallback_service(service);

            let server = axum::serve(listener, app).with_graceful_shutdown(async move {
                tokio::signal::ctrl_c().await.ok();
            });

            server.await?;
        }
    }
    Ok(())
}
