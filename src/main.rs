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
use std::{path::PathBuf, sync::Arc};

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
    #[arg(
        short = 'w',
        long,
        value_name = "PATH",
        help = "Default working directory for executed commands"
    )]
    workdir: Option<PathBuf>,
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

fn format_shell_features(config: &shell::FeatureConfig) -> String {
    let all_features = vec![
        (shell::ShellFeature::Pipes, config.allow_pipes),
        (shell::ShellFeature::LogicalOps, config.allow_logical_ops),
        (shell::ShellFeature::Semicolons, config.allow_semicolons),
        (
            shell::ShellFeature::InputRedirects,
            config.allow_input_redirects,
        ),
        (
            shell::ShellFeature::OutputRedirects,
            config.allow_output_redirects,
        ),
        (
            shell::ShellFeature::Substitutions,
            config.allow_substitutions,
        ),
    ];

    let mut enabled = Vec::new();
    let mut disabled = Vec::new();

    for (feature, is_enabled) in all_features {
        if is_enabled {
            enabled.push(format!("\x1b[32m{}\x1b[0m", feature));
        } else {
            disabled.push(format!("\x1b[31m!{}\x1b[0m", feature));
        }
    }

    let mut parts = Vec::new();

    // Add disabled features first (red with ! prefix)
    if !disabled.is_empty() {
        parts.push(disabled.join(", "));
    }

    // Add enabled features (green)
    if !enabled.is_empty() {
        parts.push(enabled.join(", "));
    }

    parts.join(", ")
}

fn format_shell_commands(command_config: &shell::CommandConfig) -> String {
    let mut parts = Vec::new();

    // Add disabled commands first (red with ! prefix)
    if !command_config.disabled_commands.is_empty() {
        let disabled: Vec<String> = command_config
            .disabled_commands
            .iter()
            .map(|cmd| format!("\x1b[31m!{}\x1b[0m", cmd))
            .collect();
        parts.push(disabled.join(", "));
    }

    if command_config.allow_all {
        // Add green * for allow all
        parts.push(format!("\x1b[32m*\x1b[0m"));
    } else {
        // Show allowed commands in green
        if !command_config.allowed_commands.is_empty() {
            let enabled: Vec<String> = command_config
                .allowed_commands
                .iter()
                .map(|cmd| format!("\x1b[32m{}\x1b[0m", cmd))
                .collect();
            parts.push(enabled.join(", "));
        }
    }

    if parts.is_empty() {
        // Fallback if somehow both are empty
        format!("\x1b[32m*\x1b[0m")
    } else {
        parts.join(", ")
    }
}

fn format_feature_status(config: &shell::FeatureConfig) -> String {
    let features = vec![
        ("Pipes (|)", config.allow_pipes),
        ("Logical operators (&& ||)", config.allow_logical_ops),
        ("Semicolons (;)", config.allow_semicolons),
        ("Input redirects (<)", config.allow_input_redirects),
        ("Output redirects (>)", config.allow_output_redirects),
        (
            "Command substitutions ($(command))",
            config.allow_substitutions,
        ),
    ];

    features
        .iter()
        .map(|(name, enabled)| {
            let status = if *enabled { "enabled" } else { "disabled" };
            format!("  {}: {}", name, status)
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn format_validation_error(error: &shell::ValidationError) -> String {
    match error {
        shell::ValidationError::CommandNotAllowed { command } => {
            format!("Command '{}' is not in the allowed list", command)
        }
        shell::ValidationError::CommandDisabled { command } => {
            format!("Command '{}' is explicitly disabled", command)
        }
        shell::ValidationError::FeatureDisabled { feature } => {
            format!("{} are disabled", feature)
        }
        shell::ValidationError::NestedValidationError { node_type, inner } => {
            format!("Error in {}: {}", node_type, format_validation_error(inner))
        }
    }
}

fn format_available_commands(commands: &std::collections::HashSet<String>) -> String {
    let mut sorted_commands: Vec<&String> = commands.iter().collect();
    sorted_commands.sort();

    sorted_commands
        .iter()
        .map(|cmd| format!("  {}", cmd))
        .collect::<Vec<_>>()
        .join(", ")
}

fn format_disabled_commands(commands: &std::collections::HashSet<String>) -> String {
    if commands.is_empty() {
        "  (none)".to_string()
    } else {
        let mut sorted_commands: Vec<&String> = commands.iter().collect();
        sorted_commands.sort();

        sorted_commands
            .iter()
            .map(|cmd| format!("  {}", cmd))
            .collect::<Vec<_>>()
            .join("\n")
    }
}

fn get_shell_features() -> shell::FeatureConfig {
    // Check for SHELL_DISABLE_FEATURES first (takes precedence)
    if let Ok(disabled_str) = std::env::var("SHELL_DISABLE_FEATURES") {
        let disabled_trimmed = disabled_str.trim().to_lowercase();

        // Special case: disable all features
        if disabled_trimmed == "all" {
            return shell::FeatureConfig::all_disabled();
        }

        // Parse individual features to disable
        let disabled_features: Vec<shell::ShellFeature> = disabled_str
            .split(',')
            .filter_map(|s| match s.trim().to_lowercase().as_str() {
                "pipes" => Some(shell::ShellFeature::Pipes),
                "logical-ops" => Some(shell::ShellFeature::LogicalOps),
                "semicolons" => Some(shell::ShellFeature::Semicolons),
                "input-redirects" => Some(shell::ShellFeature::InputRedirects),
                "output-redirects" => Some(shell::ShellFeature::OutputRedirects),
                "substitutions" => Some(shell::ShellFeature::Substitutions),
                _ => None,
            })
            .collect();

        return shell::FeatureConfig::from_disabled_features(&disabled_features);
    }

    // Fall back to existing SHELL_FEATURES logic for backward compatibility
    std::env::var("SHELL_FEATURES")
        .map(|features_str| {
            let enabled_features: Vec<shell::ShellFeature> = features_str
                .split(',')
                .filter_map(|s| match s.trim().to_lowercase().as_str() {
                    "pipes" => Some(shell::ShellFeature::Pipes),
                    "logical-ops" => Some(shell::ShellFeature::LogicalOps),
                    "semicolons" => Some(shell::ShellFeature::Semicolons),
                    "input-redirects" => Some(shell::ShellFeature::InputRedirects),
                    "output-redirects" => Some(shell::ShellFeature::OutputRedirects),
                    "substitutions" => Some(shell::ShellFeature::Substitutions),
                    _ => None,
                })
                .collect();
            shell::FeatureConfig::from_enabled_features(&enabled_features)
        })
        .unwrap_or_default()
}

#[derive(Debug, Clone)]
pub struct ShellExecutor {
    tool_router: ToolRouter<Self>,
    timeout_secs: u64,
    default_cwd: PathBuf,
}

#[tool_router]
impl ShellExecutor {
    pub fn new(timeout_secs: u64, default_cwd: PathBuf) -> Self {
        Self {
            tool_router: Self::tool_router(),
            timeout_secs,
            default_cwd,
        }
    }

    #[tool(description = "Execute a shell command and return the output")]
    async fn shell(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(ExecuteCommandRequest { command }): Parameters<ExecuteCommandRequest>,
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

        // Get command config and features from environment variables
        let command_config = shell::CommandConfig::from_env();
        let shell_features = get_shell_features();

        // Validate the AST against command config and features
        if let Err(validation_error) = shell::validate_ast(&ast, &command_config, &shell_features) {
            if context.peer.supports_elicitation() {
                // Elicit confirmation for validation errors
                let error_message = format_validation_error(&validation_error);
                match context
                    .peer
                    .elicit::<Confirmation>(format!("{} Confirm execution?", error_message))
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
            } else {
                // Context-aware error messages based on error type
                let enhanced_error = match validation_error {
                    shell::ValidationError::CommandNotAllowed { command } => {
                        if command_config.allow_all {
                            format!(
                                "Command blocked: All commands are allowed except the following disabled commands:\n{}",
                                format_disabled_commands(&command_config.disabled_commands)
                            )
                        } else {
                            format!(
                                "Command blocked: Command '{}' is not in the allowed list\n\nAvailable Commands:\n{}",
                                command,
                                format_available_commands(&command_config.allowed_commands)
                            )
                        }
                    }
                    shell::ValidationError::CommandDisabled { command } => {
                        format!(
                            "Command blocked: Command '{}' is explicitly disabled",
                            command
                        )
                    }
                    shell::ValidationError::FeatureDisabled { feature } => {
                        format!(
                            "Command blocked: {} are disabled\n\nShell Features Status:\n{}",
                            feature,
                            format_feature_status(&shell_features)
                        )
                    }
                    shell::ValidationError::NestedValidationError { node_type, inner } => {
                        format!(
                            "Command blocked: Error in {}: {}\n\nShell Features Status:\n{}",
                            node_type,
                            format_validation_error(&inner),
                            format_feature_status(&shell_features)
                        )
                    }
                };

                return Ok(CallToolResult::success(vec![Content::text(enhanced_error)]));
            }
        }

        let cwd_str = self.default_cwd.to_string_lossy().to_string();

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
    let default_cwd = match args.workdir.clone() {
        Some(path) => path,
        None => std::env::current_dir()?,
    };

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
        println!("\x1b[1mWorking directory:\x1b[0m {}", default_cwd.display());

        let command_config = shell::CommandConfig::from_env();
        println!(
            "\x1b[1mShell commands:\x1b[0m {}",
            format_shell_commands(&command_config)
        );

        let shell_features = get_shell_features();
        println!(
            "\x1b[1mShell features:\x1b[0m {}",
            format_shell_features(&shell_features)
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
            let service =
                serve_server(ShellExecutor::new(timeout, default_cwd.clone()), stdio()).await?;
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

            let default_cwd_for_service = default_cwd.clone();
            let ct = sse_server
                .with_service(move || ShellExecutor::new(timeout, default_cwd_for_service.clone()));

            tokio::signal::ctrl_c().await?;
            ct.cancel();
        }
        Transport::StreamableHttp => {
            let config = StreamableHttpServerConfig {
                sse_keep_alive: streamable_http_sse_keep_alive,
                stateful_mode: streamable_http_stateful,
            };

            let session_manager = Arc::new(LocalSessionManager::default());

            let default_cwd_for_service = default_cwd.clone();
            let service = StreamableHttpService::new(
                move || Ok(ShellExecutor::new(timeout, default_cwd_for_service.clone())),
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
