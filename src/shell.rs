use tokio::process::Command;

#[derive(Debug, Clone, PartialEq)]
pub enum ShellFeature {
    Pipes,           // |
    LogicalOps,      // && ||
    Semicolons,      // ;
    InputRedirects,  // <
    OutputRedirects, // > >>
    Substitutions,   // $(...) and `...`
}

impl std::fmt::Display for ShellFeature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ShellFeature::Pipes => write!(f, "pipes"),
            ShellFeature::LogicalOps => write!(f, "logical-ops"),
            ShellFeature::Semicolons => write!(f, "semicolons"),
            ShellFeature::InputRedirects => write!(f, "input-redirects"),
            ShellFeature::OutputRedirects => write!(f, "output-redirects"),
            ShellFeature::Substitutions => write!(f, "substitutions"),
        }
    }
}

#[derive(Debug, Clone)]
pub enum ValidationError {
    CommandNotAllowed {
        command: String,
    },
    CommandDisabled {
        command: String,
    },
    FeatureDisabled {
        feature: ShellFeature,
    },
    NestedValidationError {
        node_type: String,
        inner: Box<ValidationError>,
    },
}

#[derive(Debug, Clone)]
pub struct CommandConfig {
    pub allow_all: bool,
    pub allowed_commands: std::collections::HashSet<String>,
    pub disabled_commands: std::collections::HashSet<String>,
}

impl CommandConfig {
    pub fn from_env() -> Self {
        let commands_str = std::env::var("SHELL_COMMANDS")
            .unwrap_or_else(|_| "ls,cat,grep,find,echo,pwd".to_string());

        let allow_all = commands_str.trim() == "*";
        let allowed_commands = if allow_all {
            std::collections::HashSet::new()
        } else {
            commands_str
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        };

        let disabled_commands = std::env::var("SHELL_DISABLED_COMMANDS")
            .unwrap_or_default()
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        Self {
            allow_all,
            allowed_commands,
            disabled_commands,
        }
    }

    pub fn is_command_allowed(&self, command: &str) -> bool {
        if self.disabled_commands.contains(command) {
            return false;
        }
        if self.allow_all {
            return true;
        }
        self.allowed_commands.contains(command)
    }
}

#[derive(Debug, Clone)]
pub struct FeatureConfig {
    pub allow_pipes: bool,
    pub allow_logical_ops: bool,
    pub allow_semicolons: bool,
    pub allow_input_redirects: bool,
    pub allow_output_redirects: bool,
    pub allow_substitutions: bool,
}

impl Default for FeatureConfig {
    fn default() -> Self {
        Self::all_enabled()
    }
}

impl FeatureConfig {
    pub fn all_enabled() -> Self {
        Self {
            allow_pipes: true,
            allow_logical_ops: true,
            allow_semicolons: true,
            allow_input_redirects: true,
            allow_output_redirects: true,
            allow_substitutions: true,
        }
    }

    pub fn all_disabled() -> Self {
        Self {
            allow_pipes: false,
            allow_logical_ops: false,
            allow_semicolons: false,
            allow_input_redirects: false,
            allow_output_redirects: false,
            allow_substitutions: false,
        }
    }

    pub fn from_enabled_features(features: &[ShellFeature]) -> Self {
        Self {
            allow_pipes: features.contains(&ShellFeature::Pipes),
            allow_logical_ops: features.contains(&ShellFeature::LogicalOps),
            allow_semicolons: features.contains(&ShellFeature::Semicolons),
            allow_input_redirects: features.contains(&ShellFeature::InputRedirects),
            allow_output_redirects: features.contains(&ShellFeature::OutputRedirects),
            allow_substitutions: features.contains(&ShellFeature::Substitutions),
        }
    }

    pub fn from_disabled_features(disabled: &[ShellFeature]) -> Self {
        let mut config = Self::all_enabled();
        for feature in disabled {
            match feature {
                ShellFeature::Pipes => config.allow_pipes = false,
                ShellFeature::LogicalOps => config.allow_logical_ops = false,
                ShellFeature::Semicolons => config.allow_semicolons = false,
                ShellFeature::InputRedirects => config.allow_input_redirects = false,
                ShellFeature::OutputRedirects => config.allow_output_redirects = false,
                ShellFeature::Substitutions => config.allow_substitutions = false,
            }
        }
        config
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Arg {
    Literal(String),
    Substitution(usize),
}

// Implement PartialEq<&str> for Arg so Arg can be compared with &str
impl PartialEq<&str> for Arg {
    fn eq(&self, other: &&str) -> bool {
        match self {
            Arg::Literal(s) => s == *other,
            Arg::Substitution(_) => false,
        }
    }
}

#[derive(Debug, Clone)]
pub enum ShellNode {
    Command {
        args: Vec<Arg>,
        redirects: Vec<Redirect>,
        substitutions: Vec<ShellNode>,
    },
    Pipe(Box<ShellNode>, Box<ShellNode>),
    And(Box<ShellNode>, Box<ShellNode>),
    Or(Box<ShellNode>, Box<ShellNode>),
    Semicolon(Box<ShellNode>, Box<ShellNode>),
}

#[derive(Debug, Clone)]
pub enum Redirect {
    Output(String, bool), // filename, append (true for >>, false for >)
    Input(String),
}

pub fn validate_ast(
    ast: &ShellNode,
    command_config: &CommandConfig,
    config: &FeatureConfig,
) -> Result<(), ValidationError> {
    match ast {
        ShellNode::Command {
            args,
            redirects,
            substitutions,
        } => {
            // Check the first arg if it's a literal command
            if let Some(Arg::Literal(cmd)) = args.first() {
                if !command_config.is_command_allowed(cmd) {
                    if command_config.disabled_commands.contains(cmd) {
                        return Err(ValidationError::CommandDisabled {
                            command: cmd.clone(),
                        });
                    } else {
                        return Err(ValidationError::CommandNotAllowed {
                            command: cmd.clone(),
                        });
                    }
                }
            }

            // Check feature restrictions
            if !config.allow_substitutions && !substitutions.is_empty() {
                return Err(ValidationError::FeatureDisabled {
                    feature: ShellFeature::Substitutions,
                });
            }

            for redirect in redirects {
                match redirect {
                    Redirect::Input(_) if !config.allow_input_redirects => {
                        return Err(ValidationError::FeatureDisabled {
                            feature: ShellFeature::InputRedirects,
                        });
                    }
                    Redirect::Output(_, _) if !config.allow_output_redirects => {
                        return Err(ValidationError::FeatureDisabled {
                            feature: ShellFeature::OutputRedirects,
                        });
                    }
                    _ => {}
                }
            }

            // Validate all substitutions
            for subst in substitutions {
                if let Err(e) = validate_ast(subst, command_config, config) {
                    return Err(ValidationError::NestedValidationError {
                        node_type: "substitution".to_string(),
                        inner: Box::new(e),
                    });
                }
            }
        }
        ShellNode::Pipe(left, right) => {
            if !config.allow_pipes {
                return Err(ValidationError::FeatureDisabled {
                    feature: ShellFeature::Pipes,
                });
            }
            if let Err(e) = validate_ast(left, command_config, config) {
                return Err(ValidationError::NestedValidationError {
                    node_type: "left side of pipe".to_string(),
                    inner: Box::new(e),
                });
            }
            if let Err(e) = validate_ast(right, command_config, config) {
                return Err(ValidationError::NestedValidationError {
                    node_type: "right side of pipe".to_string(),
                    inner: Box::new(e),
                });
            }
        }
        ShellNode::And(left, right) | ShellNode::Or(left, right) => {
            if !config.allow_logical_ops {
                return Err(ValidationError::FeatureDisabled {
                    feature: ShellFeature::LogicalOps,
                });
            }
            if let Err(e) = validate_ast(left, command_config, config) {
                return Err(ValidationError::NestedValidationError {
                    node_type: "left side of logical operator".to_string(),
                    inner: Box::new(e),
                });
            }
            if let Err(e) = validate_ast(right, command_config, config) {
                return Err(ValidationError::NestedValidationError {
                    node_type: "right side of logical operator".to_string(),
                    inner: Box::new(e),
                });
            }
        }
        ShellNode::Semicolon(left, right) => {
            if !config.allow_semicolons {
                return Err(ValidationError::FeatureDisabled {
                    feature: ShellFeature::Semicolons,
                });
            }
            if let Err(e) = validate_ast(left, command_config, config) {
                return Err(ValidationError::NestedValidationError {
                    node_type: "left side of semicolon".to_string(),
                    inner: Box::new(e),
                });
            }
            if let Err(e) = validate_ast(right, command_config, config) {
                return Err(ValidationError::NestedValidationError {
                    node_type: "right side of semicolon".to_string(),
                    inner: Box::new(e),
                });
            }
        }
    }
    Ok(())
}

#[derive(Debug)]
pub struct ExecutionResult {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
    pub success: bool,
}

/// Convert AST back to shell command string for execution through shell
pub fn ast_to_shell_string(ast: &ShellNode) -> Result<String, String> {
    match ast {
        ShellNode::Command {
            args,
            redirects,
            substitutions,
        } => {
            let mut parts = Vec::new();

            // Handle arguments and substitutions
            for arg in args {
                match arg {
                    Arg::Literal(s) => parts.push(shell_escape(s)),
                    Arg::Substitution(idx) => {
                        if *idx < substitutions.len() {
                            parts
                                .push(format!("$({})", ast_to_shell_string(&substitutions[*idx])?));
                        } else {
                            return Err("Invalid substitution index".to_string());
                        }
                    }
                }
            }

            let mut result = parts.join(" ");

            // Add redirects
            for redirect in redirects {
                match redirect {
                    Redirect::Output(filename, append) => {
                        result.push_str(&format!(
                            " {} {}",
                            if *append { ">>" } else { ">" },
                            shell_escape(filename)
                        ));
                    }
                    Redirect::Input(filename) => {
                        result.push_str(&format!(" < {}", shell_escape(filename)));
                    }
                }
            }

            Ok(result)
        }
        ShellNode::Pipe(left, right) => Ok(format!(
            "{} | {}",
            ast_to_shell_string(left)?,
            ast_to_shell_string(right)?
        )),
        ShellNode::And(left, right) => Ok(format!(
            "{} && {}",
            ast_to_shell_string(left)?,
            ast_to_shell_string(right)?
        )),
        ShellNode::Or(left, right) => Ok(format!(
            "{} || {}",
            ast_to_shell_string(left)?,
            ast_to_shell_string(right)?
        )),
        ShellNode::Semicolon(left, right) => Ok(format!(
            "{}; {}",
            ast_to_shell_string(left)?,
            ast_to_shell_string(right)?
        )),
    }
}

/// Execute a full shell command through the system shell
pub async fn execute_through_shell(
    command: &str,
    cwd: Option<&str>,
) -> Result<ExecutionResult, String> {
    let mut cmd = Command::new("sh");
    cmd.arg("-c").arg(command);

    // Set working directory
    if let Some(cwd) = cwd {
        cmd.current_dir(cwd);
    }

    let output = cmd
        .output()
        .await
        .map_err(|e| format!("Shell command execution failed: {}", e))?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let exit_code = output.status.code().unwrap_or(-1);
    let success = output.status.success();

    Ok(ExecutionResult {
        stdout,
        stderr,
        exit_code,
        success,
    })
}

/// Escape shell arguments properly
fn shell_escape(arg: &str) -> String {
    // Simple escaping - wrap in quotes if contains special characters
    if arg.chars().any(|c| {
        c.is_whitespace()
            || matches!(
                c,
                '|' | '&' | ';' | '(' | ')' | '<' | '>' | '$' | '`' | '"' | '\\'
            )
    }) {
        format!("'{}'", arg.replace('\'', "\\'"))
    } else {
        arg.to_string()
    }
}

#[cfg(test)]
mod feature_config_tests {
    use super::*;
    use crate::pest_parser::parse_shell;
    use std::collections::HashSet;

    #[test]
    fn test_feature_config_default_all_enabled() {
        let config = FeatureConfig::default();
        assert!(config.allow_pipes);
        assert!(config.allow_logical_ops);
        assert!(config.allow_semicolons);
        assert!(config.allow_input_redirects);
        assert!(config.allow_output_redirects);
        assert!(config.allow_substitutions);
    }

    #[test]
    fn test_feature_config_from_enabled_features() {
        let enabled = vec![ShellFeature::Pipes, ShellFeature::OutputRedirects];
        let config = FeatureConfig::from_enabled_features(&enabled);

        assert!(config.allow_pipes);
        assert!(!config.allow_logical_ops);
        assert!(!config.allow_semicolons);
        assert!(!config.allow_input_redirects);
        assert!(config.allow_output_redirects);
        assert!(!config.allow_substitutions);
    }

    #[test]
    fn test_feature_config_from_disabled_features_single() {
        let disabled = vec![ShellFeature::Substitutions];
        let config = FeatureConfig::from_disabled_features(&disabled);

        assert!(config.allow_pipes);
        assert!(config.allow_logical_ops);
        assert!(config.allow_semicolons);
        assert!(config.allow_input_redirects);
        assert!(config.allow_output_redirects);
        assert!(!config.allow_substitutions); // This should be disabled
    }

    #[test]
    fn test_feature_config_from_disabled_features_multiple() {
        let disabled = vec![
            ShellFeature::Pipes,
            ShellFeature::LogicalOps,
            ShellFeature::Substitutions,
        ];
        let config = FeatureConfig::from_disabled_features(&disabled);

        assert!(!config.allow_pipes); // Disabled
        assert!(!config.allow_logical_ops); // Disabled
        assert!(config.allow_semicolons);
        assert!(config.allow_input_redirects);
        assert!(config.allow_output_redirects);
        assert!(!config.allow_substitutions); // Disabled
    }

    #[test]
    fn test_feature_config_from_disabled_features_empty() {
        let disabled: Vec<ShellFeature> = vec![];
        let config = FeatureConfig::from_disabled_features(&disabled);

        // All should be enabled when no features are disabled
        assert!(config.allow_pipes);
        assert!(config.allow_logical_ops);
        assert!(config.allow_semicolons);
        assert!(config.allow_input_redirects);
        assert!(config.allow_output_redirects);
        assert!(config.allow_substitutions);
    }

    #[test]
    fn test_validate_pipes_disabled() {
        let mut allowed = HashSet::new();
        allowed.insert("ls".to_string());
        allowed.insert("grep".to_string());

        let command_config = CommandConfig {
            allow_all: false,
            allowed_commands: allowed,
            disabled_commands: HashSet::new(),
        };
        let config = FeatureConfig::all_disabled();

        let ast = parse_shell("ls | grep test").unwrap();
        assert!(validate_ast(&ast, &command_config, &config).is_err());
    }

    #[test]
    fn test_validate_logical_ops_disabled() {
        let mut allowed = HashSet::new();
        allowed.insert("echo".to_string());

        let command_config = CommandConfig {
            allow_all: false,
            allowed_commands: allowed,
            disabled_commands: HashSet::new(),
        };
        let config = FeatureConfig::all_disabled();

        let ast = parse_shell("echo hello && echo world").unwrap();
        assert!(validate_ast(&ast, &command_config, &config).is_err());
    }

    #[test]
    fn test_validate_semicolons_disabled() {
        let mut allowed = HashSet::new();
        allowed.insert("echo".to_string());

        let command_config = CommandConfig {
            allow_all: false,
            allowed_commands: allowed,
            disabled_commands: HashSet::new(),
        };
        let config = FeatureConfig::all_disabled();

        // Test direct semicolon (may not parse due to grammar limitations)
        let result = parse_shell("echo hello; echo world");
        if let Some(ast) = result {
            assert!(validate_ast(&ast, &command_config, &config).is_err());
        }
    }

    #[test]
    fn test_validate_input_redirects_disabled() {
        let mut allowed = HashSet::new();
        allowed.insert("grep".to_string());

        let command_config = CommandConfig {
            allow_all: false,
            allowed_commands: allowed,
            disabled_commands: HashSet::new(),
        };
        let config = FeatureConfig::all_disabled();

        let ast = parse_shell("grep pattern < input.txt").unwrap();
        assert!(validate_ast(&ast, &command_config, &config).is_err());
    }

    #[test]
    fn test_validate_output_redirects_disabled() {
        let mut allowed = HashSet::new();
        allowed.insert("echo".to_string());

        let command_config = CommandConfig {
            allow_all: false,
            allowed_commands: allowed,
            disabled_commands: HashSet::new(),
        };
        let config = FeatureConfig::all_disabled();

        let ast = parse_shell("echo hello > output.txt").unwrap();
        assert!(validate_ast(&ast, &command_config, &config).is_err());
    }

    #[test]
    fn test_validate_substitutions_disabled() {
        let mut allowed = HashSet::new();
        allowed.insert("echo".to_string());

        let command_config = CommandConfig {
            allow_all: false,
            allowed_commands: allowed,
            disabled_commands: HashSet::new(),
        };
        let config = FeatureConfig::all_disabled();

        let ast = parse_shell("echo $(date)").unwrap();
        assert!(validate_ast(&ast, &command_config, &config).is_err());
    }

    #[test]
    fn test_validate_backtick_substitutions_disabled() {
        let mut allowed = HashSet::new();
        allowed.insert("echo".to_string());

        let command_config = CommandConfig {
            allow_all: false,
            allowed_commands: allowed,
            disabled_commands: HashSet::new(),
        };
        let config = FeatureConfig::all_disabled();

        let ast = parse_shell("echo `date`").unwrap();
        assert!(validate_ast(&ast, &command_config, &config).is_err());
    }

    #[test]
    fn test_validate_allowed_features_work() {
        let mut allowed = HashSet::new();
        allowed.insert("echo".to_string());
        allowed.insert("ls".to_string());
        allowed.insert("grep".to_string());

        let command_config = CommandConfig {
            allow_all: false,
            allowed_commands: allowed,
            disabled_commands: HashSet::new(),
        };
        let config = FeatureConfig {
            allow_pipes: true,
            allow_output_redirects: true,
            ..FeatureConfig::all_disabled()
        };

        // Should allow pipes and output redirects
        let ast1 = parse_shell("ls | grep test").unwrap();
        assert!(validate_ast(&ast1, &command_config, &config).is_ok());

        let ast2 = parse_shell("echo hello > output.txt").unwrap();
        assert!(validate_ast(&ast2, &command_config, &config).is_ok());
    }

    #[test]
    fn test_shell_feature_display() {
        assert_eq!(format!("{}", ShellFeature::Pipes), "pipes");
        assert_eq!(format!("{}", ShellFeature::LogicalOps), "logical-ops");
        assert_eq!(format!("{}", ShellFeature::Semicolons), "semicolons");
        assert_eq!(
            format!("{}", ShellFeature::InputRedirects),
            "input-redirects"
        );
        assert_eq!(
            format!("{}", ShellFeature::OutputRedirects),
            "output-redirects"
        );
        assert_eq!(format!("{}", ShellFeature::Substitutions), "substitutions");
    }
}

#[cfg(test)]
mod execution_tests {
    use super::*;
    use crate::pest_parser::parse_shell;
    use std::time::Duration;
    use tokio::time::timeout;

    #[tokio::test]
    async fn test_execute_simple_echo() {
        let ast = parse_shell("echo hello").unwrap();
        let shell_cmd = ast_to_shell_string(&ast).unwrap();
        let result = execute_through_shell(&shell_cmd, None).await.unwrap();

        assert!(result.success);
        assert_eq!(result.stdout.trim(), "hello");
        assert_eq!(result.exit_code, 0);
    }

    #[tokio::test]
    async fn test_execute_pwd() {
        let ast = parse_shell("pwd").unwrap();
        let shell_cmd = ast_to_shell_string(&ast).unwrap();
        let result = execute_through_shell(&shell_cmd, None).await.unwrap();

        assert!(result.success);
        assert!(!result.stdout.is_empty());
        assert_eq!(result.exit_code, 0);
    }

    #[tokio::test]
    async fn test_execute_with_cwd() {
        let temp_dir = std::env::temp_dir();
        let ast = parse_shell("pwd").unwrap();
        let shell_cmd = ast_to_shell_string(&ast).unwrap();
        let result = execute_through_shell(&shell_cmd, Some(temp_dir.to_str().unwrap()))
            .await
            .unwrap();

        assert!(result.success);
        assert_eq!(result.stdout.trim(), temp_dir.to_string_lossy());
    }

    #[tokio::test]
    async fn test_execute_safe_pipe() {
        // Test simple pipe with echo to cat (should work)
        let ast = parse_shell("echo hello | cat").unwrap();
        let shell_cmd = ast_to_shell_string(&ast).unwrap();
        let result = execute_through_shell(&shell_cmd, None).await.unwrap();

        assert!(result.success);
        // The pipe should work properly now with shell execution
        assert_eq!(result.stdout.trim(), "hello");
    }

    #[tokio::test]
    async fn test_execute_command_substitution() {
        let ast = parse_shell("echo $(echo hello)").unwrap();
        let shell_cmd = ast_to_shell_string(&ast).unwrap();
        let result = execute_through_shell(&shell_cmd, None).await.unwrap();

        assert!(result.success);
        assert_eq!(result.stdout.trim(), "hello");
    }

    #[tokio::test]
    async fn test_execute_logical_and() {
        let ast = parse_shell("echo first && echo second").unwrap();
        let shell_cmd = ast_to_shell_string(&ast).unwrap();
        let result = execute_through_shell(&shell_cmd, None).await.unwrap();

        assert!(result.success);
        assert!(result.stdout.contains("first"));
        assert!(result.stdout.contains("second"));
        assert_eq!(result.exit_code, 0);
    }

    #[tokio::test]
    async fn test_execute_logical_or() {
        let ast = parse_shell("false || echo success").unwrap();
        let shell_cmd = ast_to_shell_string(&ast).unwrap();
        let result = execute_through_shell(&shell_cmd, None).await.unwrap();

        assert!(result.success);
        assert_eq!(result.stdout.trim(), "success");
    }

    #[tokio::test]
    async fn test_execute_semicolon() {
        let ast = parse_shell("echo first; echo second").unwrap();
        let shell_cmd = ast_to_shell_string(&ast).unwrap();
        let result = execute_through_shell(&shell_cmd, None).await.unwrap();

        assert!(result.success);
        assert!(result.stdout.contains("first"));
        assert!(result.stdout.contains("second"));
        assert_eq!(result.exit_code, 0);
    }

    #[tokio::test]
    async fn test_file_output_redirect() {
        let temp_file = "/tmp/shell_mcp_test_output.txt";

        // Clean up first
        let _ = tokio::fs::remove_file(temp_file).await;

        // Test shell execution with redirect
        let ast = parse_shell(&format!("echo test > {}", temp_file)).unwrap();
        let shell_cmd = ast_to_shell_string(&ast).unwrap();
        let result = execute_through_shell(&shell_cmd, None).await.unwrap();

        assert!(result.success);

        // Verify file was created with correct content
        let content = tokio::fs::read_to_string(temp_file).await.unwrap();
        assert_eq!(content.trim(), "test");

        // Clean up
        let _ = tokio::fs::remove_file(temp_file).await;
    }

    #[tokio::test]
    async fn test_file_append_redirect() {
        let temp_file = "/tmp/shell_mcp_test_append.txt";

        // Clean up first
        let _ = tokio::fs::remove_file(temp_file).await;

        // Test shell execution with append redirect
        let ast1 = parse_shell(&format!("echo first >> {}", temp_file)).unwrap();
        let shell_cmd1 = ast_to_shell_string(&ast1).unwrap();
        let result1 = execute_through_shell(&shell_cmd1, None).await.unwrap();
        assert!(result1.success);

        let ast2 = parse_shell(&format!("echo second >> {}", temp_file)).unwrap();
        let shell_cmd2 = ast_to_shell_string(&ast2).unwrap();
        let result2 = execute_through_shell(&shell_cmd2, None).await.unwrap();
        assert!(result2.success);

        // Verify both lines are present
        let content = tokio::fs::read_to_string(temp_file).await.unwrap();
        assert!(content.contains("first"));
        assert!(content.contains("second"));

        // Clean up
        let _ = tokio::fs::remove_file(temp_file).await;
    }

    #[tokio::test]
    async fn test_command_timeout() {
        let ast = parse_shell("sleep 5").unwrap();
        let shell_cmd = ast_to_shell_string(&ast).unwrap();
        // Use a very short timeout to test functionality
        let timeout_result = timeout(
            Duration::from_millis(100),
            execute_through_shell(&shell_cmd, None),
        )
        .await;

        assert!(timeout_result.is_err()); // Should timeout
    }

    #[tokio::test]
    async fn test_execute_failing_command() {
        let ast = parse_shell("false").unwrap();
        let shell_cmd = ast_to_shell_string(&ast).unwrap();
        let result = execute_through_shell(&shell_cmd, None).await.unwrap();

        assert!(!result.success);
        assert_ne!(result.exit_code, 0);
    }

    #[tokio::test]
    async fn test_execute_nonexistent_command() {
        let ast = parse_shell("this_command_definitely_does_not_exist_12345").unwrap();
        let shell_cmd = ast_to_shell_string(&ast).unwrap();
        let result = execute_through_shell(&shell_cmd, None).await.unwrap();

        assert!(!result.success);
        assert_ne!(result.exit_code, 0);
    }

    #[tokio::test]
    async fn test_nested_command_substitution() {
        let ast = parse_shell("echo $(echo $(echo nested))").unwrap();
        let shell_cmd = ast_to_shell_string(&ast).unwrap();
        let result = execute_through_shell(&shell_cmd, None).await.unwrap();

        assert!(result.success);
        assert_eq!(result.stdout.trim(), "nested");
    }

    #[test]
    fn test_ast_to_shell_simple_command() {
        let ast = parse_shell("echo hello").unwrap();
        let shell_cmd = ast_to_shell_string(&ast).unwrap();
        assert_eq!(shell_cmd, "echo hello");
    }

    #[test]
    fn test_ast_to_shell_command_with_spaces() {
        let ast = parse_shell("echo 'hello world'").unwrap();
        let shell_cmd = ast_to_shell_string(&ast).unwrap();
        assert_eq!(shell_cmd, "echo 'hello world'");
    }

    #[test]
    fn test_ast_to_shell_pipe() {
        let ast = parse_shell("ls | grep test").unwrap();
        let shell_cmd = ast_to_shell_string(&ast).unwrap();
        assert_eq!(shell_cmd, "ls | grep test");
    }

    #[test]
    fn test_ast_to_shell_logical_and() {
        let ast = parse_shell("echo first && echo second").unwrap();
        let shell_cmd = ast_to_shell_string(&ast).unwrap();
        assert_eq!(shell_cmd, "echo first && echo second");
    }

    #[test]
    fn test_ast_to_shell_logical_or() {
        let ast = parse_shell("false || echo backup").unwrap();
        let shell_cmd = ast_to_shell_string(&ast).unwrap();
        assert_eq!(shell_cmd, "false || echo backup");
    }

    #[test]
    fn test_ast_to_shell_semicolon() {
        let ast = parse_shell("echo first; echo second").unwrap();
        let shell_cmd = ast_to_shell_string(&ast).unwrap();
        assert_eq!(shell_cmd, "echo first; echo second");
    }

    #[test]
    fn test_ast_to_shell_output_redirect() {
        let ast = parse_shell("echo test > output.txt").unwrap();
        let shell_cmd = ast_to_shell_string(&ast).unwrap();
        assert_eq!(shell_cmd, "echo test > output.txt");
    }

    #[test]
    fn test_ast_to_shell_append_redirect() {
        let ast = parse_shell("echo test >> output.txt").unwrap();
        let shell_cmd = ast_to_shell_string(&ast).unwrap();
        assert_eq!(shell_cmd, "echo test >> output.txt");
    }

    #[test]
    fn test_ast_to_shell_input_redirect() {
        let ast = parse_shell("grep pattern < input.txt").unwrap();
        let shell_cmd = ast_to_shell_string(&ast).unwrap();
        assert_eq!(shell_cmd, "grep pattern < input.txt");
    }

    #[test]
    fn test_ast_to_shell_command_substitution() {
        let ast = parse_shell("echo $(date)").unwrap();
        let shell_cmd = ast_to_shell_string(&ast).unwrap();
        assert_eq!(shell_cmd, "echo $(date)");
    }

    #[test]
    fn test_ast_to_shell_nested_command_substitution() {
        let ast = parse_shell("echo $(echo $(echo nested))").unwrap();
        let shell_cmd = ast_to_shell_string(&ast).unwrap();
        assert_eq!(shell_cmd, "echo $(echo $(echo nested))");
    }

    #[test]
    fn test_ast_to_shell_complex_command() {
        let ast = parse_shell("cat file.txt | grep pattern > output.log && echo done").unwrap();
        let shell_cmd = ast_to_shell_string(&ast).unwrap();
        assert_eq!(
            shell_cmd,
            "cat file.txt | grep pattern > output.log && echo done"
        );
    }
}
