use tokio::process::Command;

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
    allowed_commands: &std::collections::HashSet<String>,
) -> Result<(), String> {
    match ast {
        ShellNode::Command {
            args,
            substitutions,
            ..
        } => {
            // Check the first arg if it's a literal command
            if let Some(Arg::Literal(cmd)) = args.first() {
                if !allowed_commands.contains(cmd) {
                    return Err(format!("Command '{}' is not in the whitelist", cmd));
                }
            }
            // Validate all substitutions
            for subst in substitutions {
                validate_ast(subst, allowed_commands)?;
            }
        }
        ShellNode::Pipe(left, right)
        | ShellNode::And(left, right)
        | ShellNode::Or(left, right)
        | ShellNode::Semicolon(left, right) => {
            validate_ast(left, allowed_commands)?;
            validate_ast(right, allowed_commands)?;
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
