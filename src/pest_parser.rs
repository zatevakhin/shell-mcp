use pest::Parser;
use pest_derive::Parser;

#[derive(Parser)]
#[grammar = "src/shell.pest"]
pub struct ShellParser;

pub use super::shell::{Redirect, ShellNode};

pub fn parse_shell(input: &str) -> Option<ShellNode> {
    let pairs = match ShellParser::parse(Rule::expression, input) {
        Ok(pairs) => pairs,
        Err(_) => return None,
    };

    let mut pairs_iter = pairs.into_iter();

    if let Some(pair) = pairs_iter.next() {
        let expected_end = input.trim_end().len();
        let actual_end = pair.as_span().end();
        if actual_end != expected_end {
            return None;
        }
        parse_expression(pair)
    } else {
        None
    }
}

fn parse_expression(pair: pest::iterators::Pair<Rule>) -> Option<ShellNode> {
    match pair.as_rule() {
        Rule::expression => {
            let mut inner = pair.into_inner();
            let mut left = match parse_pipe_expression(inner.next()?) {
                Some(cmd) => cmd,
                None => return None,
            };

            while let Some(op) = inner.next() {
                match op.as_rule() {
                    Rule::logical_op => {
                        let op_str = op.as_str();
                        let right = match parse_pipe_expression(inner.next()?) {
                            Some(cmd) => cmd,
                            None => return None,
                        };
                        left = match op_str {
                            "&&" => ShellNode::And(Box::new(left), Box::new(right)),
                            "||" => ShellNode::Or(Box::new(left), Box::new(right)),
                            _ => unreachable!(),
                        };
                    }
                    Rule::semicolon_op => {
                        let right = match parse_expression(inner.next()?) {
                            Some(expr) => expr,
                            None => return None,
                        };
                        left = ShellNode::Semicolon(Box::new(left), Box::new(right));
                    }
                    _ => break,
                }
            }

            Some(left)
        }
        _ => parse_pipe_expression(pair),
    }
}

fn parse_pipe_expression(pair: pest::iterators::Pair<Rule>) -> Option<ShellNode> {
    match pair.as_rule() {
        Rule::pipe_expression => {
            let mut inner = pair.into_inner();
            let mut left = match parse_command(inner.next()?) {
                Some(cmd) => cmd,
                None => return None,
            };

            while let Some(pipe_op) = inner.next() {
                match pipe_op.as_rule() {
                    Rule::pipe_op => {
                        let right = match parse_command(inner.next()?) {
                            Some(cmd) => cmd,
                            None => return None,
                        };
                        left = ShellNode::Pipe(Box::new(left), Box::new(right));
                    }
                    _ => return None,
                }
            }

            Some(left)
        }
        _ => parse_command(pair),
    }
}

fn parse_command(pair: pest::iterators::Pair<Rule>) -> Option<ShellNode> {
    let mut args: Vec<crate::shell::Arg> = Vec::new();
    let mut redirects: Vec<Redirect> = Vec::new();
    let mut substitutions: Vec<ShellNode> = Vec::new();

    for inner_pair in pair.into_inner() {
        match inner_pair.as_rule() {
            Rule::command_text => {
                let command_str = inner_pair.as_str().trim();
                if !command_str.is_empty() {
                    let split_args = match shell_split(command_str) {
                        Some(a) => a,
                        None => return None,
                    };
                    args.extend(split_args.into_iter().map(crate::shell::Arg::Literal));
                }
            }
            Rule::substitution => {
                // substitution -> "$(" expression ")"
                let mut inner = inner_pair.into_inner();
                let expr_pair = inner.next()?;
                let inner_ast = match parse_expression(expr_pair) {
                    Some(a) => a,
                    None => return None,
                };
                args.push(crate::shell::Arg::Substitution(substitutions.len()));
                substitutions.push(inner_ast);
            }
            Rule::backtick_substitution => {
                let s = inner_pair.as_str();
                if s.len() >= 2 {
                    let inner_str = &s[1..s.len() - 1];
                    let inner_ast = match parse_shell(inner_str) {
                        Some(a) => a,
                        None => return None,
                    };
                    args.push(crate::shell::Arg::Substitution(substitutions.len()));
                    substitutions.push(inner_ast);
                } else {
                    return None;
                }
            }
            Rule::redirect => {
                let redirect = match parse_redirect(inner_pair) {
                    Some(r) => r,
                    None => return None,
                };
                redirects.push(redirect);
            }
            _ => unreachable!(),
        }
    }

    if args.is_empty() {
        return None;
    }

    Some(ShellNode::Command {
        args,
        redirects,
        substitutions,
    })
}

fn shell_split(input: &str) -> Option<Vec<String>> {
    match shlex::split(input) {
        Some(args) if !args.is_empty() => Some(args),
        _ => None,
    }
}

fn parse_redirect(pair: pest::iterators::Pair<Rule>) -> Option<Redirect> {
    let mut inner = pair.into_inner();
    let op = inner.next().unwrap();
    let filename = inner.next().unwrap().as_str().to_string();

    match op.as_str() {
        ">" => Some(Redirect::Output(filename, false)),
        ">>" => Some(Redirect::Output(filename, true)),
        "<" => Some(Redirect::Input(filename)),
        _ => unreachable!(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shell::{FeatureConfig, validate_ast};
    use std::collections::HashSet;

    #[test]
    fn test_parse_simple_command() {
        let result = parse_shell("ls -la");
        assert!(result.is_some());
        let ast = result.unwrap();
        match ast {
            ShellNode::Command {
                args,
                redirects,
                substitutions,
            } => {
                assert_eq!(args, vec!["ls", "-la"]);
                assert!(redirects.is_empty());
                assert!(substitutions.is_empty());
            }
            _ => panic!("Expected Command"),
        }
    }

    #[test]
    fn test_parse_pipe() {
        let result = parse_shell("ls | grep txt");
        assert!(result.is_some());
        let ast = result.unwrap();
        match ast {
            ShellNode::Pipe(left, right) => {
                match *left {
                    ShellNode::Command {
                        args,
                        substitutions,
                        ..
                    } => {
                        assert_eq!(args, vec!["ls"]);
                        assert!(substitutions.is_empty());
                    }
                    _ => panic!("Expected Command"),
                }
                match *right {
                    ShellNode::Command {
                        args,
                        substitutions,
                        ..
                    } => {
                        assert_eq!(args, vec!["grep", "txt"]);
                        assert!(substitutions.is_empty());
                    }
                    _ => panic!("Expected Command"),
                }
            }
            _ => panic!("Expected Pipe"),
        }
    }

    #[test]
    fn test_validation_integration() {
        let mut allowed = HashSet::new();
        allowed.insert("ls".to_string());
        allowed.insert("grep".to_string());

        let command_config = crate::shell::CommandConfig {
            allow_all: false,
            allowed_commands: allowed,
            disabled_commands: HashSet::new(),
        };
        let ast = parse_shell("ls | grep txt").unwrap();

        // Test that validation works with pest-generated AST
        assert!(validate_ast(&ast, &command_config, &FeatureConfig::default()).is_ok());
    }

    #[test]
    fn test_parse_semicolon() {
        let ast = parse_shell("ls ; pwd").unwrap();
        match ast {
            ShellNode::Semicolon(left, right) => {
                match *left {
                    ShellNode::Command {
                        args,
                        substitutions,
                        ..
                    } => {
                        assert_eq!(args, vec!["ls"]);
                        assert!(substitutions.is_empty());
                    }
                    _ => panic!("Expected Command"),
                }
                match *right {
                    ShellNode::Command {
                        args,
                        substitutions,
                        ..
                    } => {
                        assert_eq!(args, vec!["pwd"]);
                        assert!(substitutions.is_empty());
                    }
                    _ => panic!("Expected Command"),
                }
            }
            _ => panic!("Expected Semicolon"),
        }
    }

    #[test]
    fn test_parse_redirect() {
        let ast = parse_shell("cat file.txt > output.txt").unwrap();
        match ast {
            ShellNode::Command {
                args,
                redirects,
                substitutions,
            } => {
                assert_eq!(args, vec!["cat", "file.txt"]);
                assert_eq!(redirects.len(), 1);
                match &redirects[0] {
                    Redirect::Output(filename, append) => {
                        assert_eq!(filename, "output.txt");
                        assert!(!*append);
                    }
                    _ => panic!("Expected Output redirect"),
                }
                assert!(substitutions.is_empty());
            }
            _ => panic!("Expected Command"),
        }
    }

    #[test]
    fn test_validate_allowed_command() {
        let mut allowed = HashSet::new();
        allowed.insert("ls".to_string());
        allowed.insert("grep".to_string());

        let command_config = crate::shell::CommandConfig {
            allow_all: false,
            allowed_commands: allowed,
            disabled_commands: HashSet::new(),
        };
        let ast = parse_shell("ls -la | grep txt").unwrap();
        assert!(validate_ast(&ast, &command_config, &FeatureConfig::default()).is_ok());
    }

    #[test]
    fn test_validate_disallowed_command() {
        let mut allowed = HashSet::new();
        allowed.insert("ls".to_string());

        let command_config = crate::shell::CommandConfig {
            allow_all: false,
            allowed_commands: allowed,
            disabled_commands: HashSet::new(),
        };
        let ast = parse_shell("ls | rm -rf /").unwrap();
        assert!(validate_ast(&ast, &command_config, &FeatureConfig::default()).is_err());
    }

    #[test]
    fn test_unclosed_quote() {
        let result = parse_shell("echo \"hello");
        assert!(result.is_none(), "Parser should fail on unclosed quotes");
    }

    #[test]
    fn test_empty_command_in_pipe() {
        let result = parse_shell("ls | | grep txt");
        assert!(
            result.is_none(),
            "Parser should fail on empty command in pipe"
        );
    }

    #[test]
    fn test_disallowed_command_in_substitution() {
        let mut allowed = HashSet::new();
        allowed.insert("echo".to_string());
        let command_config = crate::shell::CommandConfig {
            allow_all: false,
            allowed_commands: allowed,
            disabled_commands: HashSet::new(),
        };
        let ast = parse_shell("echo $(rm -rf /)").unwrap();
        // Now this should fail because rm is not in the allowed list
        assert!(validate_ast(&ast, &command_config, &FeatureConfig::default()).is_err());
    }

    #[test]
    fn test_allowed_command_in_substitution() {
        let mut allowed = HashSet::new();
        allowed.insert("echo".to_string());
        allowed.insert("date".to_string());
        let command_config = crate::shell::CommandConfig {
            allow_all: false,
            allowed_commands: allowed,
            disabled_commands: HashSet::new(),
        };
        let ast = parse_shell("echo $(date)").unwrap();
        assert!(validate_ast(&ast, &command_config, &FeatureConfig::default()).is_ok());
    }

    #[test]
    fn test_nested_substitution_validation() {
        let mut allowed = HashSet::new();
        allowed.insert("echo".to_string());
        allowed.insert("cat".to_string());
        let command_config = crate::shell::CommandConfig {
            allow_all: false,
            allowed_commands: allowed,
            disabled_commands: HashSet::new(),
        };
        let ast = parse_shell("echo $(cat $(echo hello))").unwrap();
        assert!(validate_ast(&ast, &command_config, &FeatureConfig::default()).is_ok());
    }

    #[test]
    fn test_nested_substitution_with_disallowed() {
        let mut allowed = HashSet::new();
        allowed.insert("echo".to_string());
        allowed.insert("cat".to_string());
        let command_config = crate::shell::CommandConfig {
            allow_all: false,
            allowed_commands: allowed,
            disabled_commands: HashSet::new(),
        };
        let ast = parse_shell("echo $(cat $(rm -rf /))").unwrap();
        assert!(validate_ast(&ast, &command_config, &FeatureConfig::default()).is_err());
    }

    #[test]
    fn test_backtick_substitution_validation() {
        let mut allowed = HashSet::new();
        allowed.insert("echo".to_string());
        allowed.insert("date".to_string());
        let command_config = crate::shell::CommandConfig {
            allow_all: false,
            allowed_commands: allowed,
            disabled_commands: HashSet::new(),
        };
        let ast = parse_shell("echo `date`").unwrap();
        assert!(validate_ast(&ast, &command_config, &FeatureConfig::default()).is_ok());
    }

    #[test]
    fn test_backtick_substitution_with_disallowed() {
        let mut allowed = HashSet::new();
        allowed.insert("echo".to_string());
        let command_config = crate::shell::CommandConfig {
            allow_all: false,
            allowed_commands: allowed,
            disabled_commands: HashSet::new(),
        };
        let ast = parse_shell("echo `rm -rf /`").unwrap();
        assert!(validate_ast(&ast, &command_config, &FeatureConfig::default()).is_err());
    }

    #[test]
    fn test_mixed_substitution_types() {
        let mut allowed = HashSet::new();
        allowed.insert("echo".to_string());
        allowed.insert("date".to_string());
        allowed.insert("pwd".to_string());
        let command_config = crate::shell::CommandConfig {
            allow_all: false,
            allowed_commands: allowed,
            disabled_commands: HashSet::new(),
        };
        let ast = parse_shell("echo $(date) `pwd`").unwrap();
        assert!(validate_ast(&ast, &command_config, &FeatureConfig::default()).is_ok());
    }

    #[test]
    fn test_complex_substitution_with_pipe() {
        let mut allowed = HashSet::new();
        allowed.insert("echo".to_string());
        allowed.insert("cat".to_string());
        allowed.insert("grep".to_string());
        let command_config = crate::shell::CommandConfig {
            allow_all: false,
            allowed_commands: allowed,
            disabled_commands: HashSet::new(),
        };
        let ast = parse_shell("echo $(cat file.txt | grep pattern)").unwrap();
        assert!(validate_ast(&ast, &command_config, &FeatureConfig::default()).is_ok());
    }

    #[test]
    fn test_complex_substitution_with_disallowed_pipe() {
        let mut allowed = HashSet::new();
        allowed.insert("echo".to_string());
        allowed.insert("cat".to_string());
        let command_config = crate::shell::CommandConfig {
            allow_all: false,
            allowed_commands: allowed,
            disabled_commands: HashSet::new(),
        };
        let ast = parse_shell("echo $(cat file.txt | rm -rf /)").unwrap();
        assert!(validate_ast(&ast, &command_config, &FeatureConfig::default()).is_err());
    }

    #[test]
    fn test_backtick_substitution() {
        let ast = parse_shell("echo `date`").unwrap();
        match ast {
            ShellNode::Command {
                args,
                redirects,
                substitutions,
            } => {
                // Check args
                assert_eq!(args.len(), 2);
                match &args[0] {
                    crate::shell::Arg::Literal(s) => assert_eq!(s, "echo"),
                    _ => panic!("Expected Literal"),
                }
                match &args[1] {
                    crate::shell::Arg::Substitution(idx) => assert_eq!(*idx, 0),
                    _ => panic!("Expected Substitution"),
                }
                assert!(redirects.is_empty());
                // Check substitutions
                assert_eq!(substitutions.len(), 1);
                match &substitutions[0] {
                    ShellNode::Command {
                        args, redirects, ..
                    } => {
                        assert_eq!(args.len(), 1);
                        match &args[0] {
                            crate::shell::Arg::Literal(s) => assert_eq!(s, "date"),
                            _ => panic!("Expected Literal"),
                        }
                        assert!(redirects.is_empty());
                    }
                    _ => panic!("Expected Command in substitution"),
                }
            }
            _ => panic!("Expected Command"),
        }
    }

    #[test]
    fn test_parse_append_redirect() {
        let ast = parse_shell("echo 'hello' >> file.txt").unwrap();
        match ast {
            ShellNode::Command {
                args,
                redirects,
                substitutions,
            } => {
                assert_eq!(args, vec!["echo", "hello"]);
                assert_eq!(redirects.len(), 1);
                match &redirects[0] {
                    Redirect::Output(filename, append) => {
                        assert_eq!(filename, "file.txt");
                        assert!(*append);
                    }
                    _ => panic!("Expected Output redirect"),
                }
                assert!(substitutions.is_empty());
            }
            _ => panic!("Expected Command"),
        }
    }

    #[test]
    fn test_parse_input_redirect() {
        let ast = parse_shell("grep 'pattern' < input.txt").unwrap();
        match ast {
            ShellNode::Command {
                args,
                redirects,
                substitutions,
            } => {
                assert_eq!(args, vec!["grep", "pattern"]);
                assert_eq!(redirects.len(), 1);
                match &redirects[0] {
                    Redirect::Input(filename) => {
                        assert_eq!(filename, "input.txt");
                    }
                    _ => panic!("Expected Input redirect"),
                }
                assert!(substitutions.is_empty());
            }
            _ => panic!("Expected Command"),
        }
    }

    #[test]
    fn test_parse_logical_and() {
        let ast = parse_shell("ls && pwd").unwrap();
        match ast {
            ShellNode::And(left, right) => {
                match *left {
                    ShellNode::Command {
                        args,
                        substitutions,
                        ..
                    } => {
                        assert_eq!(args, vec!["ls"]);
                        assert!(substitutions.is_empty());
                    }
                    _ => panic!("Expected Command"),
                }
                match *right {
                    ShellNode::Command {
                        args,
                        substitutions,
                        ..
                    } => {
                        assert_eq!(args, vec!["pwd"]);
                        assert!(substitutions.is_empty());
                    }
                    _ => panic!("Expected Command"),
                }
            }
            _ => panic!("Expected And"),
        }
    }

    #[test]
    fn test_parse_logical_or() {
        let ast = parse_shell("ls || pwd").unwrap();
        match ast {
            ShellNode::Or(left, right) => {
                match *left {
                    ShellNode::Command {
                        args,
                        substitutions,
                        ..
                    } => {
                        assert_eq!(args, vec!["ls"]);
                        assert!(substitutions.is_empty());
                    }
                    _ => panic!("Expected Command"),
                }
                match *right {
                    ShellNode::Command {
                        args,
                        substitutions,
                        ..
                    } => {
                        assert_eq!(args, vec!["pwd"]);
                        assert!(substitutions.is_empty());
                    }
                    _ => panic!("Expected Command"),
                }
            }
            _ => panic!("Expected Or"),
        }
    }

    #[test]
    fn test_parse_complex_command() {
        let ast = parse_shell("cat input.txt | grep 'error' > output.log && echo 'done'").unwrap();
        match ast {
            ShellNode::And(left, right) => {
                match *left {
                    ShellNode::Pipe(pipe_left, pipe_right) => {
                        match *pipe_left {
                            ShellNode::Command {
                                args,
                                redirects,
                                substitutions,
                            } => {
                                assert_eq!(args, vec!["cat", "input.txt"]);
                                assert!(redirects.is_empty());
                                assert!(substitutions.is_empty());
                            }
                            _ => panic!("Expected Command"),
                        }
                        match *pipe_right {
                            ShellNode::Command {
                                args,
                                redirects,
                                substitutions,
                            } => {
                                assert_eq!(args, vec!["grep", "error"]);
                                assert_eq!(redirects.len(), 1);
                                assert!(substitutions.is_empty());
                            }
                            _ => panic!("Expected Command"),
                        }
                    }
                    _ => panic!("Expected Pipe"),
                }
                // Right side: echo 'done'
                match *right {
                    ShellNode::Command {
                        args,
                        redirects,
                        substitutions,
                    } => {
                        assert_eq!(args, vec!["echo", "done"]);
                        assert!(redirects.is_empty());
                        assert!(substitutions.is_empty());
                    }
                    _ => panic!("Expected Command"),
                }
            }
            _ => panic!("Expected And"),
        }
    }

    #[test]
    fn test_parse_command_substitution() {
        let ast = parse_shell("echo $(date +%Y)").unwrap();
        match ast {
            ShellNode::Command {
                args,
                redirects,
                substitutions,
            } => {
                assert_eq!(args.len(), 2);
                match &args[0] {
                    crate::shell::Arg::Literal(s) => assert_eq!(s, "echo"),
                    _ => panic!("Expected Literal"),
                }
                match &args[1] {
                    crate::shell::Arg::Substitution(idx) => assert_eq!(*idx, 0),
                    _ => panic!("Expected Substitution"),
                }
                assert!(redirects.is_empty());
                assert_eq!(substitutions.len(), 1);
                match &substitutions[0] {
                    ShellNode::Command {
                        args, redirects, ..
                    } => {
                        assert_eq!(args.len(), 2);
                        match &args[0] {
                            crate::shell::Arg::Literal(s) => assert_eq!(s, "date"),
                            _ => panic!("Expected Literal"),
                        }
                        match &args[1] {
                            crate::shell::Arg::Literal(s) => assert_eq!(s, "+%Y"),
                            _ => panic!("Expected Literal"),
                        }
                        assert!(redirects.is_empty());
                    }
                    _ => panic!("Expected Command in substitution"),
                }
            }
            _ => panic!("Expected Command"),
        }
    }

    #[test]
    fn test_parse_empty_input() {
        let result = parse_shell("");
        assert!(
            result.is_none(),
            "Parser should return None for empty input"
        );
    }

    #[test]
    fn test_parse_whitespace_only() {
        let result = parse_shell("   \t\n  ");
        assert!(
            result.is_none(),
            "Parser should return None for whitespace-only input"
        );
    }

    #[test]
    fn test_parse_multiple_spaces() {
        let ast = parse_shell("ls    -la    --color").unwrap();
        match ast {
            ShellNode::Command {
                args,
                redirects,
                substitutions,
            } => {
                assert_eq!(args, vec!["ls", "-la", "--color"]);
                assert!(redirects.is_empty());
                assert!(substitutions.is_empty());
            }
            _ => panic!("Expected Command"),
        }
    }
}
