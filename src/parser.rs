use regex::Regex;
use std::sync::LazyLock;
use tree_sitter::{Node, Parser};

pub fn clean(cmd: &str) -> String {
    static ENV: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r#"^[A-Za-z_][A-Za-z0-9_]*=(?:'[^']*'|"[^"]*"|\S+)\s*"#).unwrap()
    });
    let text = cmd.replace("\\\r\n", " ").replace("\\\n", " ");
    let mut s = text.trim();
    while (s.starts_with('(') && s.ends_with(')')) || (s.starts_with('{') && s.ends_with('}')) {
        s = s[1..s.len() - 1].trim();
    }
    while let Some(m) = ENV.find(s) {
        s = s[m.end()..].trim_start();
    }
    s.trim().into()
}
fn children(node: Node<'_>) -> Vec<Node<'_>> {
    let mut c = node.walk();
    node.children(&mut c).collect()
}
fn substitutions(node: Node<'_>, src: &str, out: &mut Vec<String>) {
    for child in children(node) {
        if matches!(
            child.kind(),
            "command_substitution" | "process_substitution"
        ) {
            walk(child, src, out);
        } else {
            substitutions(child, src, out);
        }
    }
}
fn append(s: &str, out: &mut Vec<String>) {
    let s = clean(s);
    if !s.is_empty() {
        out.push(s);
    }
}
fn walk(node: Node<'_>, src: &str, out: &mut Vec<String>) {
    match node.kind() {
        "variable_assignment" => (),
        "command" => {
            append(&src[node.byte_range()], out);
            substitutions(node, src, out);
        }
        "redirected_statement" => {
            let body = node.child_by_field_name("body").or_else(|| node.child(0));
            match body.map(|n| n.kind()) {
                Some("subshell" | "compound_statement") => walk(body.unwrap(), src, out),
                Some("list" | "pipeline") => {
                    let nodes: Vec<_> = children(body.unwrap())
                        .into_iter()
                        .filter(|n| n.is_named())
                        .collect();
                    for (i, n) in nodes.iter().enumerate() {
                        let end = if i + 1 == nodes.len() {
                            node.end_byte()
                        } else {
                            n.end_byte()
                        };
                        append(&src[n.start_byte()..end], out);
                    }
                }
                _ => {
                    append(&src[node.byte_range()], out);
                    substitutions(node, src, out);
                }
            }
        }
        _ if node.is_named() => {
            for n in children(node) {
                if n.is_named() {
                    walk(n, src, out);
                }
            }
        }
        _ => (),
    }
}
pub fn commands(src: &str) -> Vec<String> {
    if src.trim().is_empty() {
        return vec![];
    }
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_bash::LANGUAGE.into())
        .expect("bundled bash grammar");
    let mut out = vec![];
    if let Some(tree) = parser.parse(src, None) {
        walk(tree.root_node(), src, &mut out);
    }
    if out.is_empty() {
        append(src, &mut out);
    }
    out
}
