use regex::Regex;
use std::env;
use std::fs;

fn parse_args() -> String {
    let args: Vec<String> = env::args().collect();
    args.iter()
        .position(|arg| arg == "--input")
        .and_then(|idx| args.get(idx + 1))
        .cloned()
        .unwrap_or_else(|| "paths.txt".to_string())
}

fn tag_path(path: &str, traversal_re: &Regex, secrets_re: &Regex, backup_re: &Regex) -> Vec<String> {
    let mut tags = Vec::new();
    if traversal_re.is_match(path) {
        tags.push("traversal".to_string());
    }
    if secrets_re.is_match(path) {
        tags.push("secrets".to_string());
    }
    if backup_re.is_match(path) {
        tags.push("backup".to_string());
    }
    if path.contains("/admin") || path.contains("\\\\admin") {
        tags.push("admin".to_string());
    }
    if tags.is_empty() {
        tags.push("ok".to_string());
    }
    tags
}

fn main() {
    let input = parse_args();
    let raw = fs::read_to_string(&input).expect("Failed to read paths file");

    let traversal_re = Regex::new(r"(\\.\\./|\\.\\.\\\\)").unwrap();
    let secrets_re = Regex::new(r"(?i)(\\.env|id_rsa|\\.ssh|credentials|passwd)").unwrap();
    let backup_re = Regex::new(r"(?i)(\\.bak$|\\.sql$|backup)").unwrap();

    for line in raw.lines() {
        let path = line.trim();
        if path.is_empty() {
            continue;
        }
        let tags = tag_path(path, &traversal_re, &secrets_re, &backup_re);
        println!("{path} -> {}", tags.join(", "));
    }
}
