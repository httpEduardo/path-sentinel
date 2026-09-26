use regex::Regex;
use std::env;
use std::fs;
use std::process::ExitCode;

/// A risk indicator that can be attached to a path.
struct Rule {
    tag: &'static str,
    pattern: Regex,
}

fn rules() -> Vec<Rule> {
    let rule = |tag, pattern| Rule {
        tag,
        pattern: Regex::new(pattern).expect("invalid built-in pattern"),
    };
    vec![
        // "..", as a whole path segment
        rule("traversal", r"(^|/)\.\.(/|$)"),
        // /etc/..., C:/..., //server/share
        rule("absolute", r"^(/|[A-Za-z]:/|//)"),
        rule(
            "secrets",
            r"(?i)(^|/)(\.env(\..*)?|id_rsa|id_ed25519|\.ssh|\.aws|credentials(\.json)?|passwd|shadow|\.htpasswd|wp-config\.php|web\.config)(/|$)",
        ),
        rule("vcs", r"(?i)(^|/)\.(git|svn|hg)(/|$)"),
        rule(
            "backup",
            r"(?i)(\.(bak|old|orig|swp|sql|dump|tar|gz|zip)$|~$|(^|/)backups?(/|$))",
        ),
        rule("admin", r"(?i)(^|/)admin(/|$)"),
    ]
}

/// Decodes percent-encoding (up to two layers, to catch double encoding)
/// and normalizes Windows separators so every rule sees the same shape.
fn normalize(raw: &str) -> (String, bool) {
    let mut current = raw.to_string();
    let mut encoded = false;
    for _ in 0..2 {
        let decoded = percent_decode(&current);
        if decoded == current {
            break;
        }
        encoded = true;
        current = decoded;
    }
    (current.replace('\\', "/"), encoded)
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let decoded = std::str::from_utf8(&bytes[i + 1..i + 3])
                .ok()
                .and_then(|hex| u8::from_str_radix(hex, 16).ok());
            if let Some(b) = decoded {
                out.push(b);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn tag_path(raw: &str, rules: &[Rule]) -> Vec<&'static str> {
    let (path, encoded) = normalize(raw);
    let mut tags: Vec<&'static str> = rules
        .iter()
        .filter(|r| r.pattern.is_match(&path))
        .map(|r| r.tag)
        .collect();
    if path.contains('\0') {
        tags.push("null-byte");
    }
    if encoded && !tags.is_empty() {
        tags.push("encoded");
    }
    tags
}

fn input_path() -> Result<String, String> {
    let args: Vec<String> = env::args().skip(1).collect();
    match args.as_slice() {
        [] => Ok("paths.txt".to_string()),
        [flag, value] if flag == "--input" || flag == "-i" => Ok(value.clone()),
        [flag] if flag == "--help" || flag == "-h" => Err(String::new()),
        _ => Err("unrecognized arguments".to_string()),
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    if matches!(args.as_slice(), [flag] if flag == "--help" || flag == "-h") {
        println!("usage: path-sentinel [--input FILE]");
        println!("  --input, -i  file with one path per line (default: paths.txt)");
        println!("  --help, -h   show this help");
        return ExitCode::SUCCESS;
    }
    let input = match input_path() {
        Ok(path) => path,
        Err(msg) => {
            if !msg.is_empty() {
                eprintln!("error: {msg}");
            }
            eprintln!("usage: path-sentinel [--input FILE]");
            return ExitCode::from(2);
        }
    };

    let raw = match fs::read_to_string(&input) {
        Ok(raw) => raw,
        Err(e) => {
            eprintln!("error: cannot read {input}: {e}");
            return ExitCode::from(2);
        }
    };

    let rules = rules();
    let mut flagged = 0;
    let mut total = 0;
    for line in raw.lines() {
        let path = line.trim();
        if path.is_empty() || path.starts_with('#') {
            continue;
        }
        total += 1;
        let tags = tag_path(path, &rules);
        if tags.is_empty() {
            println!("ok       {path}");
        } else {
            flagged += 1;
            println!("FLAGGED  {path}  [{}]", tags.join(", "));
        }
    }
    println!("\n{flagged} of {total} paths flagged");

    if flagged > 0 {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tags(path: &str) -> Vec<&'static str> {
        tag_path(path, &rules())
    }

    #[test]
    fn detects_unix_and_windows_traversal() {
        assert!(tags("../../etc/passwd").contains(&"traversal"));
        assert!(tags(r"..\..\windows\win.ini").contains(&"traversal"));
    }

    #[test]
    fn detects_encoded_traversal() {
        let t = tags("%2e%2e%2f%2e%2e%2fetc%2fpasswd");
        assert!(t.contains(&"traversal") && t.contains(&"encoded"));
        assert!(tags("%252e%252e%252fsecret").contains(&"traversal"));
    }

    #[test]
    fn dots_inside_names_are_not_traversal() {
        assert!(tags("docs/v1..v2/notes.txt").is_empty());
    }

    #[test]
    fn detects_sensitive_targets() {
        assert!(tags("/var/www/.env").contains(&"secrets"));
        assert!(tags(r"C:\Users\me\.ssh\id_rsa").contains(&"secrets"));
        assert!(tags("repo/.git/config").contains(&"vcs"));
        assert!(tags("backup/db.sql").contains(&"backup"));
    }

    #[test]
    fn detects_null_byte() {
        assert!(tags("avatar.php%00.png").contains(&"null-byte"));
    }

    #[test]
    fn plain_upload_is_clean() {
        assert!(tags("./uploads/avatar.png").is_empty());
    }
}
