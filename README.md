# path-sentinel

A small command-line tool that reviews a list of file paths and flags the ones that look like path traversal attempts or point at sensitive files.

It's meant for quick triage: paste in paths pulled from access logs, upload filenames, or parameters captured during a pentest, and see at a glance which ones deserve a closer look.

## What it flags

| Tag | Meaning |
|-----|---------|
| `traversal` | Contains a `..` path segment (`../`, `..\`) |
| `absolute` | Absolute path: `/etc/...`, `C:\...` or a UNC share |
| `secrets` | Targets credentials or config: `.env`, `id_rsa`, `.ssh`, `.aws`, `passwd`, `shadow`, `.htpasswd`, `wp-config.php`, `web.config` |
| `vcs` | Reaches into `.git`, `.svn` or `.hg` |
| `backup` | Backup or dump files: `.bak`, `.old`, `.swp`, `.sql`, `.dump`, archives, `backup/` folders |
| `admin` | Contains an `admin` segment |
| `null-byte` | Contains `%00`, a classic trick to cut off an enforced extension |
| `encoded` | The finding only appears after URL-decoding (including double encoding like `%252e`) |

Before matching, each path is URL-decoded (up to two layers) and backslashes are converted to forward slashes, so `..\..\`, `%2e%2e%2f` and `../../` are all treated the same. Matching works on whole path segments, so a name like `v1..v2` isn't mistaken for traversal.

## Usage

```bash
cargo run --release -- --input paths.txt
```

```text
FLAGGED  ../../etc/passwd  [traversal, secrets]
ok       ./uploads/avatar.png
FLAGGED  /var/www/.env  [absolute, secrets]
FLAGGED  C:\Users\user\.ssh\id_rsa  [absolute, secrets]
FLAGGED  backup/db.bak  [backup]
FLAGGED  %2e%2e%2f%2e%2e%2fconfig%2fsettings.yml  [traversal, encoded]
FLAGGED  static/.git/config  [vcs]
FLAGGED  avatar.php%00.png  [null-byte, encoded]

7 of 8 paths flagged
```

The input file has one path per line; blank lines and lines starting with `#` are ignored. If `--input` is omitted, `paths.txt` is used.

Exit codes: `0` when nothing is flagged, `1` when at least one path is flagged, `2` for bad arguments or an unreadable file — so it can be used as a check in scripts.

## Building

```bash
cargo build --release
./target/release/path-sentinel --input paths.txt
```

Run the tests with `cargo test`.

## Limitations

This is pattern matching, not path resolution. It tells you a path *looks* dangerous; whether it actually escapes a directory depends on how the application joins and resolves it. Treat a flag as a lead to investigate.

## License

[MIT](LICENSE)
