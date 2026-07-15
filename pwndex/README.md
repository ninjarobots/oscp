# pwndex

A terminal-based CVE and PoC hunter for penetration testers. Searches SearchSploit and GitHub simultaneously, scores results by relevance, and presents them in an interactive TUI where you can browse descriptions, read READMEs, and clone promising repos — all without leaving the terminal.

Built as a faster, more targeted alternative to running `searchsploit` alone. Useful when you're staring at an unfamiliar service during a lab or exam and need to find working exploits quickly.

---

## Install

```bash
git clone https://github.com/youruser/pwndex
cd pwndex
sudo ./install.sh
```

To uninstall:
```bash
sudo ./install.sh --uninstall
```

### Dependencies

Installed automatically via apt:

| Package | Purpose |
|---|---|
| `python3-rich` | Markdown rendering in the detail pane |
| `git` | Cloning repos from within the TUI |
| `exploitdb` | Provides `searchsploit` (Kali only, optional) |
| `ddgr` / `googler` | Web search fallback (optional) |

### GitHub Token (recommended)

The GitHub API rate-limits unauthenticated requests aggressively. Set a token to avoid hitting limits mid-search:

```bash
export GITHUB_TOKEN=ghp_yourtoken
# Add to ~/.bashrc or ~/.zshrc to persist
```

Generate one at: https://github.com/settings/tokens (no scopes needed for public repo search)

---

## Usage

```
pwndex <service> [version] [options]
```

```bash
pwndex vesta
pwndex apache 2.4.49
pwndex "vesta cp" 19.09 --rce
pwndex nginx 1.14 --lpe --open
pwndex proftpd 1.3.5 --no-github
pwndex openssh 7.4 --auth
```

---

## TUI Keys

| Key | Action |
|---|---|
| `↑` / `↓` / `j` / `k` | Navigate results |
| `PgUp` / `PgDn` | Jump 5 results / scroll detail page |
| `Enter` | Open detail pane |
| `r` | Load README or exploit file |
| `c` | Clone GitHub repo to `/tmp` |
| `b` / `ESC` | Back to list |
| `q` | Quit |

---

## Exploit Type Filters

Filter both SearchSploit and GitHub results to a specific vulnerability class. Flags are mutually exclusive.

| Flag | Type |
|---|---|
| `--rce` | Remote Code Execution |
| `--lpe` | Local Privilege Escalation |
| `--sqli` | SQL Injection |
| `--lfi` | Local File Inclusion / Path Traversal |
| `--ssrf` | Server-Side Request Forgery |
| `--auth` | Authentication Bypass |
| `--dos` | Denial of Service / Buffer Overflow |
| `--xxe` | XXE Injection |

---

## Relevance Scoring

Results from both sources are merged and ranked by a relevance score (shown in brackets on each card). Signals used:

| Signal | Weight |
|---|---|
| Service name match in title | 25 pts |
| Version match (exact or fuzzy) | 20 pts |
| Exploit type keyword hits | 15 pts |
| Recency (age of repo / EDB submission) | 15 pts |
| Popularity (stars / EDB-ID recency) | 10 pts |
| PoC/exploit signal in repo name | 10 pts |
| SearchSploit source bonus (curated) | 5 pts |

---

## Caching

Search results are cached to `~/.cache/pwndex/` keyed by search parameters. Default TTL is 24 hours.

```bash
# Force fresh search
pwndex vesta --no-cache

# Custom TTL
pwndex vesta --ttl 48

# Clear all cached results
pwndex --cache-clear
```

---

## Other Flags

```
-f, --fuzzy             Fuzzy title matching in searchsploit
--no-searchsploit       Skip searchsploit
--no-github             Skip GitHub search
--no-tui                Print results to stdout (for scripting)
--web                   Also run ddgr/googler web search
--open                  Open top results in browser
--urls-only             Print manual search URLs and exit
--no-cache              Bypass cache
--cache-clear           Delete all cached results
--ttl HOURS             Cache TTL in hours (default: 24)
```

---

## How It Works

1. Searches run in parallel — GitHub API and `searchsploit --json` fire simultaneously
2. Results are merged and scored against the query (service name, version, type keywords, recency, popularity)
3. The TUI renders cards with title, metadata, description, and URL visible without opening a detail view
4. Pressing `r` fetches the GitHub README or local SearchSploit file and renders it as formatted markdown via `rich`
5. Pressing `c` runs `git clone --depth 1` into `/tmp/` and marks the entry with `✓`

---

## Notes

- SearchSploit requires the `exploitdb` package (standard on Kali). On other distros, install manually from https://github.com/offensive-security/exploitdb
- GitHub results require internet access. `--no-github` works fully offline if SearchSploit is installed
- The `--no-tui` flag makes the output scriptable: `pwndex apache 2.4.49 --no-tui --no-github`
- Markdown rendering degrades gracefully — if `python3-rich` is missing, detail view shows plain text
