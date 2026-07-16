# recon

oscp/sec200 recon automation — nmap + searchsploit scanning, a live Flask
dashboard, per-host Obsidian notes, credential tracking, and a final report
generator.

## Requirements

``` bash
sudo apt install python3-nmap nmap
pip install flask --break-system-packages
```

`searchsploit` (from exploitdb) is optional but recommended — exploit
lookups are skipped if it's not found.

## Usage

### Option 1 — CLI scan (headless, scriptable)

``` bash
sudo python3 recon_scan.py <project_name> <target_file> [-t threads] [-p ports] [--no-udp]
```

- `<target_file>` — one IP/hostname per line, `#` comments allowed
- `-t/--threads` — parallel scan threads (default: 5)
- `-p/--ports` — nmap port args (default: `--top-ports 10000`)
- `--no-udp` — skip the UDP phase (UDP scanning needs elevated privileges)

Re-running with the same `<project_name>` merges new results in rather than
overwriting — safe to add hosts incrementally.

### Option 2 — Live dashboard (recommended)

``` bash
sudo python3 recon_server.py <project_dir> --host 192.168.xxx.xxx --port 5000
```

Navigate to `<host>:<port>`, paste targets into the Scan Hosts box, and hit
Start Scan. Hosts populate the dashboard as each one finishes — no need to
run `recon_scan.py` separately first, though you still can (e.g. for
scripted runs against the same project).

Root/sudo is needed for both by default — nmap's SYN/UDP scans require
raw sockets. **Don't want to run the whole thing as root?** See
[Running without sudo](#running-without-sudo) below — one-time setup, then
neither entry point needs sudo again.

## Per-host page features

Each host gets a page at `scans/html/<safe>.html` (linked from the
dashboard and the static `index.html` snapshot):

- **Scan results** — open ports, service versions, NSE script output
- **Searchsploit hits** — matched exploits with classification badges
- **Credentials** — add/track creds per host (username, password or hash,
  service, status, notes) directly on the page. Persisted to the project
  manifest, survives rescans. Each credential has a **Spray** button that
  fires it against every known host in the project via the same
  `/api/spray/<host>/<cred_id>` job the Credentials page uses — status
  auto-updates (`valid`/`valid-admin`) based on what comes back, but full
  results (which host, which protocol) stay on the Credentials page; the
  host page just shows a toast when it's done, so you're not stuck reading
  a results table you didn't ask to see. Requires `recon_server.py`
  running — read-only/unavailable on a static snapshot.
- **Feroxbuster** — only shown when a web service was actually detected.
  Deliberately minimal — this is for quick recon, not a full scan-config
  UI: pick protocol and port from what was already found (both
  pre-selected to the first detected endpoint), hit Start Scan. The
  target is always this host — no IP field, since there's no reason to
  ever scan a different one from here. Live progress and a collapsible
  results table appear inline as hits come in; results persist to the
  manifest and survive rescans, same as credentials. An **Advanced**
  toggle reveals wordlist/extensions/thread-count overrides plus two
  checkboxes, both on by default: disable feroxbuster's own
  wildcard/soft-404 auto-filter (it can silently drop real hits) and only
  surface 2xx/3xx/401 results (a raw wordlist scan is mostly 404s, and
  403 is often just a blanket WAF/deny rule rather than a real signal —
  the full untouched output is always saved to
  `scans/ferox/<safe>.jsonl` regardless of this filter, so nothing is
  ever lost, only curated for the dashboard). Always runs with
  `-k`/`--insecure` (skips TLS cert validation) since lab hosts almost
  always run self-signed certs — feroxbuster otherwise refuses to
  connect at all on https targets. Requires `feroxbuster` on
  the machine running `recon_server.py`.
- **Download Obsidian Note** — grabs the hand-editable `.md` note for that
  host straight from the page.
- **Delete Host** — removes the host and all associated data (scan
  results, notes, credentials, feroxbuster results) from the project.
  Confirms before deleting since it also removes anything you've
  hand-written in the note.

## Notes

For each scanned host, `notes/<host>.md` is generated as a starting point
for an Obsidian note — auto-filled with scan data (ports, services,
searchsploit hits) plus a structured template for the parts you fill in by
hand as you work the box: attack vectors, foothold, privilege escalation,
loot, and flags, with a Timeline table for logging exact timestamps.

**Notes are never overwritten by a rescan** — once `notes/<host>.md`
exists, `recon_scan.py` leaves it alone on subsequent scans of the same
host, so your hand-written progress is safe.

Credentials are tracked separately in the live dashboard (see above) as the
current-state source of truth, so status/notes edits can't drift out of
sync with the note. Each time a credential is added, though, it's also
logged into the note under `## Credential Log` — a timestamped,
append-only history (newest entry first) so you can see when and how each
cred was found without leaving the note. Editing or deleting a credential
later only updates the dashboard/manifest, not this log — it's a record
of history, not a live mirror.

Each note also has a `## Network Access` section — fill this in if the
host required pivoting/tunneling to reach it (pivot tool, which host it
went through, the tunnel command(s)). Left as `Direct` by default. This
feeds the Pivoting subsection of the generated Word report automatically.

## A note on "admin" status from credential spraying

nxc marks a hit `(Pwn3d!)` when it actually attempts (and succeeds at)
code execution — this is generally reliable for **domain** accounts. For
**local** (non-domain, non-RID-500) accounts, Windows' UAC remote token
filtering (`LocalAccountTokenFilterPolicy`) strips admin rights from the
token used over the network by default, even when the account genuinely
is in the local Administrators group — a well-documented source of
Pwn3d false positives that nxc itself can't fully account for.

This tool tags every admin hit with whether it came from a `--local-auth`
check, and reflects that in the status: a **local-account-only** Pwn3d
hit gets `valid-admin-uncertain` (shown as `ADMIN?` with an orange
badge), while a **domain-account** Pwn3d hit gets the normal
`valid-admin` (red badge, and what actually triggers the dashboard's
"PWNED" indicator). If a credential has both, the confident domain hit
wins. Treat `admin?`/`valid-admin-uncertain` as "worth trying to verify
manually" rather than "confirmed" — e.g. actually attempt command
execution (`nxc smb <target> -u user -p pass -x whoami`) before relying
on it.

## Running without sudo

nmap's SYN/UDP scans need `CAP_NET_RAW`/`CAP_NET_ADMIN` for raw sockets —
normally that means running the whole tool as root. `setup_caps.sh`
grants those capabilities directly to the nmap binary instead, so nmap
can do it unprivileged and neither `recon_scan.py` nor `recon_server.py`
need sudo at all:

```bash
sudo ./setup_caps.sh    # one-time — setting file capabilities needs root
python3 recon_server.py <project_dir>   # no sudo needed from here on
```

Only nmap needs this — `nxc`, `feroxbuster`, `bloodhound-python`, and
`proxychains` are all regular userspace network clients that never
needed elevated privileges in the first place. Both entry points detect
automatically whether nmap already has the capability set (or you're
already root) and only fall back to wrapping calls in `sudo` if neither
is true — so this is fully optional; running with plain `sudo` like
before still works exactly as it always did.

One thing worth knowing: reinstalling or upgrading nmap (`apt upgrade
nmap`) replaces the binary, which resets the capability — just re-run
`setup_caps.sh` after any nmap upgrade.

## Pivoting / proxy support

Every scan checks the kernel routing table per-target before deciding how
to reach it — no manual toggle needed:

- **Route-based tunnels** (ligolo-ng, sshuttle) — once you've added a
  route for the pivot subnet (`ip route add 10.5.5.0/24 dev ligolo`), the
  target has a specific route and gets scanned completely normally.
- **SOCKS-based tunnels** (SSH `-D` dynamic forwarding, chisel) — these
  don't add a kernel route, so a target with *no* specific route (only
  the generic default route matches it) gets automatically wrapped in
  `proxychains` instead.

Every nmap invocation also runs with `-Pn` regardless of which path it
takes — ping-based host discovery doesn't work over a SOCKS proxy (no
raw ICMP), so this keeps direct and proxied scans working the same way
without needing separate logic for each. Proxied scans are also forced
to `-sT` (TCP connect) instead of the default SYN scan — `proxychains`
can only intercept userspace `connect()` calls, and a raw-socket SYN
scan bypasses that entirely, so it would otherwise just silently return
nothing. UDP scanning is skipped for proxied targets for the same
reason — there's no way to tunnel it through `proxychains`.

Set the SOCKS port with `--proxy-port` (default `9050`) on either
entry point:
```bash
python3 recon_scan.py <project> <targets> --proxy-port 1080
python3 recon_server.py <project_dir> --proxy-port 1080
```
Requires `proxychains` on the machine running the scan — a startup
warning fires if it's missing, though it only actually matters for
targets that need the proxy fallback.

## Lab restarts (subnet octet changes)

PEN-200 lab restarts often reassign the third octet of every host's IP
(e.g. `192.168.50.x` becomes `192.168.150.x`), which would otherwise
orphan all your existing scan data, notes, and credentials for that
project.

**From the dashboard:** a collapsible "Lab Restarted? Remap IPs" panel
sits below the Scan Hosts card — enter the old/new octet, hit Preview to
see what would change, then Apply. No CLI needed.

**From the CLI**, `recon_remap.py` does the same thing:

``` bash
python3 recon_remap.py <project_dir> <old_octet> <new_octet> [--dry-run]

# example: lab restarted, subnet went from .50.x to .150.x
python3 recon_remap.py ~/relia-lab 50 150
```

Either way: renames every associated file (notes, html, nmap XML,
searchsploit output, per-host creds), rewrites literal IP references
inside note/html content, and regenerates the index and Obsidian summary
— hand-written notes, credentials, and Local/Proof flags all carry over
untouched, and nothing gets rescanned. Hosts that don't match
`<old_octet>` are left alone. A host matching `<old_octet>` whose target
IP would collide with an existing entry is skipped and reported rather
than silently overwritten.

- **BloodHound** — only shown when a host looks like a domain controller
  (LDAP detected: ports 389/636/3268/3269, or an `ldap`-named service).
  A credential dropdown is populated with anything confirmed to work over
  LDAP against this host — either a spray hit (protocol `ldap`) from
  anywhere in the project, or a credential manually marked `valid`/
  `valid-admin`/`valid-admin-uncertain` with `ldap` in its service field.
  **Start Scan stays disabled until at least one such credential exists.**
  Domain auto-fills from the host's note (`## System Information` →
  Domain / Workgroup); DC hostname is optional and auto-detected by
  `bloodhound-python` if left blank. Runs `bloodhound-python -c All --zip`
  under the hood; results persist as `scans/bloodhound/<safe>.zip` (survives
  rescans) with a quick object-count summary, and the zip downloads
  straight from the results panel — ready to drop into BloodHound's
  "Upload Data" dialog. Requires `bloodhound-python` on the machine
  running `recon_server.py`.

  **Optional auto-submit to BloodHound CE** — pass `--bh-host`,
  `--bh-key-id`, and `--bh-key` when starting the server and every
  completed collection is submitted for ingestion automatically, no
  manual upload needed:
  ```bash
  python3 recon_server.py <project_dir> --bh-host http://localhost:8080 --bh-key-id '<TOKEN_ID>' --bh-key '<TOKEN_KEY>'
  ```
  Get both from the BloodHound CE UI under **Administration → API
  Tokens → Create Token** — `--bh-key-id` is the public Token ID,
  `--bh-key` is the secret Token Key. All three flags are optional and
  independent of everything else; if any are missing, the server logs a
  warning at startup and the feature is silently disabled for that run —
  the zip still saves locally either way, so nothing is ever lost, you'd
  just upload it through the BloodHound CE UI yourself instead.
  Submission uses BloodHound CE's HMAC-signed request scheme (not a
  JWT), matching SpecterOps' own reference API client.

## Final report (Word doc, matches OffSec's official OSCP exam report template)

`recon_report_docx.py` generates a `.docx` matching the structure of
OffSec's official "OffSec Certified Professional Exam Report v2.0"
template:

```
1  OffSec Certified Professional Exam Report
   1.1 Introduction · 1.2 Objective · 1.3 Requirements
2  High-Level Summary · 2.1 Recommendations
3  Methodologies
   3.1 Information Gathering · 3.2 Service Enumeration · 3.3 Penetration
   3.4 Maintaining Access · 3.5 House Cleaning
4  Independent Challenges      (standalone, non-domain-joined hosts)
5  Active Directory Set        (domain-joined hosts)
```

Hosts are auto-sorted into section 4 vs 5 based on the **Domain /
Workgroup** field in each host's note (`## System Information`) —
anything other than blank/`WORKGROUP` is treated as domain-joined. Each
finding gets the same structure the official template uses: a
high-level Initial Access writeup (Vulnerability Explanation / Fix /
Severity / steps-to-reproduce), Service Enumeration, Credentials, a
detailed technical walkthrough, Privilege Escalation, and
Post-Exploitation. A real Word **Table of Contents field** is inserted
on the title page — right-click it in Word and choose "Update Field" to
populate it from the document's headings, same as the official template.

**What's auto-filled:** host list, port/service enumeration, credentials
(from the manifest — the live source of truth), the technical attack
narrative and flag hashes (from `## Attack Notes` / `## Flags` in each
note), and tunneling detail from `## Network Access`.

**What's deliberately left as a placeholder:** Vulnerability
Explanation/Fix/Severity, the steps-to-reproduce summary, and the
High-Level Summary/Recommendations narrative. Those are exactly the
analysis and understanding OSCP is grading — this tool won't fabricate
that content on your behalf, only give you the correct structure and
the factual details to write around. Screenshots are always a
placeholder too, obviously.

**From the dashboard:** a collapsible "📄 Generate Report" panel — fill in
Candidate/OSID/Email (all optional, left as bracketed placeholders if
blank), hit Download Report. Only Local/Proof-flagged hosts are included
by default; check "Include every host" to override.

**From the CLI:**
``` bash
python3 recon_report_docx.py <project_dir> [-o OUTPUT.docx] [--all] \
    --candidate "Jane Doe" --osid "OS-12345" --email "jane@example.com"
```

Requires `python-docx`: `pip install python-docx --break-system-packages`.
If it's not installed, the dashboard button still shows but returns an
error explaining what to install — the rest of the app works fine without it.

## Final report (Markdown)

Once you've worked through some boxes, generate a single consolidated
report pulling from the manifest (host metadata, credentials) and your
notes (attack narrative, flags):

``` bash
python3 recon_report.py <project_dir>                 # Local/Proof-flagged hosts only, curated sections
python3 recon_report.py <project_dir> --all            # every scanned host, regardless of flags
python3 recon_report.py <project_dir> --full           # every note section, not just the curated set
python3 recon_report.py <project_dir> -o report.md      # custom output path
```

Default output: `<project_dir>/FINAL_REPORT.md`. Credentials in the report
are always pulled fresh from the manifest, so the report can't go stale
even if a note's own credentials section wasn't kept up to date.

## Project layout

```
<project_dir>/
├── index.html               # static snapshot of all hosts
├── FINAL_REPORT.md           # generated by recon_report.py
├── FINAL_REPORT.docx         # generated by recon_report_docx.py
├── targets.txt                # every scanned host, one per line — for other manual tools
├── users.txt                   # every credential username, deduped
├── passwords.txt                # every credential secret (password or hash), deduped
├── creds.txt                     # every credential as user:secret, deduped
├── work/                          # your scratch space — nothing here is ever touched by this tool
├── scans/
│   ├── .manifest.json        # source of truth: scan data, flags, credentials
│   ├── nmap/                  # raw nmap XML per host (tcp + udp)
│   ├── searchsploit/           # raw searchsploit output per host
│   ├── html/                    # per-host report pages
│   ├── creds/                    # per-host user:secret files
│   ├── ferox/                     # per-host feroxbuster JSON-lines output
│   └── bloodhound/                 # per-host BloodHound collection zips
└── notes/
    ├── _scan_summary.md        # links to every host note
    └── <host>.md                 # per-host Obsidian note (hand-edited)
```

`targets.txt`/`users.txt`/`passwords.txt`/`creds.txt` stay in sync
automatically — refreshed after every scan, credential add/edit/delete,
host delete, IP remap, and at server startup (so an existing project
gets backfilled the first time you start the dashboard on it). All four
are removed automatically if the project ever has nothing to put in
them, rather than being left behind stale/empty.
