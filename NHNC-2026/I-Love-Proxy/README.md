# NHNC CTF — I Love Proxy

**Category:** Web / Reversing  
**Difficulty:** Hard  
**Solved on:** 2026-07-04  
**Flag:** `NHNC{I_L0ve_Pr0xy_Pr0xy_pr0xy_It_is_s0_wounderful_de9e1bc43d4e45f1afc375297558058c}`

## Summary

I Love Proxy is a multi-container challenge built around a stripped, custom HTTP proxy (`edge-httpd`) that routes requests to backend services. The flag is at `/flag.txt` inside the `courier` container, readable only by root.

The solve is a three-layer chain:

1. **UDP route injection** — edge-httpd starts with an empty route table. Register a route via its UDP control protocol to reach the courier backend.
2. **cgid packer gate bypass** — the courier container runs `cgid`, an anti-debug packer that gates access behind a hidden header/body signature. Satisfy it to set the `CGI_STACK_STAGE` environment variable.
3. **Courier lease forgery** — the inner `courier.cgi` binary verifies a "signed lease" using custom hashes over headers and body fields. Forge the struct so it calls `run_filter("cat /flag.txt")` and returns the flag.

The entire chain is deterministic — no per-instance randomness, no brute force. The same payload works on local and remote unchanged.

## Architecture

```
                    TCP :8080           TCP :7000
  ┌──────────┐    ┌────────────┐     ┌─────────────┐
  │  Client   │───│  edge-httpd │────│   courier    │
  └──────────┘    │  (proxy)   │     │  cgid →      │
       │          └────────────┘     │  courier.cgi  │
       │          UDP :5555          │  /flag.txt    │
       └──────────────┘              └─────────────┘
                                     ┌─────────────┐
                                     │ vault       │ (decoy)
                                     │ ledger      │ (decoy)
                                     │ render-cache│ (decoy)
                                     └─────────────┘
```

`edge-httpd` is a no-PIE, stripped x86_64 binary that:
- Listens on TCP for HTTP requests and UDP for route control
- Maintains a route table (up to 48 entries) mapping path prefixes to `host:port` upstreams
- Starts with the route table **empty** — no upstream is reachable until registered

`cgid` is an anti-debug packer (checks TracerPid, LD_PRELOAD, GCONV_PATH) that decrypts and fexecve's an inner binary from a memfd. The inner sets CGI environment variables and execs `courier.cgi`.

`courier.cgi` is also packed. Its decrypted inner is non-PIE at 0x400000 and unstripped — a gift for static analysis once extracted.

## Vulnerability Chain

### Layer 1 — UDP Route Injection

The route table starts empty. The UDP handler at `fcn.004024b0` accepts two packet types to register routes:

**Packet 1 — Handshake (type `0x03/0x36`, exactly 14 bytes):**

```
[0:4]   Wire magic (0x89543217 — derived from XOR/ROL obfuscation)
[4]     0x03  (0x59 ^ 0x5a)
[5]     0x36  (0xad ^ 0x9b)
[6:10]  Seed value (big-endian u32, attacker-chosen)
[10:14] keyed_hash(pkt[4:10], 6, seed ^ 0xa7)
```

The server validates the hash, then computes a nonce from the seed using a derivation involving XOR, IMUL, and ROL/ROR operations, storing it at `DAT_00406180`.

**Packet 2 — Registration (type `0x03/0x71`, length = 20 + path_len + upstream_len):**

```
[0:4]   Wire magic
[4]     0x03
[5]     0x71  (0xb7 ^ 0xc6)
[6:7]   Flags (bit 2 must be clear to allow registration)
[8:10]  path_len    (big-endian u16)
[10:12] upstream_len (big-endian u16)
[12:16] Nonce echo  (must match DAT_00406180)
[16:]   XOR-encoded path + upstream + 4-byte keyed_hash
```

The XOR encoding is `data[i] ^ ((0x31 + i*0x0d) & 0xff) ^ (flags_b ^ 0xa7)`. Path must start with `/`, contain no `..` or `//` or `\`, and not match `/admin` if the admin-block flag is set.

Since we control the seed and know the nonce derivation, we can compute the nonce without any server interaction. The entire handshake is single-round, no response needed.

**What we register:** `/c` → `courier:7000`

The `keyed_hash` function at `0x401530` is a custom construction using the golden ratio constant `0x9e3779b9`, IMUL by `0x45d9f3b`, and position-dependent mixing (SHL/ROL/ROR/XOR branching on `(i ^ seed) & 3`). Full port in [`solve.py`](./solve.py).

### Layer 2 — cgid Packer Gate

The cgid inner binary (extracted via `/proc/1/exe` from a running container, then analyzed in Ghidra) contains a hidden gate that activates when the HTTP request meets specific criteria:

1. **Host header**: exactly 1368 `A` characters + 12 hex digits + `:` (total 1381 chars)
2. **Content-Length**: >= `0xf0` (240 bytes)
3. **Body markers**: `body[0x49] = 0x58`, `body[0x58] = 0x58`, `body[0xd0] = 0xf8`

When all three conditions are met, cgid sets the environment variable `CGI_STACK_STAGE` to a keyed hash derived from the request. This variable is what courier.cgi checks later — it serves as a proof that the request passed through cgid's gate correctly.

The 12 hex digits in the Host header encode `(Content-Length << 7) ^ uVar28 ^ 0x5353495f504f5354`, masked to 48 bits. Since `uVar28` depends on the header set, this value is fixed for our specific request.

The anti-debug checks (TracerPid, LD_PRELOAD, GCONV_PATH) only run at packer startup, not per-request, so they don't interfere with exploitation. To extract the inner binary for analysis:

```bash
# Inside the container:
gdb -p 1
# Break after fexecve (0x1c0d in packer), bypass TracerPid check (set rax=0 at 0x11e7)
# Then: cp /proc/self/exe /tmp/inner_cgid
```

### Layer 3 — Courier Lease Forgery

The decrypted courier.cgi inner (`courier_inner`, non-PIE at 0x400000, unstripped) is the crown jewel. It uses **suffix-based routing**: FNV-1a-32 over the last N characters of `PATH_INFO` determines which handler runs.

**Finding the lease endpoint:**

The lease handler activates when `fnv1a_32(last_10_chars) == 0x26045b27`. Brute-forcing the suffix gives us `plkkaaaagi`:

```python
fnv1a_32(b"plkkaaaagi") == 0x26045b27  # ✓
```

So our full path is `/c/plkkaaaagi` (through the route we injected).

**Lease verification (main at 0x4023f5):**

The lease endpoint performs extensive verification:

1. **analyze_headers** — counts headers whose `djb2(name) & 0x1f == 0x11` (need >= 29), checks for a specific header with `djb2(name) == 0xa2e31e1b` and `fnv1a(value) == 0x5c547beb`, and rejects if any header has `djb2(name) == 0x89424ae8`.

2. **host_body_chain_ok** — validates the giant Host header format, the 12-hex derivation, body struct fields at specific offsets, and the `CGI_STACK_STAGE` environment variable against `mix64(...)`.

3. **tape_stream** — decodes a command string from `body[0x100:]` using byte-pair encoding `(index, char)`, terminated by `0xff`.

4. **Function dispatch** — a struct field at `body[0x148]` must decode to `0x4022ac`, the address of `run_filter`.

**run_filter at 0x4022ac:**

```c
run_filter(char *cmd) {
    FILE *f = popen(cmd, "r");
    // reads and returns output
}
```

This uses `popen`, not `open` — so the argument is a shell command, not a file path. Our command is `cat /flag.txt`.

**Body layout (512 bytes):**

| Offset | Value | Purpose |
|--------|-------|---------|
| 0x49 | 0x58 | cgid gate marker |
| 0x58 | 0x58 | cgid gate marker |
| 0x80 | jmp ^ 0x9c8e949aa062989e | body chain verification |
| 0x88 | jmp ^ 0x1a00000 | body chain verification |
| 0x90 | rotation value | body chain verification |
| 0xd0 | 0xf8 | cgid + courier marker |
| 0xd8 | 0x5245545f414c4947 | "RET_ALIG" alignment tag |
| 0xe0 | 0x53595354454d5f31 | "SYSTEM_1" system tag |
| 0x100+ | tape_stream data | encodes "cat /flag.txt" |
| 0x148 | 0x4022ac (LE) | run_filter function pointer |

The `jmp` and rotation values are derived from a tag of the request head — since our request is fixed, these are constants extracted via GDB.

## Exploit

**Files:**
- [`solve.py`](./solve.py) — full exploit chain (UDP inject + HTTP forged lease)

**Run:**

```bash
# Local (docker-compose up)
python3 solve.py 127.0.0.1 8080 8080 courier:7000

# Remote
python3 solve.py <remote-host> <remote-port> <remote-port> courier:7000
```

**Expected output:**

```
================================================================
  I Love Proxy — Full Exploit Chain
  3 layers: UDP inject → cgid gate → courier lease forgery
================================================================

────────────────────────────────────────────────────────────────
[LAYER 1] UDP route injection: /c → courier:7000
────────────────────────────────────────────────────────────────
[*] Handshake packet (14B): 895432170336414243440557adf7
[*] Computed nonce: 0x........
[*] Register packet (30B): /c -> courier:7000
[+] Route injected: /c -> courier:7000

────────────────────────────────────────────────────────────────
[LAYER 2+3] Forged lease: cgid gate + courier signed lease
────────────────────────────────────────────────────────────────
[*] Total payload: .... bytes
[*] Path: /c/plkkaaaagi
[*] Command: cat /flag.txt

================================================================
  FLAG: NHNC{I_L0ve_Pr0xy_Pr0xy_pr0xy_It_is_s0_wounderful_de9e1bc43d4e45f1afc375297558058c}
================================================================
```

## Reverse Engineering Notes

### Extracting the inner binaries

Both `cgid` and `courier.cgi` are anti-debug packers. The inner binaries live in memfds created at runtime:

```bash
# For cgid inner:
docker exec -it <container> bash
# Attach GDB to PID 1, bypass TracerPid check, break at fexecve
# Read /proc/<child-pid>/exe after fexecve

# For courier.cgi inner:
# Same approach — break at fexecve in courier.cgi's unpacker
# The inner is non-PIE @ 0x400000, unstripped — much easier to analyze
```

The courier inner being non-PIE and unstripped means `run_filter` is at a fixed address (`0x4022ac`) with symbol information. This eliminates the need for any info leak.

### Key hash functions

| Function | Location | Purpose |
|----------|----------|---------|
| `keyed_hash` | edge-httpd @ 0x401530 | UDP authentication |
| FNV-1a-32 | courier inner | Suffix routing, header value matching |
| djb2 | courier inner | Header name bucketing |
| `mix64` | courier inner | CGI_STACK_STAGE verification |
| `tag32` | courier inner | Request head fingerprinting |

All are deterministic, position-dependent hash functions with no secret keys or randomness.

### Decoy services

The docker-compose includes three decoy upstreams:
- `vault` — "vault sealed: no material on this node"
- `ledger` — "ledger replay window closed"
- `render-cache` — "cache shard online, exports disabled"

All are simple busybox httpd instances serving static text. They exist to distract — the only target is `courier:7000`.

## Root Cause

The core vulnerability is that edge-httpd exposes an unauthenticated (but obfuscated) UDP control protocol that allows arbitrary route registration. Once you can route traffic to the courier backend, the remaining barriers are verification puzzles: cgid's hidden gate and courier's lease struct are complex but fully deterministic forgeries.

The anti-debug protections in cgid and courier.cgi are effective against casual analysis but fall to GDB with targeted breakpoints. The courier inner being non-PIE and unstripped undermines the packer's purpose entirely.

## Timeline

- **Hour 0–3**: Reverse-engineered edge-httpd (r2 + Ghidra). Identified the UDP route protocol, ported `keyed_hash`, achieved route injection.
- **Hour 3–5**: Extracted cgid inner via GDB. Found the hidden gate conditions.
- **Hour 5–10**: Extracted courier inner. Mapped the lease verification chain (analyze_headers, host_body_chain_ok, tape_stream). Brute-forced the suffix path and header names.
- **Hour 10–12**: Built the forged body struct with GDB-extracted constants. First local flag.
- **Hour 12**: Ran against remote — one-shot success, same payload.

## Closing Note

This challenge is three layers of obfuscated gatekeeping around a single `popen` call. The proxy starts with no routes. The packer checks for debuggers. The CGI binary verifies a 20-field struct. But underneath it all, the flag is just `cat /flag.txt` away — you just need to convince four binaries that you belong there.
