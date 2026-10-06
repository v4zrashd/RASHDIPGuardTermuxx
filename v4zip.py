#!/usr/bin/env python3
"""
V4Z IP Guard - RASHDIPGuardTermuxx
Termux IP checker + Tor compare + privacy score + local proxy tester.

Author: V4Z RASHD
Channel: https://t.me/rashdteem

Original tool. Python standard library only (no pip installs).

What it really does (honest version):
  - Shows your current public IP with geo/ISP info.
  - If Tor is running, compares your direct IP against the Tor exit IP.
  - Gives a small privacy score from observable signals.
  - Keeps a local history of IP changes.
  - Tests proxies from a LOCAL proxies.txt file you provide
    (never uploaded, never sent anywhere except the proxy itself).

It does NOT magically rewrite your carrier IP. On a non-rooted phone the
real "switch" is Tor or a proxy. Everything below just shows proof.
"""

import argparse
import base64
import concurrent.futures
import json
import os
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

VERSION = "1.0"
APP_NAME = "V4Z IP Guard"
CHANNEL = "https://t.me/rashdteem"
DATA_DIR = os.path.join(os.path.expanduser("~"), ".v4zip")
LOG_FILE = os.path.join(DATA_DIR, "history.jsonl")
TOR_PID_FILE = os.path.join(DATA_DIR, "tor.pid")
TOR_SOCKS_HOST = "127.0.0.1"
TOR_SOCKS_PORT = 9050
PROXY_FILE_NAMES = ("proxies.txt", os.path.join(DATA_DIR, "proxies.txt"))

GREEN = "\033[92m"
CYAN = "\033[96m"
YELLOW = "\033[93m"
RED = "\033[91m"
DIM = "\033[2m"
BOLD = "\033[1m"
RESET = "\033[0m"


def c(text, color):
    return f"{color}{text}{RESET}"


def banner():
    print(c("=" * 56, GREEN))
    print(c(f"  {APP_NAME}  v{VERSION}  -  RASHDIPGuardTermuxx", GREEN + BOLD))
    print(c(f"  by V4Z RASHD  |  {CHANNEL}", DIM))
    print(c("=" * 56, GREEN))


# --------------------------------------------------------------------------
# Basic HTTP helpers (direct)
# --------------------------------------------------------------------------

def fetch_json(url, timeout=10):
    req = urllib.request.Request(url, headers={"User-Agent": f"v4zip/{VERSION}"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8", "replace"))


def get_direct_ip_info():
    """Public IP info for the current direct connection."""
    url = ("http://ip-api.com/json/?fields=status,message,query,country,"
           "countryCode,regionName,city,isp,org,as,timezone,proxy,hosting")
    data = fetch_json(url, timeout=12)
    if data.get("status") != "success":
        raise RuntimeError(data.get("message", "ip lookup failed"))
    return normalize_info(data, source="direct")


def get_geo_for_ip(ip):
    """Geo info for an arbitrary IP (used for Tor exit / proxy exit IPs)."""
    if not ip:
        return None
    url = (f"http://ip-api.com/json/{urllib.parse.quote(ip)}"
           "?fields=status,message,query,country,countryCode,regionName,"
           "city,isp,org,as,timezone,proxy,hosting")
    data = fetch_json(url, timeout=12)
    if data.get("status") != "success":
        return {"ip": ip}
    return normalize_info(data, source="lookup")


def normalize_info(data, source):
    return {
        "ip": data.get("query"),
        "country": data.get("country"),
        "country_code": data.get("countryCode"),
        "region": data.get("regionName"),
        "city": data.get("city"),
        "isp": data.get("isp"),
        "org": data.get("org"),
        "asn": data.get("as"),
        "timezone": data.get("timezone"),
        "is_proxy": bool(data.get("proxy")),
        "is_hosting": bool(data.get("hosting")),
        "source": source,
        "checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }


def print_info(info, title):
    print(c(f"\n[{title}]", CYAN + BOLD))
    if not info:
        print(c("  no data", RED))
        return
    rows = [
        ("IP", info.get("ip")),
        ("Country", f"{info.get('country')} ({info.get('country_code')})"),
        ("Region", info.get("region")),
        ("City", info.get("city")),
        ("ISP", info.get("isp")),
        ("Org", info.get("org")),
        ("ASN", info.get("asn")),
        ("Timezone", info.get("timezone")),
        ("Proxy/VPN flag", info.get("is_proxy")),
        ("Hosting flag", info.get("is_hosting")),
    ]
    for key, val in rows:
        if val is not None and val != "None (None)":
            print(f"  {key:<16} {val}")


# --------------------------------------------------------------------------
# History log
# --------------------------------------------------------------------------

def ensure_data_dir():
    os.makedirs(DATA_DIR, exist_ok=True)


def log_ip(info, note=""):
    if not info or not info.get("ip"):
        return
    ensure_data_dir()
    entry = dict(info)
    entry["note"] = note
    entry["logged_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except OSError:
        pass


def read_log(limit=10):
    if not os.path.exists(LOG_FILE):
        return []
    entries = []
    try:
        with open(LOG_FILE, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    try:
                        entries.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
    except OSError:
        return []
    return entries[-limit:]


def cmd_log(limit=10):
    entries = read_log(limit)
    if not entries:
        print(c("No history yet. Run `v4zip check` first.", YELLOW))
        return
    print(c(f"\nLast {len(entries)} IP record(s):", CYAN + BOLD))
    for e in entries:
        when = e.get("logged_at", "?")
        print(f"  {when}  {e.get('ip')}  {e.get('country')}/{e.get('city')}  "
              f"[{e.get('source')}] {e.get('note', '')}")


# --------------------------------------------------------------------------
# Tor support (minimal SOCKS5 client, stdlib only)
# --------------------------------------------------------------------------

def _recvn(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("socket closed early")
        data += chunk
    return data


def socks5_get(host, path="/", use_tls=True, socks_host=TOR_SOCKS_HOST,
               socks_port=TOR_SOCKS_PORT, username=None, password=None,
               timeout=15):
    """Minimal SOCKS5 client: GET https://host/path through the SOCKS proxy."""
    raw = socket.create_connection((socks_host, socks_port), timeout=timeout)
    try:
        methods = [0]  # no-auth
        if username is not None:
            methods.append(2)  # username/password
        raw.sendall(bytes([5, len(methods)] + methods))
        ver, method = _recvn(raw, 2)
        if ver != 5 or method == 0xFF:
            raise ConnectionError("SOCKS5: no acceptable auth method")
        if method == 2:
            u = (username or "").encode()
            p = (password or "").encode()
            raw.sendall(b"\x01" + bytes([len(u)]) + u + bytes([len(p)]) + p)
            aver, status = _recvn(raw, 2)
            if status != 0:
                raise ConnectionError("SOCKS5: auth failed")
        host_b = host.encode("idna")
        req = b"\x05\x01\x00\x03" + bytes([len(host_b)]) + host_b
        req += (443 if use_tls else 80).to_bytes(2, "big")
        raw.sendall(req)
        rver, rep, _rsv, atyp = _recvn(raw, 4)
        if rep != 0:
            raise ConnectionError(f"SOCKS5: connect failed (code {rep})")
        if atyp == 1:
            _recvn(raw, 4)
        elif atyp == 3:
            ln = _recvn(raw, 1)[0]
            _recvn(raw, ln)
        elif atyp == 4:
            _recvn(raw, 16)
        _recvn(raw, 2)  # bound port

        conn = raw
        if use_tls:
            ctx = ssl.create_default_context()
            conn = ctx.wrap_socket(raw, server_hostname=host)
        http_req = (
            f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
            f"User-Agent: v4zip/{VERSION}\r\nConnection: close\r\n\r\n"
        )
        conn.sendall(http_req.encode())
        chunks = []
        while True:
            chunk = conn.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)
        raw_bytes = b"".join(chunks)
        head, _, body = raw_bytes.partition(b"\r\n\r\n")
        status_line = head.split(b"\r\n", 1)[0].decode("utf-8", "replace")
        parts = status_line.split(" ", 2)
        status_code = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
        # Handle chunked transfer-encoding simply
        if b"transfer-encoding: chunked" in head.lower():
            body = _decode_chunked(body)
        return status_code, body.decode("utf-8", "replace")
    finally:
        try:
            raw.close()
        except OSError:
            pass


def _decode_chunked(data):
    out = b""
    buf = data
    while True:
        idx = buf.find(b"\r\n")
        if idx < 0:
            break
        size_line = buf[:idx].split(b";", 1)[0].strip()
        try:
            size = int(size_line, 16)
        except ValueError:
            break
        if size == 0:
            break
        start = idx + 2
        out += buf[start:start + size]
        buf = buf[start + size + 2:]
    return out


def tor_running():
    try:
        with socket.create_connection((TOR_SOCKS_HOST, TOR_SOCKS_PORT), timeout=2):
            return True
    except OSError:
        return False


def get_tor_check():
    """Ask Tor Project's check API through the local Tor SOCKS port."""
    status, body = socks5_get("check.torproject.org", "/api/ip", use_tls=True)
    if status != 200:
        raise RuntimeError(f"tor check HTTP {status}")
    data = json.loads(body)
    return {"ip": data.get("IP"), "is_tor": bool(data.get("IsTor"))}


def get_tor_ip_info():
    chk = get_tor_check()
    ip = chk.get("ip")
    geo = get_geo_for_ip(ip) if ip else None
    if geo is None:
        geo = {"ip": ip}
    geo["source"] = "tor"
    geo["is_tor"] = chk.get("is_tor", False)
    return geo


def tor_start():
    if tor_running():
        print(c("Tor is already running on 127.0.0.1:9050.", GREEN))
        return True
    if not _which("tor"):
        print(c("Tor is not installed.", RED))
        print("Install it in Termux with:  pkg install tor")
        return False
    ensure_data_dir()
    try:
        proc = subprocess.Popen(
            ["tor"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        with open(TOR_PID_FILE, "w", encoding="utf-8") as fh:
            fh.write(str(proc.pid))
    except OSError as exc:
        print(c(f"Could not start tor: {exc}", RED))
        return False
    for _ in range(30):
        if tor_running():
            print(c("Tor started (127.0.0.1:9050).", GREEN))
            return True
        time.sleep(1)
    print(c("Tor did not come up in 30s. Try running `tor` manually to see errors.", RED))
    return False


def tor_stop():
    pid = None
    if os.path.exists(TOR_PID_FILE):
        try:
            with open(TOR_PID_FILE, encoding="utf-8") as fh:
                pid = int(fh.read().strip())
        except (OSError, ValueError):
            pid = None
    if pid:
        try:
            os.kill(pid, 15)
            print(c(f"Tor (pid {pid}) stopped.", GREEN))
        except OSError:
            print(c("Tor pid file existed but the process is gone.", YELLOW))
        try:
            os.remove(TOR_PID_FILE)
        except OSError:
            pass
    elif tor_running():
        print(c("Tor is running but was not started by v4zip; "
                "stop it where you started it.", YELLOW))
    else:
        print(c("Tor is not running.", DIM))


def _which(name):
    for path in os.environ.get("PATH", "").split(":"):
        cand = os.path.join(path, name)
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return None


# --------------------------------------------------------------------------
# Commands: check / compare / score
# --------------------------------------------------------------------------

def cmd_check(args):
    banner()
    try:
        info = get_direct_ip_info()
    except Exception as exc:  # noqa: BLE001 - show the user what went wrong
        print(c(f"IP lookup failed: {exc}", RED))
        print("Check your internet connection and try again.")
        return 1
    print_info(info, "Your current public IP (direct)")
    log_ip(info, note="check")
    print(c("\nSaved to history. See `v4zip log`.", DIM))
    return 0


def cmd_compare(args):
    banner()
    direct = None
    try:
        direct = get_direct_ip_info()
        print_info(direct, "Direct IP")
        log_ip(direct, note="compare-direct")
    except Exception as exc:  # noqa: BLE001
        print(c(f"Direct lookup failed: {exc}", RED))

    if tor_running():
        try:
            tor_info = get_tor_ip_info()
            print_info(tor_info, "Tor exit IP")
            log_ip(tor_info, note="compare-tor")
            if direct and tor_info.get("ip"):
                if tor_info["ip"] != direct.get("ip"):
                    print(c("\nTor exit IP is DIFFERENT from your direct IP. "
                            "The switch is real.", GREEN + BOLD))
                else:
                    print(c("\nTor exit IP equals your direct IP (unusual). "
                            "Wait for a new circuit and retry.", YELLOW))
        except Exception as exc:  # noqa: BLE001
            print(c(f"Tor lookup failed: {exc}", RED))
    else:
        print(c("\nTor is not running, so no Tor IP to compare.", YELLOW))
        print("Start it with:  v4zip tor start   (or run tor in another session)")
    return 0


def _device_timezone():
    try:
        return time.tzname[0]
    except Exception:  # noqa: BLE001
        return None


def compute_score(direct, tor_info):
    """Small transparent heuristic. Returns (score, notes)."""
    score = 0
    notes = []
    if direct:
        score += 2
        notes.append("+2 direct IP info fetched")
    if tor_info and tor_info.get("is_tor"):
        score += 2
        notes.append("+2 traffic confirmed as Tor exit (IsTor=true)")
    if direct and tor_info and tor_info.get("ip") and tor_info["ip"] != direct.get("ip"):
        score += 3
        notes.append("+3 Tor exit IP differs from direct IP")
    if direct and direct.get("timezone"):
        tz = _device_timezone()
        note_tz = str(direct["timezone"])
        # crude match: ip timezone string like Asia/Dhaka vs device offset name
        if tz and (tz.lower() in note_tz.lower()):
            score += 1
            notes.append("+1 device timezone roughly matches IP timezone")
        else:
            notes.append(" 0 device timezone not obviously matching IP timezone")
    if tor_info and tor_info.get("is_proxy"):
        score += 2
        notes.append("+2 exit IP flagged as proxy/anonymized by geo DB")
    if direct and direct.get("is_hosting"):
        score -= 1
        notes.append("-1 direct IP looks like hosting/datacenter")
    return max(0, min(10, score)), notes


def cmd_score(args):
    banner()
    direct = None
    tor_info = None
    try:
        direct = get_direct_ip_info()
        print_info(direct, "Direct IP")
        log_ip(direct, note="score-direct")
    except Exception as exc:  # noqa: BLE001
        print(c(f"Direct lookup failed: {exc}", RED))
    if tor_running():
        try:
            tor_info = get_tor_ip_info()
            print_info(tor_info, "Tor exit IP")
            log_ip(tor_info, note="score-tor")
        except Exception as exc:  # noqa: BLE001
            print(c(f"Tor lookup failed: {exc}", RED))
    else:
        print(c("\n(Tor not running - score excludes Tor checks.)", DIM))
    score, notes = compute_score(direct, tor_info)
    print(c(f"\nPrivacy score: {score}/10", CYAN + BOLD))
    for n in notes:
        print(f"  {n}")
    print(c("\nNote: this is a simple observable-signal score, not a full "
            "anonymity audit.", DIM))
    return 0


def cmd_report(args):
    entries = read_log(50)
    if not entries:
        print(c("No history yet. Run `v4zip check` or `v4zip compare` first.", YELLOW))
        return 1
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    path = os.path.abspath(f"v4zip-report-{stamp}.txt")
    lines = [f"{APP_NAME} v{VERSION} - session report",
             f"generated: {datetime.now(timezone.utc).isoformat(timespec='seconds')}",
             f"channel: {CHANNEL}", ""]
    last_direct = None
    for e in entries:
        lines.append(f"{e.get('logged_at')}  {e.get('ip')}  "
                     f"{e.get('country')}/{e.get('city')}  "
                     f"isp={e.get('isp')}  [{e.get('source')}] {e.get('note', '')}")
        if e.get("source") == "direct":
            last_direct = e
    if last_direct:
        sc, notes = compute_score(last_direct, None)
        lines += ["", f"latest direct-IP score (no Tor context): {sc}/10"] + notes
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
    except OSError as exc:
        print(c(f"Could not write report: {exc}", RED))
        return 1
    print(c(f"Report saved: {path}", GREEN))
    return 0


# --------------------------------------------------------------------------
# Proxy support (local file only - your pasted list stays on your phone)
# --------------------------------------------------------------------------

def find_proxy_file():
    for name in PROXY_FILE_NAMES:
        if os.path.exists(name):
            return name
    return None


def parse_proxy_line(line):
    """Accept: scheme://user:pass@host:port | host:port:user:pass | host:port
    Returns dict or None. Never print the password anywhere."""
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    scheme = "http"
    rest = line
    if "://" in line:
        scheme, rest = line.split("://", 1)
        scheme = scheme.lower()
    username = password = None
    hostport = rest
    if "@" in rest:
        cred, hostport = rest.rsplit("@", 1)
        if ":" in cred:
            username, password = cred.split(":", 1)
        else:
            username = cred
    parts = hostport.split(":")
    if len(parts) == 2:
        host, port = parts
    elif len(parts) >= 4 and username is None:
        # host:port:user:pass  (password itself may contain ':')
        host, port = parts[0], parts[1]
        username, password = parts[2], ":".join(parts[3:])
    else:
        return None
    try:
        port = int(port)
    except ValueError:
        return None
    if not host or not (0 < port < 65536):
        return None
    return {"scheme": scheme if scheme in ("http", "https", "socks5") else "http",
            "host": host, "port": port,
            "username": username, "password": password}


def load_proxies(path=None):
    path = path or find_proxy_file()
    if not path:
        return [], None
    proxies = []
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                parsed = parse_proxy_line(line)
                if parsed:
                    proxies.append(parsed)
    except OSError:
        return [], path
    return proxies, path


def mask_proxy(p):
    cred = f"{p['username']}:***@" if p.get("username") else ""
    return f"{p['scheme']}://{cred}{p['host']}:{p['port']}"


def http_get_via_proxy(proxy, url, timeout=12):
    """GET an http:// URL through an HTTP proxy. Returns (status, body)."""
    parsed = urllib.parse.urlparse(url)
    target_host = parsed.hostname
    target_port = parsed.port or 80
    _ = target_host, target_port  # target reached via absolute-form request
    sock = socket.create_connection((proxy["host"], proxy["port"]), timeout=timeout)
    try:
        path = urllib.parse.urlunparse(("", "", parsed.path or "/", "",
                                        parsed.query, ""))
        absolute = f"http://{parsed.hostname}{path}"
        headers = [f"GET {absolute} HTTP/1.1",
                   f"Host: {parsed.hostname}",
                   f"User-Agent: v4zip/{VERSION}",
                   "Connection: close"]
        if proxy.get("username"):
            raw = f"{proxy['username']}:{proxy.get('password') or ''}".encode()
            headers.append("Proxy-Authorization: Basic " +
                           base64.b64encode(raw).decode())
        sock.sendall(("\r\n".join(headers) + "\r\n\r\n").encode())
        chunks = []
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)
        raw_resp = b"".join(chunks)
        head, _, body = raw_resp.partition(b"\r\n\r\n")
        status_line = head.split(b"\r\n", 1)[0].decode("utf-8", "replace")
        parts = status_line.split(" ", 2)
        status = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
        if b"transfer-encoding: chunked" in head.lower():
            body = _decode_chunked(body)
        return status, body.decode("utf-8", "replace")
    finally:
        try:
            sock.close()
        except OSError:
            pass


def test_one_proxy(proxy, timeout=12):
    started = time.time()
    try:
        if proxy["scheme"] == "socks5":
            status, body = socks5_get(
                "ip-api.com", "/json/?fields=status,query,country,city,isp",
                use_tls=False, socks_host=proxy["host"], socks_port=proxy["port"],
                username=proxy.get("username"), password=proxy.get("password"),
                timeout=timeout)
        else:
            status, body = http_get_via_proxy(
                proxy, "http://ip-api.com/json/?fields=status,query,country,city,isp",
                timeout=timeout)
        ms = int((time.time() - started) * 1000)
        if status != 200:
            if status == 407:
                err = ("proxy alive but auth required (407) - your current IP "
                       "is not whitelisted, or user/pass is wrong/missing")
            else:
                err = f"HTTP {status}"
            return {**proxy, "ok": False, "error": err, "ms": ms}
        data = json.loads(body)
        if data.get("status") != "success":
            return {**proxy, "ok": False, "error": "bad response", "ms": ms}
        return {**proxy, "ok": True, "exit_ip": data.get("query"),
                "country": data.get("country"), "city": data.get("city"),
                "isp": data.get("isp"), "ms": ms}
    except Exception as exc:  # noqa: BLE001 - report per-proxy failure
        return {**proxy, "ok": False, "error": str(exc)[:80],
                "ms": int((time.time() - started) * 1000)}


def _proxy_preamble():
    proxies, path = load_proxies()
    if not proxies:
        print(c("No proxies found.", RED))
        print("Put your list (one per line) in ./proxies.txt or "
              "~/.v4zip/proxies.txt")
        print("Formats: host:port:user:pass  or  "
              "scheme://user:pass@host:port")
        print(c("Keep that file only on your phone. Never upload it.", YELLOW))
        return None, None
    print(c(f"Loaded {len(proxies)} proxies from {path}", DIM))
    return proxies, path


def cmd_proxy_test(args):
    banner()
    proxies, _path = _proxy_preamble()
    if proxies is None:
        return 1
    print("Testing (this talks to each proxy once)...")
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
        futures = {pool.submit(test_one_proxy, p): p for p in proxies}
        for fut in concurrent.futures.as_completed(futures):
            results.append(fut.result())
    alive = [r for r in results if r["ok"]]
    alive.sort(key=lambda r: r["ms"])
    print(c(f"\nAlive: {len(alive)}/{len(results)}", CYAN + BOLD))
    for r in alive:
        print(f"  {mask_proxy(r):<44} {r['ms']:>6} ms  exit={r.get('exit_ip')}  "
              f"{r.get('country')}/{r.get('city')}")
    if len(alive) < len(results):
        print(c(f"\nDead/failed: {len(results) - len(alive)} (not shown; "
                "your list may have expired entries)", DIM))
    return 0


def cmd_proxy_run(args):
    banner()
    proxies, _path = _proxy_preamble()
    if proxies is None:
        return 1
    rounds = max(1, args.rounds)
    print(f"Rotating through your list for {rounds} round(s). Ctrl+C to stop.")
    print(c("Demo rotation: shows the exit IP each hop would use. "
            "Apps only use a proxy if you point them at it.", DIM))
    idx = 0
    try:
        for done in range(rounds):
            alive = []
            for _try in range(len(proxies)):
                proxy = proxies[idx % len(proxies)]
                idx += 1
                res = test_one_proxy(proxy)
                if res["ok"]:
                    alive.append(res)
                    print(f"  hop {done + 1}: {mask_proxy(res)} -> "
                          f"exit {res['exit_ip']} ({res['country']}) "
                          f"{res['ms']} ms")
                    break
                print(f"  skip dead: {mask_proxy(proxy)} ({res['error']})")
            if not alive:
                print(c("No alive proxy found this round.", RED))
                break
            if done < rounds - 1:
                time.sleep(max(0, args.delay))
    except KeyboardInterrupt:
        print(c("\nStopped.", YELLOW))
    return 0


def cmd_proxy(args):
    if args.proxy_cmd == "test":
        return cmd_proxy_test(args)
    if args.proxy_cmd == "run":
        return cmd_proxy_run(args)
    return cmd_proxy_test(args)


# --------------------------------------------------------------------------
# Tor subcommands + menu
# --------------------------------------------------------------------------

def cmd_tor(args):
    banner()
    if args.tor_cmd == "start":
        tor_start()
    elif args.tor_cmd == "stop":
        tor_stop()
    elif args.tor_cmd == "ip":
        if not tor_running():
            print(c("Tor is not running (127.0.0.1:9050 not answering).", YELLOW))
            print("Start with:  v4zip tor start")
            return 1
        try:
            info = get_tor_ip_info()
            print_info(info, "Tor exit IP")
            log_ip(info, note="tor-ip")
        except Exception as exc:  # noqa: BLE001
            print(c(f"Tor lookup failed: {exc}", RED))
            return 1
    else:  # status
        installed = _which("tor") is not None
        running = tor_running()
        print(f"  tor installed : {'yes' if installed else 'no (pkg install tor)'}")
        print(f"  tor running   : {'yes (127.0.0.1:9050)' if running else 'no'}")
    return 0


def menu():
    banner()
    actions = {
        "1": ("Check my IP", lambda: cmd_check(None)),
        "2": ("Start Tor", lambda: (banner(), tor_start())[1]),
        "3": ("Stop Tor", lambda: (banner(), tor_stop())[1]),
        "4": ("Compare direct vs Tor IP", lambda: cmd_compare(None)),
        "5": ("Privacy score", lambda: cmd_score(None)),
        "6": ("Show IP history (log)", lambda: cmd_log(10)),
        "7": ("Test my proxies (proxies.txt)", lambda: cmd_proxy_test(None)),
        "8": ("Rotate proxies (demo)", lambda: cmd_proxy_run(
            type("A", (), {"rounds": 3, "delay": 2})())),
        "9": ("Save session report", lambda: cmd_report(None)),
        "0": ("Exit", None),
    }
    while True:
        print()
        for key, (label, _fn) in actions.items():
            print(f"  {key}) {label}")
        choice = input(c("\nChoose: ", CYAN)).strip()
        if choice == "0":
            print("Bye.")
            return 0
        item = actions.get(choice)
        if not item:
            print(c("Unknown choice.", YELLOW))
            continue
        try:
            item[1]()
        except KeyboardInterrupt:
            print(c("\nInterrupted.", YELLOW))
        input(c("\n[Enter] back to menu ", DIM))


def build_parser():
    parser = argparse.ArgumentParser(
        prog="v4zip",
        description=f"{APP_NAME} - Termux IP checker, Tor compare, "
                    "privacy score and local proxy tester.")
    parser.add_argument("--version", action="version",
                        version=f"v4zip {VERSION}")
    sub = parser.add_subparsers(dest="cmd")

    sub.add_parser("check", help="show your current public IP info")
    sub.add_parser("compare", help="direct IP vs Tor exit IP")
    sub.add_parser("score", help="privacy score from observable signals")

    p_log = sub.add_parser("log", help="show IP change history")
    p_log.add_argument("--last", type=int, default=10)

    sub.add_parser("report", help="save a text session report")

    p_tor = sub.add_parser("tor", help="tor controls")
    tor_sub = p_tor.add_subparsers(dest="tor_cmd")
    tor_sub.add_parser("status")
    tor_sub.add_parser("start")
    tor_sub.add_parser("stop")
    tor_sub.add_parser("ip")

    p_proxy = sub.add_parser("proxy", help="local proxies.txt tools")
    proxy_sub = p_proxy.add_subparsers(dest="proxy_cmd")
    proxy_sub.add_parser("test")
    p_run = proxy_sub.add_parser("run")
    p_run.add_argument("--rounds", type=int, default=3)
    p_run.add_argument("--delay", type=int, default=2)
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.cmd is None:
        return menu()
    if args.cmd == "check":
        return cmd_check(args)
    if args.cmd == "compare":
        return cmd_compare(args)
    if args.cmd == "score":
        return cmd_score(args)
    if args.cmd == "log":
        cmd_log(args.last)
        return 0
    if args.cmd == "report":
        return cmd_report(args)
    if args.cmd == "tor":
        return cmd_tor(args)
    if args.cmd == "proxy":
        return cmd_proxy(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
