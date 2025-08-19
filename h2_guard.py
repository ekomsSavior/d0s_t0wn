#!/usr/bin/env python3
# h2_guard.py — Safe HTTP/2 exposure + config auditor + rate-limit validator (no flood logic).
# Usage: sudo python3 h2_guard.py

import os, sys, shutil, subprocess, re, time, socket, ssl, json, statistics
from datetime import datetime, timezone
from ipaddress import ip_address

LOOT = "loot"
os.makedirs(LOOT, exist_ok=True)

def which(name):
    return shutil.which(name)

def run_cmd(cmd):
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True)
        return out, 0
    except subprocess.CalledProcessError as e:
        return e.output, e.returncode

def prompt(msg, default=None):
    v = input(f"{msg}{' ['+str(default)+']' if default is not None else ''}: ").strip()
    return v if v else default

# ---------- helpers ----------
def is_private_or_local(host):
    try:
        ip = ip_address(host)
        return ip.is_private or ip.is_loopback
    except ValueError:
        # hostname: try resolve
        try:
            ip = ip_address(socket.gethostbyname(host))
            return ip.is_private or ip.is_loopback
        except Exception:
            return False

def now_ts():
    # timezone-aware UTC (avoids deprecation warnings)
    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")

def default_iface():
    """
    Best-effort default interface guess:
    - Try 'ip route get 1.1.1.1'
    - Fallback to 'eth0'
    """
    try:
        out, rc = run_cmd(["ip", "route", "get", "1.1.1.1"])
        if rc == 0:
            m = re.search(r"dev\s+(\S+)", out)
            if m:
                return m.group(1)
    except Exception:
        pass
    return "eth0"

# ---------- OpenSSL ALPN fallback ----------
def openssl_alpn_h2(host, port, timeout=5):
    """
    Returns True if OpenSSL confirms ALPN 'h2' is negotiated on host:port.
    """
    if not which("openssl"):
        return False
    try:
        cmd = [
            "openssl","s_client","-alpn","h2",
            "-connect", f"{host}:{port}",
            "-servername", host,
            "-brief","-tls1_2"
        ]
        out, rc = run_cmd(cmd)
        return ("ALPN protocol: h2" in out)
    except Exception:
        return False

# ---------- Active scan (nmap tls-alpn) ----------
def parse_nmap_h2(out):
    """
    Parse Nmap tls-alpn output. Only mark a port as h2 if the tls-alpn section
    explicitly lists 'h2'.
    Example:
      | tls-alpn:
      |   h2
      |   http/1.1
      |_  http/1.0
    """
    h2_ports = set()
    cur_port = None
    in_tls_alpn_block = False

    for raw in out.splitlines():
        line = raw.rstrip("\n")

        # Track open port lines like: "443/tcp open  https"
        m = re.match(r'^(\d{1,5})/tcp\s+open', line)
        if m:
            cur_port = m.group(1)
            in_tls_alpn_block = False
            continue

        # Enter tls-alpn section
        if re.match(r'^\|\s+tls-alpn:\s*$', line):
            in_tls_alpn_block = True
            continue

        # Exit block on end marker or new script section
        if in_tls_alpn_block and (re.match(r'^\|_', line) or re.match(r'^\|\s+\w', line)):
            in_tls_alpn_block = False
            continue

        # Within block, look for protocol lines like: "|   h2"
        if in_tls_alpn_block and cur_port:
            if re.match(r'^\|\s+h2\s*$', line):
                h2_ports.add(cur_port)
                # one h2 line is enough for this port
                continue

    return sorted(h2_ports)

def active_scan(target, ports=None, all_ports=False):
    if not which("nmap"):
        return None, "[!] nmap not found (install: sudo apt install nmap)"

    # Prefer tls-alpn (correct NSE)
    if all_ports:
        cmd = ["sudo","nmap","-p-","-sV","--open","--script","tls-alpn",target]
    else:
        ports = ports or "443,80,8080,8443,9443,10443,50051"
        cmd = ["sudo","nmap","-p",ports,"-sV","--open","--script","tls-alpn",target]

    print(f"\n[+] Running nmap ALPN scan on {target} ...")
    out, rc = run_cmd(cmd)
    path = os.path.join(LOOT, f"h2_active_{target.replace('/','_')}_{now_ts()}.txt")
    with open(path,"w") as f: f.write(out)
    if rc != 0:
        print("[!] nmap returned non-zero exit; check output. (Tip: sudo nmap --script-help tls-alpn)")

    h2_ports = parse_nmap_h2(out)

    # Fallback with OpenSSL if no hits and a concrete port list is known
    if (not h2_ports) and ports:
        print("[i] No h2 ports found by Nmap; attempting OpenSSL ALPN fallback ...")
        for p in str(ports).split(","):
            p = p.strip()
            if p.isdigit() and openssl_alpn_h2(target, p):
                h2_ports.append(p)
        h2_ports = sorted(set(h2_ports))
        if h2_ports:
            print(f"[+] OpenSSL confirmed h2 on: {', '.join(h2_ports)}")

    print(f"[✓] Active scan saved → {path}")
    return h2_ports, None

# ---------- HTTP/2 SETTINGS probe (safe single connection) ----------
def probe_h2_settings(host, port):
    """
    Uses hyper (if available) to negotiate h2 and read remote SETTINGS.
    Returns (dict, errstr).
    """
    try:
        from hyper import HTTPConnection
    except Exception:
        return None, "[i] Python 'hyper' not installed (pip3 install hyper)"

    try:
        ctx = ssl.create_default_context()
        ctx.set_alpn_protocols(['h2'])
        s = socket.create_connection((host, int(port)), timeout=5)
        s = ctx.wrap_socket(s, server_hostname=host)
        if s.selected_alpn_protocol() != "h2":
            try: s.close()
            except: pass
            return None, "[i] ALPN did not negotiate h2 on this port."
        conn = HTTPConnection(host, port=int(port), secure=True, ssl_context=ctx, socket=s)
        settings = getattr(conn, "_remote_settings", {}) or {}
        out = {}
        if hasattr(settings, "items"):
            for k, v in settings.items():
                try:
                    out[str(k)] = int(v)
                except Exception:
                    pass
        try: s.close()
        except: pass
        return out, None
    except Exception as e:
        return None, f"[i] SETTINGS probe failed: {e}"

# ---------- Passive capture (tshark) ----------
def passive_capture(iface, seconds=60, target_host=None):
    if not which("tshark"):
        return "[!] tshark not found (install: sudo apt install tshark)"
    outpath = os.path.join(LOOT, f"h2_passive_{iface}_{now_ts()}.txt")
    display = "tls.handshake.extensions_alpn_str == h2"
    if target_host:
        display = f"({display}) && (ip.addr == {target_host})"
    cmd = ["sudo","tshark","-i",iface,"-Y",display,"-T","fields",
           "-e","frame.time","-e","ip.src","-e","ip.dst","-e","tcp.dstport",
           "-e","tls.handshake.extensions_alpn_str"]
    print(f"\n[+] Starting passive capture on {iface} for {seconds}s (filter: {display})")
    with open(outpath, "w") as f:
        proc = subprocess.Popen(cmd, stdout=f, stderr=subprocess.STDOUT, text=True)
        try:
            time.sleep(seconds)
        except KeyboardInterrupt:
            pass
        finally:
            proc.terminate()
            try: proc.wait(timeout=3)
            except subprocess.TimeoutExpired: proc.kill()
    print(f"[✓] Passive capture saved → {outpath}")
    return None

# ---------- SAFE rate-limit validator (HTTP/2; small capped requests) ----------
def ratelimit_probe(url, total=200, rps=20, max_conns=10, timeout=5.0, method="GET", assume_owned=True):
    """
    Sends small, capped H2 requests to your host and checks whether you see 429/503
    and how latency behaves. No stream resets, no abuse. Requires httpx with h2.
    """
    try:
        import httpx
    except Exception:
        return None, "[!] httpx not installed. Install: pip3 install 'httpx[http2]'"

    # Parse host for safety hint
    from urllib.parse import urlparse
    u = urlparse(url)
    host = u.hostname or ""
    if not host:
        return None, "[!] Invalid URL."

    is_private = is_private_or_local(host)
    if not is_private and not assume_owned:
        return None, "[i] Skipping rate-limit probe on non-private host (assume_owned=False)."

    # httpx client with HTTP/2 and connection caps
    limits = httpx.Limits(max_keepalive_connections=max_conns, max_connections=max_conns)
    client = httpx.Client(http2=True, verify=False, limits=limits, timeout=timeout)

    lat_ms = []
    codes = {}
    errs = 0
    started = time.perf_counter()
    interval = 1.0 / float(max(1, rps))

    for _ in range(total):
        t0 = time.perf_counter()
        try:
            if method == "GET":
                r = client.get(url, headers={"Accept": "*/*"})
            else:
                r = client.head(url)
            r.read()  # drain body if any
            dt = (time.perf_counter() - t0) * 1000.0
            lat_ms.append(dt)
            codes[r.status_code] = codes.get(r.status_code, 0) + 1
        except Exception:
            errs += 1
        # pace requests
        elapsed = time.perf_counter() - t0
        sleep_for = interval - elapsed
        if sleep_for > 0:
            time.sleep(sleep_for)

    took = time.perf_counter() - started
    client.close()

    summary = {
        "url": url,
        "http2_enabled": True,
        "total_attempted": total,
        "sent_rate_target_rps": rps,
        "duration_seconds": round(took, 2),
        "status_counts": codes,
        "errors": errs,
        "latency_ms": {
            "count": len(lat_ms),
            "p50": round(statistics.median(lat_ms), 2) if lat_ms else None,
            "p95": round(statistics.quantiles(lat_ms, n=20)[18], 2) if len(lat_ms) >= 20 else None,
            "p99": round(statistics.quantiles(lat_ms, n=100)[98], 2) if len(lat_ms) >= 100 else None,
            "min": round(min(lat_ms), 2) if lat_ms else None,
            "max": round(max(lat_ms), 2) if lat_ms else None,
        }
    }
    return summary, None

def save_probe_report(summary):
    ts = now_ts()
    jpath = os.path.join(LOOT, f"h2_ratelimit_{ts}.json")
    tpath = os.path.join(LOOT, f"h2_ratelimit_{ts}.txt")
    with open(jpath, "w") as jf:
        json.dump(summary, jf, indent=2, sort_keys=True)
    # text summary
    lines = []
    lines.append(f"# H2 Rate-Limit Probe Report ({ts})")
    lines.append(f"URL: {summary['url']}")
    sc = summary["status_counts"]
    lines.append("Status counts: " + ", ".join(f"{k}:{v}" for k,v in sorted(sc.items())) if sc else "Status counts: (none)")
    lines.append(f"Errors: {summary['errors']}")
    lat = summary["latency_ms"]
    lines.append(f"Latency (ms): count={lat['count']} p50={lat['p50']} p95={lat['p95']} p99={lat['p99']} min={lat['min']} max={lat['max']}")
    # Simple verdicts
    v = []
    if sc.get(429, 0) > 0:
        v.append("✅ 429 observed (rate limit engaged).")
    if sc.get(503, 0) > 0:
        v.append("✅ 503 observed (overload protection).")
    if not v:
        v.append("⚠️ No 429/503 observed; consider tightening per-IP rate/conn/streams.")
    lines.append("Verdict: " + " ".join(v))
    with open(tpath, "w") as tf:
        tf.write("\n".join(lines) + "\n")
    print(f"[✓] Rate-limit probe saved → {jpath}\n[✓] Summary → {tpath}")

# ---------- Mitigation checklist ----------
def mitigation_text(host, ports_h2, settings_map):
    lines = []
    lines.append(f"# H2 Mitigation Checklist for {host}")
    if not ports_h2:
        lines.append("- No ports advertising ALPN=h2 were found by nmap on the scanned range.")
    else:
        lines.append(f"- Ports with ALPN=h2: {', '.join(ports_h2)}")
        lines.append("- For each h2 listener, consider:")
        lines.append("  • NGINX: http2_max_concurrent_streams 50–100; http2_recv_timeout 2–3s; keepalive_requests 50–100;")
        lines.append("    plus limit_conn/limit_req per real client IP.")
        lines.append("  • HAProxy: tune.h2.max-concurrent-streams 50–100; src rate/conn caps; http-buffer-request;")
        lines.append("    use stick-tables for src_http_req_rate()/conn rate bans.")
        lines.append("  • Envoy: http2_protocol_options.max_concurrent_streams: 50–100; stream_error_on_invalid_http_message: true;")
        lines.append("    set circuit breakers & retry budgets, and cap request queues.")
        lines.append("  • CDN/WAF: enable HTTP/2 rapid-reset protections; configure per-IP connection/stream caps.")
    for port, st in settings_map.items():
        if not st:
            continue
        # Common key names seen from hyper's internal dict
        mcs = st.get("SETTINGS_MAX_CONCURRENT_STREAMS") or st.get("MAX_CONCURRENT_STREAMS") \
              or st.get("SETTINGS_MAX_CONCURRENT_STREAMS".lower()) or st.get("4")
        if mcs:
            lines.append(f"- Port {port}: peer SETTINGS_MAX_CONCURRENT_STREAMS ≈ {mcs} (observed).")
            lines.append("  • If high, lower it to reduce per-connection fanout; set short recv/idle timeouts.")
    lines.append("\n# Discovery commands you can reuse")
    lines.append("sudo nmap -p 443,80,8080,8443,9443,10443,50051 --script tls-alpn <target>")
    lines.append('sudo tshark -i <iface> -Y "tls.handshake.extensions_alpn_str == h2"')
    return "\n".join(lines)

# ---------- main ----------
def main():
    print(r"""
H2 Guard — HTTP/2 Exposure & Settings Auditor (safe)
---------------------------------------------------
Auto-run mode (no Y/N prompts):
- Quick ALPN discovery (nmap tls-alpn) + OpenSSL fallback
- SETTINGS probe (safe single connection per h2 port)
- Passive ALPN capture (tshark)
- Safe rate-limit probe (tiny capped H2 GETs)
- Mitigation checklist
""")
    # ---- Target (still a prompt so you can specify host quickly)
    target = prompt("Target (IP/hostname or CIDR)", "127.0.0.1")

    # ---- Active scan (auto: quick common ports)
    ports = "443,80,8080,8443,9443,10443,50051"
    all_ports = False
    h2_ports, err = active_scan(target, ports=ports, all_ports=all_ports)
    if err:
        print(err)

    # ---- SETTINGS probe (auto)
    settings_map = {}
    if h2_ports:
        print("\n[+] Probing HTTP/2 SETTINGS (one safe connection per port)...")
        host_for_probe = target
        for p in h2_ports:
            st, e = probe_h2_settings(host_for_probe, p)
            if e:
                print(f"  - {host_for_probe}:{p} → {e}")
            settings_map[p] = st
        with open(os.path.join(LOOT, f"h2_settings_{host_for_probe}_{now_ts()}.json"), "w") as f:
            json.dump(settings_map, f, indent=2, sort_keys=True)
        print("[✓] SETTINGS snapshot saved.")

    # ---- Passive capture (auto)
    iface = prompt("Interface (e.g., eth0, wlan0)", default_iface())
    secs = int(prompt("Duration seconds", "60"))
    host_filter = None
    try:
        # If target is a single IP/host, try to filter; if CIDR, skip.
        ip_address(target); host_filter = target
    except ValueError:
        try:
            host_filter = socket.gethostbyname(target)
        except Exception:
            host_filter = None
    errp = passive_capture(iface, secs, host_filter)
    if errp:
        print(errp)

    # ---- Rate-limit validation (auto)
    # Build a default URL from target; if CIDR or non-HTTPS, user can edit the default quickly.
    url_default = "https://%s/" % (target if not re.match(r'.*/', target) else target.rstrip('/'))
    url = prompt("Full URL to probe (must be your host)", url_default)
    total = int(prompt("Total requests (<=1000 recommended)", "200"))
    rps   = int(prompt("Target send rate (RPS)", "20"))
    conns = int(prompt("Max concurrent connections", "10"))
    timeout = float(prompt("Per-request timeout (seconds)", "5.0"))
    summary, perr = ratelimit_probe(url, total=total, rps=rps, max_conns=conns, timeout=timeout, assume_owned=True)
    if perr:
        print(perr)
    else:
        save_probe_report(summary)

    # ---- Mitigation checklist (auto)
    checklist = mitigation_text(target, h2_ports or [], settings_map)
    path = os.path.join(LOOT, f"h2_mitigation_{target.replace('/','_')}_{now_ts()}.txt")
    with open(path,"w") as f:
        f.write(checklist)
    print(f"\n[✓] Mitigation checklist saved → {path}")
    print("\n[Done]")

if __name__ == "__main__":
    main()
