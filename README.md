# d0s_t0wn
### c0me 0n d0wn t0 d0s t0wn

# HTTP/2 Rapid Reset d0s & H2 Guard

## Overview

This repository contains **two complementary tools** for studying and mitigating the HTTP/2 “Rapid Reset” class of denial-of-service vulnerabilities (see [CVE-2025-8671](https://nvd.nist.gov/)):

* **`http2_rapid_reset.py`** — A python scripted stressor that demonstrates how attackers can abuse HTTP/2’s stream accounting mismatches (“imaginary rules”) to trigger excessive server work.
* **`h2_guard.py`** — A safe auditing utility for defenders. It scans for HTTP/2 exposure, inspects SETTINGS, optionally captures ALPN handshakes, runs capped/safe rate-limit probes, and produces mitigation checklists.

Together, they show both sides of the coin: where the protocol cracks under pressure, and how operators can detect and harden their own stacks.

---

## Background: The “Imaginary Rules” in HTTP/2

HTTP/2 multiplexes many streams over a single connection. On paper, the spec assumes:

* **Resets stop work** — once a stream is reset (`RST_STREAM`), processing halts.
* **Counters align** — stream/accounting at the protocol layer matches backend reality.
* **Flow control & headers protect** — windows and header size limits prevent excess cost.

In practice, these assumptions (“imaginary rules”) often **don’t hold**. Backend tasks may continue after resets, counters may drift, and error handling can be CPU-expensive.
Attackers exploit this gap by **opening many streams, triggering resets rapidly, or provoking flow-control/header errors**—leaving servers chewing on “dead” work.

---

## Script Roles

### 1. `http2_rapid_reset.py` (attacker)

* Opens multiple HTTP/2 connections and multiplexed streams.
* Cycles through tactics:

  * **Client resets**: send HEADERS then immediately `RST_STREAM(CANCEL)`.
  * **Malformed headers**: oversized/invalid HPACK to make the *server* issue a reset.
  * **Flow control violations**: push DATA beyond window limits.
* Demonstrates how servers with weak propagation or high `MAX_CONCURRENT_STREAMS` continue burning CPU/memory even after “resets.”
* Also includes other classic flood modes (HTTP/1 floods, TLS handshakes, slow POST, UDP/TCP floods, etc.) for comparative testing.

 **Note:** This script is a **stressor / red-team simulator**. Running it against systems you don’t own or lack permission for is illegal.

---

### 2. `h2_guard.py` (defender)

Focuses on safe, defensive inspection:

* **Active scan** — uses nmap’s `ssl-enum-alpn` to identify which ports negotiate ALPN=h2.
* **SETTINGS probe** — makes a *single safe HTTP/2 connection* to read server `SETTINGS` (e.g. `MAX_CONCURRENT_STREAMS`).
* **Passive capture** — optional tshark capture of ALPN=h2 handshakes on an interface.
* **Rate-limit validator** — sends **tiny capped GET/HEAD requests** (no resets, no abuse) to check whether your stack emits `429 Too Many Requests` or `503 Overload` before latency degrades.
* **Mitigation checklist** — generates actionable hardening steps per server, with vendor-specific knobs (NGINX, HAProxy, Envoy, CDN/WAF).

Artifacts are written to the `loot/` directory (`h2_active_*.txt`, `h2_settings_*.json`, `h2_ratelimit_*.json`, `h2_mitigation_*.txt`).

---

## Example Workflow

1. **Red-team simulation** (lab only)
   Run `http2_rapid_reset.py` against a controlled lab server to demonstrate how resets or malformed frames impact resource consumption.

2. **Blue-team audit**
   Run `h2_guard.py` against the same host:

   * Identify which ports are offering HTTP/2.
   * Capture observed SETTINGS, especially `MAX_CONCURRENT_STREAMS`.
   * Check if your server actually responds with `429/503` under capped, safe load.
   * Review the auto-generated mitigation checklist.

This side-by-side process helps highlight **the exact gap between stress surface and protection surface.**

---

## Defensive Takeaways

* **Cap per-connection fanout**: reduce `MAX_CONCURRENT_STREAMS` (50–100 typical).
* **Shorten idle/recv timeouts**: don’t let “dead” streams live long.
* **Propagate cancels upstream**: ensure resets stop backend work immediately.
* **Enforce per-IP budgets**: connections, streams, and req/sec should all be capped.
* **Trip early on errors**: close connections that send malformed frames or flow-control violations.
* **Audit regularly**: use `h2_guard.py` as part of your CI/CD or change review to catch regressions.

---

## Legal / Ethical Notice

* `http2_rapid_reset.py` is for **educational demonstration in controlled environments only**. Do not deploy it against networks or systems you do not own or lack explicit authorization to test.
* `h2_guard.py` is **safe for production audits** when run against your own infrastructure.

---

## INSTALLATION

Clone the repository

```bash
git clone https://github.com/ekomsSavior/d0s_t0wn.git
cd d0s_t0wn
```

Install required tools and libraries

```bash
sudo apt update && sudo apt install tor python3-requests python3-scapy nmap tshark nghttp2-client -y
pip3 install httpx[http2] scapy pysocks --break-system-packages
sudo nmap --script-updatedb
```

## to run HTTP/2 RAPID REQUEST ATTACK:

```bash
python3 http2_rapid_reset.py
```

## HTTP/2 Rapid-Reset Flood 

Overview

The http2 mode of the https2_rapid_reset.py script implements an HTTP/2 Rapid-Reset Flood, a low-bandwidth, high-impact attack designed to stress-test web servers by exploiting the HTTP/2 protocol's stream multiplexing. This mode sends rapid sequences of HTTP/2 HEADERS frames followed by RST_STREAM frames to maximize server resource consumption while minimizing client bandwidth usage.
Note: This script is intended for authorized network stress testing only. Unauthorized use may violate laws or terms of service.
What Happens When You Run http2 Mode?

HTTP/2 Connection Setup:

Establishes TLS connections to the target IP and port with HTTP/2 protocol negotiation (ALPN: h2).
Uses the hyper library to create HTTP/2 connections, ensuring compatibility with the HTTP/2 protocol.
If Tor is enabled (USE_TOR = True), connections route through a SOCKS5 proxy (127.0.0.1:9050), though HTTP/2 over Tor may be unreliable.


Server SETTINGS Parsing:

Queries the server’s SETTINGS frame to determine SETTINGS_MAX_CONCURRENT_STREAMS (default: 100 if not specified).
Caps concurrent streams per connection to avoid server backpressure, optimizing resource usage.


Rapid-Reset Attack Loop:

For each connection in each thread:
Generates HPACK-heavy headers with:
Randomized :path (e.g., /?q=1234).
Large cookie fields (session ID, multiple random parameters, and a token) to inflate server HPACK decoding costs.
Repeated headers (accept, accept-encoding, cache-control, pragma) to increase CPU load.
Spoofed :authority and x-forwarded-for with random IPs to evade simple filters.
Random user-agent from a list, including crawlers like Yahoo Slurp and DuckDuckBot (avoid mimicking DuckDuckBot’s IP ranges listed in the document).


Sends a HEADERS frame to initiate a new stream, triggering server work (e.g., routing, DB queries).
Immediately sends a RST_STREAM frame (error code: CANCEL, 0x8) to terminate the stream, wasting server resources.
Cycles stream IDs (incrementing by 2) up to the server’s SETTINGS_MAX_CONCURRENT_STREAMS limit.


Pauses briefly (0.01s) to avoid client-side resource exhaustion.


GOAWAY Handling:

Detects GOAWAY frames from the server (indicating connection termination, e.g., due to rate-limiting or resource limits).
Closes the affected connection and opens a new one to maintain continuous stream churn.
Ensures no requests are sent on doomed connections, improving efficiency and stability.


Connection Management:

If a connection fails (e.g., socket error or HyperException), it’s closed and replaced with a new one.
Maintains up to MAX_CONNECTIONS_PER_THREAD active connections per thread.
Cleans up all connections when the attack duration expires or the script is stopped.


Execution Control:

Runs for the specified duration (e.g., 60 seconds).
If loop mode is enabled, repeats until interrupted (Ctrl+C).
Prints status messages:
Start: [~] Starting HTTP/2 Rapid-Reset Flood for <duration>s with <threads> threads...
End: [✓] HTTP/2 Rapid-Reset Flood complete.
Loop stop: [✘] Loop stopped by user.



Impact on the Target
The HTTP/2 Rapid-Reset Flood is designed to:

Maximize Server CPU Usage: HPACK-heavy headers and rapid stream resets force the server to process complex headers and allocate resources for short-lived streams.
Minimize Client Bandwidth: Sends minimal data (HEADERS + RST_STREAM) while triggering significant server-side work.
Exploit Protocol Efficiency: Leverages HTTP/2’s multiplexing to open multiple streams per connection, amplifying resource consumption.
Evade Basic Defenses: Random headers, spoofed IPs, and GOAWAY handling make the attack harder to filter or throttle.

----

# H2 Guard — HTTP/2 Exposure & Defense Auditor

`h2_guard.py` is a **safe** tool for defenders.
It helps you **discover**, **measure**, and **validate** how your infrastructure exposes HTTP/2, and whether basic mitigations (rate limits, stream caps, timeouts) are in place.

 **Important:** This script never performs flooding or reset attacks. All probes are low-impact, capped, and designed for defenders to audit their own servers.

---

## Features

1. **Active Scan (nmap + ssl-enum-alpn)**

   * Runs an **nmap** scan against the target.
   * Identifies which TCP ports negotiate **ALPN=h2** (HTTP/2).
   * Saves raw output under `loot/h2_active_<target>_<timestamp>.txt`.

   Example result:

   ```
   Ports with ALPN=h2: 443, 8443
   ```

2. **HTTP/2 SETTINGS Probe**

   * For each h2 port, opens a **single safe connection** with the `hyper` library.
   * Reads remote HTTP/2 **SETTINGS frame**, especially `SETTINGS_MAX_CONCURRENT_STREAMS`.
   * Captures values defenders should tune (too high = easier for attackers).
   * Saves snapshot as JSON in `loot/h2_settings_<host>_<timestamp>.json`.

   Example result:

   ```
   Port 443: peer SETTINGS_MAX_CONCURRENT_STREAMS ≈ 100
   ```

3. **Passive Capture (tshark)** *(optional)*

   * Uses **tshark** to listen for ALPN=h2 handshakes on a chosen interface.
   * Lets you verify whether traffic is negotiating HTTP/2 in real time.
   * Useful for live environments or when monitoring edge/CDN handshakes.
   * Saves capture log under `loot/h2_passive_<iface>_<timestamp>.txt`.

4. **Rate-Limit Validation Probe (SAFE)**

   * Sends **small, capped GETs over HTTP/2** using `httpx`.
   * Total requests & RPS are capped (defaults: 200 requests @ 20 RPS).
   * Confirms whether server/CDN responds with **429 (Too Many Requests)** or **503 (Service Unavailable)** when thresholds are exceeded.
   * Measures latency distribution (p50 / p95 / p99) so you can spot early degradation.
   * Saves JSON + text report in `loot/h2_ratelimit_<timestamp>.{json,txt}`.

   Example summary:

   ```
   Status counts: 200:180, 429:20
   Errors: 0
   Latency (ms): count=200 p50=12.4 p95=55.8 p99=120.3 min=5.3 max=180.1
   Verdict:  429 observed (rate limit engaged).
   ```

5. **Mitigation Checklist**

   * Generates a **hardening guide** specific to your findings.
   * Covers:

     * NGINX, HAProxy, Envoy best practices.
     * Recommended values for `http2_max_concurrent_streams`, recv/idle timeouts.
     * Use of `limit_req`, stick-tables, circuit breakers, CDN/WAF protections.
   * Saved under `loot/h2_mitigation_<target>_<timestamp>.txt`.

---

## Typical Workflow

1. Run:

   ```bash
   sudo python3 h2_guard.py
   ```
2. Enter target IP/hostname or CIDR.
3. Choose quick scan (common ports) or full port scan.
4. Script will:

   * Discover h2 endpoints.
   * Probe SETTINGS.
   * Optionally capture traffic.
   * Optionally validate rate limits safely.
5. Review artifacts in `loot/`:

   * `h2_active_*.txt` → ALPN discovery
   * `h2_settings_*.json` → SETTINGS snapshots
   * `h2_passive_*.txt` → live captures
   * `h2_ratelimit_*.{json,txt}` → rate-limit probe results
   * `h2_mitigation_*.txt` → mitigation checklist

---

## Example Defender Use Cases

* **Before exposure:** Check which services/CDNs are speaking HTTP/2.
* **After hardening:** Validate your `limit_req`, stream caps, and CDN protections trigger 429/503 as expected.
* **During monitoring:** Capture ALPN handshakes to see if unexpected ports negotiate HTTP/2.
* **Audit evidence:** Ship the `loot/` artifacts into your SIEM / compliance reports.

---

 With this in place, defenders can **quickly confirm** whether they’re hardened against **rapid-reset and related HTTP/2 abuse vectors**, without ever running a live flood.

---

## DISCLAIMER

This script is for testing network resilience with explicit permission. The HTTP/2 rapid-reset attack, enhanced with GOAWAY handling and HPACK-heavy headers, is highly disruptive. Unauthorized use could violate laws or terms of service.

