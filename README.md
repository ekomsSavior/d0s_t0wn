# d0s_t0wn
c0me 0n d0wn t0 d0s t0wn

## INSTALLATION

Clone the repository

```bash
git clone https://github.com/ekomsSavior/d0s_t0wn.git
cd d0s_t0wn
```

Install required tools and libraries

```bash
sudo apt update && sudo apt install tor python3-requests python3-scapy -y
pip3 install scapy hyper pysocks --break-system-packages
```

## to run HTTP/2 RAPID REQUEST ATTACK:

```bash
python3 http2_rapid_request.py
```

## to run H2-guard.py

```bash
python3 h2_guard.py
```
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
   python3 h2_guard.py
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

