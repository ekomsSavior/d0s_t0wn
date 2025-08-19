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

## DISCLAIMER

This script is for testing network resilience with explicit permission. The HTTP/2 rapid-reset attack, enhanced with GOAWAY handling and HPACK-heavy headers, is highly disruptive. Unauthorized use could violate laws or terms of service.

