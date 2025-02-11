# Detailed Documentation of DDoS Attack Tool (Version 3.0)

## Overview

This script is a DDoS (Distributed Denial of Service) attack tool designed to perform various types of attacks, including HTTP request floods and SYN floods. It utilizes proxy servers and Tor instances to anonymize the source of the requests, making it harder to trace the origin of the attack. The script is written in Python and leverages several libraries, including `requests`, `scapy`, and `threading`, to achieve its functionality.

## Table of Contents

1. [Dependencies](#dependencies)
2. [Global Variables](#global-variables)
3. [Classes](#classes)
   - [ProxyChecker](#proxychecker)
   - [RateLimiter](#ratelimiter)
   - [SYNFlood](#synflood)
4. [Functions](#functions)
   - [filter_working_proxies](#filter_working_proxies)
   - [generate_dynamic_payload](#generate_dynamic_payload)
   - [generate_headers](#generate_headers)
   - [ddos_attack_https](#ddos_attack_https)
   - [display_statistics](#display_statistics)
   - [multitor](#multitor)
   - [load_proxies_from_file](#load_proxies_from_file)
   - [cleanup_tor_processes](#cleanup_tor_processes)
   - [signal_handler](#signal_handler)
   - [log_packet_sent](#log_packet_sent)
   - [resolve_url_to_ips](#resolve_url_to_ips)
   - [main](#main)
   - [main2](#main2)
5. [Execution Flow](#execution-flow)
6. [Usage Instructions](#usage-instructions)
7. [Important Notes](#important-notes)

## Dependencies

To run this script, the following Python packages must be installed:

- `requests`
- `scapy`
- `socks`
- `threading`
- `logging`

You can install the required packages using pip:

```bash
pip install requests scapy pysocks
```

## Global Variables

- `request_count`: Tracks the total number of requests sent.
- `successful_requests`: Counts the number of successful requests.
- `failed_requests`: Counts the number of failed requests.
- `USER_AGENTS`: A list of user-agent strings for HTTP requests.

## Classes

### ProxyChecker

This class is responsible for validating a list of proxy servers.

- **Methods:**
  - `checkAll(proxies: list, url: str, timeout: int, threads: int)`: Validates all proxies by sending requests to a specified URL.
  - `_check_single(proxy: str, url: str, timeout: int)`: Checks a single proxy by sending a request and returning whether it was successful.

### RateLimiter

This class implements a rate-limiting mechanism to control the number of requests sent from a single source IP.

- **Methods:**
  - `__init__(limit)`: Initializes the rate limiter with a specified limit.
  - `allow_request(key)`: Checks if a request is allowed based on the rate limit.

### SYNFlood

This class implements the SYN flood attack mechanism.

- **Attributes:**
  - `target`: Tuple containing the target IP and port.
  - `syn_packet_count`: Counts the number of SYN packets sent.
  - `rate_limiter`: Instance of `RateLimiter` to control packet sending rate.
  - `proxies`: List of proxies to use for sending packets.
  - `use_tls`: Boolean indicating whether to use TLS/SSL.

- **Methods:**
  - `generate_random_ip()`: Generates a random source IP address.
  - `_generate_syn()`: Generates a SYN packet with randomized attributes.
  - `_send_syn_packet(raw_packet: bytes, proxy=None)`: Sends the SYN packet through a raw socket or proxy.
  - `_forward_packet_via_proxy(raw_packet: bytes, proxy: str)`: Forwards the SYN packet through a SOCKS proxy.
  - `_get_next_proxy()`: Retrieves the next available proxy for use.
  - `run_flood(packets_per_iteration: int)`: Executes the SYN flood attack.
  - `get_packet_count()`: Returns the total number of SYN packets sent.

## Functions

### filter_working_proxies

```python
def filter_working_proxies(proxies):
```

- **Description**: Validates a list of proxies and returns only the working ones.
- **Parameters**:
  - `proxies`: List of proxy addresses.
- **Returns**: List of valid proxies.

### generate_dynamic_payload

```python
def generate_dynamic_payload():
```

- **Description**: Generates a random HTTP payload for POST requests.
- **Returns**: A dictionary containing the HTTP method and payload.

### generate_headers

```python
def generate_headers():
```

- **Description**: Generates random HTTP headers, including user-agent and referer.
- **Returns**: A dictionary of HTTP headers.

### ddos_attack_https

```python
def ddos_attack_https(target_url, requests_per_second, proxies):
```

- **Description**: Sends HTTP requests to the target URL at a specified rate using the provided proxies.
- **Parameters**:
  - `target_url`: The URL to attack.
  - `requests_per_second`: Number of requests to send per second.
  - `proxies`: List of proxies to use.
  
### display_statistics

```python
def display_statistics(syn_flooder: SYNFlood):
```

- **Description**: Displays real-time statistics of the SYN flood attack.
- **Parameters**:
  - `syn_flooder`: Instance of the `SYNFlood` class.

### multitor

```python
def multitor(num_ports=5):
```

- **Description**: Sets up multiple Tor instances for anonymous requests.
- **Parameters**:
  - `num_ports`: Number of Tor instances to create.
- **Returns**: A tuple containing the list of proxies and the list of Tor processes.

### load_proxies_from_file

```python
def load_proxies_from_file(file_path):
```

- **Description**: Loads a list of proxies from a specified file.
- **Parameters**:
  - `file_path`: Path to the proxy file.
- **Returns**: List of proxies.

### cleanup_tor_processes

```python
def cleanup_tor_processes(tor_processes):
```

- **Description**: Terminates all running Tor processes.
- **Parameters**:
  - `tor_processes`: List of Tor process instances.

### signal_handler

```python
def signal_handler(sig, frame):
```

- **Description**: Handles termination signals to gracefully shut down the script.
- **Parameters**:
  - `sig`: Signal number.
  - `frame`: Current stack frame.

### log_packet_sent

```python
def log_packet_sent(dst_ip, dst_port, src_ip):
```

- **Description**: Logs the details of a sent SYN packet.
- **Parameters**:
  - `dst_ip`: Destination IP address.
  - `dst_port`: Destination port.
  - `src_ip`: Source IP address.

### resolve_url_to_ips

```python
def resolve_url_to_ips(url):
```

- **Description**: Resolves a URL to its associated IP addresses.
- **Parameters**:
  - `url`: The URL to resolve.
- **Returns**: List of IP addresses.

### main

```python
def main(target_url, target_port=80, thread_count=10, packets_per_thread=100, rate=10):
```

- **Description**: Main function that launches the SYN flood attack with specified parameters.
- **Parameters**:
  - `target_url`: The target URL for the attack.
  - `target_port`: The port to attack (default is 80).
  - `thread_count`: Number of threads to use for the attack.
  - `packets_per_thread`: Number of packets to send per thread iteration.
  - `rate`: Rate limit for packets per second.

### main2

```python
def main2():
```

- **Description**: User interface for inputting target details and starting the attack.
- **Returns**: None.

## Execution Flow

1. **Initialization**: The script starts by clearing the console and displaying a banner.
2. **User  Input**: It prompts the user for target details, including URL, number of threads, requests per second, and proxy settings.
3. **Proxy Loading**: If specified, it loads proxies from a file and validates them.
4. **Tor Setup**: If Tor instances are requested, it sets them up and adds their proxies to the list.
5. **Attack Launch**: The script resolves the target URL to IP addresses and launches the SYN flood attack using multiple threads.
6. **Statistics Display**: It continuously displays real-time statistics of the attack until interrupted.

## Usage Instructions

1. Ensure all dependencies are installed.
2. Run the script using Python:
   ```bash
   python DDoS_3.0.py
   ```
3. Follow the prompts to enter the target URL, number of threads, requests per second, and other settings.
4. Press `Ctrl+C` to stop the attack.

## Important Notes

- **Legal Disclaimer**: This script is intended for educational purposes only. Unauthorized use of this tool against any network or system is illegal and unethical. Always obtain permission before conducting any form of testing.
- **Resource Intensive**: Running this script can consume significant network and system resources. Ensure you have the necessary infrastructure to handle the load.
- **Proxy and Tor Usage**: Using proxies and Tor can help anonymize the source of the requests, but it may also slow down the attack due to the additional overhead.
