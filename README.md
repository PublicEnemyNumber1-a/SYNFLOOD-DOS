The SYNFlood tool is a multi-threaded SYN flood attack script designed to overwhelm a target server by sending a large number of SYN packets. This tool can utilize proxies to mask the source IP address, making it more difficult for detection systems to identify the attack. It also supports randomization of TCP flags and can simulate SSL/TLS handshakes to mimic legitimate connection attempts.

## Features
- Multi-threaded SYN flood attack
- Proxy support for IP masking
- Randomized TCP flags for stealth
- SSL/TLS handshake simulation
- Rate limiting to control packet sending frequency
- Logging of sent packets
- Statistics display for monitoring attack progress

## Requirements
- Python 3.x
- Required Python libraries:
  - `scapy`
  - `requests`
  - `socks`
  - `concurrent.futures`
  - `argparse`
  
## Installation

### Step 1: Install Python
Ensure you have Python 3.x installed on your system. You can download it from the official [Python website](https://www.python.org/downloads/).

### Step 2: Install Required Libraries
You can install the required libraries using `pip`. Open your terminal or command prompt and run the following commands:

```bash
pip install scapy requests pysocks
```

### Step 3: Download the SYNFlood Tool
You can download the SYNFlood tool from the repository or copy the code into a Python file named `SYNFLOOD.py`.

### Step 4: Make the Script Executable (Optional)
If you are using a Unix-based system (Linux, macOS), you can make the script executable by running:

```bash
chmod +x SYNFLOOD.py
```

## Usage

### Command-Line Interface
To run the SYNFlood tool, use the following command format:

```bash
python SYNFLOOD.py <target_url> [-p <port>] [-t <threads>] [-n <packets>] [--rate <rate>] [--proxies <proxies_file>]
```

### Parameters
- `<target_url>`: The target URL to resolve to IP addresses.
- `-p`, `--port`: The target port (default: 80).
- `-t`, `--threads`: Number of threads to use for the attack (default: 100).
- `-n`, `--packets`: Number of SYN packets to send per thread iteration (default: 100).
- `--rate`: Rate limit per source IP (SYN packets per second, default: 10).
- `--proxies`: Path to the file containing proxies (one per line).

### Example Command
```bash
python SYNFLOOD.py example.com -p 80 -t 200 -n 50 --rate 5 --proxies proxies.txt
```

## Logging
The tool logs all sent SYN packets to a file named `syn_flood.log`. You can check this file for details about the packets sent during the attack.

## Statistics Display
The tool provides real-time statistics on the number of SYN packets sent and the rate of packets per second. This information is displayed in the terminal during the attack.

## Important Notes
- **Ethical Use**: This tool is intended for educational purposes and should only be used in a controlled environment with permission from the target. Unauthorized use of this tool against any network or system is illegal and unethical.
- **Firewall and Security**: Be aware that using this tool may trigger security alerts and could lead to legal consequences. Always ensure you have permission to test the target system.
- **Performance**: The effectiveness of the attack may vary based on the target's network configuration and security measures in place.

## Conclusion
The SYNFlood tool is a powerful utility for simulating SYN flood attacks for educational and testing purposes. By following the installation and usage instructions, you can effectively utilize this tool while adhering to ethical guidelines. Always remember to use such tools responsibly and legally.
