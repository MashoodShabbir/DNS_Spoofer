# DNS Spoofer
A Python-based DNS spoofing tool that intercepts DNS queries and redirects target domains to a specified IP address. This script uses netfilterqueue and scapy to process and modify network packets.

## Features
- Intercepts DNS queries.
- Redirects traffic from a specified website to a chosen IP address.
- Easy to configure via command-line arguments.
- Includes support for modifying IP tables for local and remote testing.

# Requirements
Before running the script, ensure you have the following installed:

1. Python 3.x
2. Required Python libraries:
- netfilterqueue
- scapy
You can install the dependencies using:
```bash
pip install netfilterqueue scapy
```
## Clone the Repository
Clone this repository or download the script file directly:

```bash
git clone https://github.com/MashoodShabbir/DNS_Spoofer.git
cd DNS_Spoofer
```
# Usage
Command-Line Arguments
- -w, --website: The domain to spoof (e.g., www.bing.com).
- -r, --redirect: The IP address to redirect the target to (e.g., 192.168.1.100).

## Example Command
```bash
sudo python dns_spoofer.py -w www.bing.com -r 192.168.1.100
```

## Setting Up IP Tables
To intercept and forward DNS traffic, you need to modify your IP tables.

## Local Testing
For DNS requests originating from your local machine:

```bash
sudo iptables -I OUTPUT -p udp --dport 53 -j NFQUEUE --queue-num 1
sudo iptables -I INPUT -p udp --sport 53 -j NFQUEUE --queue-num 1
```
## Remote Testing
For DNS requests passing through your machine (e.g., a gateway or router):

```bash
sudo iptables -I FORWARD -p udp --dport 53 -j NFQUEUE --queue-num 1
```

## How It Works
### Intercept DNS Packets: 
- The script uses netfilterqueue to intercept packets routed to the specified queue.
### Check and Modify DNS Responses:
- If the intercepted packet is a DNS query for the specified domain, the script modifies the response to redirect the traffic to the target IP.
### Forward Packets:
- All packets, modified or unmodified, are forwarded to ensure uninterrupted network activity.

## Example Output
When running the script, you should see output similar to this:

```css
[+] Starting DNS Spoofer...
[INFO] Spoofing 'www.bing.com' and redirecting to '192.168.1.100'
[+] Spoofing Target: www.bing.com
[+] Packet Modified and Redirected!
```
## Important Notes
### Permissions:
- The script requires root privileges to modify IP tables and process packets. Run it using sudo.
### Disable DNS Over HTTPS (DoH):
- Modern browsers use DNS over HTTPS by default, which bypasses traditional DNS requests. Disable DoH in your browser settings to test effectively.
### Flush IP Tables After Testing:
- Reset your IP tables to avoid network interference:

```bash
sudo iptables -F
```

### For Educational Purposes Only:
- This tool is intended for educational and testing purposes on networks you own or have explicit permission to test. Unauthorized use is illegal.

## How to Stop the Script
Press Ctrl+C to stop the script. The tool will automatically unbind the queue and clean up resources.



Let me know if you want to tweak any section or add additional details!
