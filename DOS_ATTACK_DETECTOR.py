import time
import requests
import scapy.all as scapy
from datetime import datetime
import subprocess
import tcconfig
import threading
import ipaddress
import platform

# Thresholds for detecting DDoS attacks
THRESHOLD_PACKETS_PER_SECOND = 50
THRESHOLD_TIME_INTERVAL = 10
MAX_PACKETS_ALLOWED = 100

# Dictionary to store packet count for each source IP
ip_packet_count = {}

# Parameters for mitigation actions
sinkhole_ip = "192.168.52.0"
new_route_ip = "192.168.52.56"
reputation_service_url = ""
latency = "10"
bandwidth_limit = "10"
backup_route = ""

# Default values for latency and bandwidth limit
LATENCY_DEFAULT = "50ms"
BANDWIDTH_LIMIT_DEFAULT = "1Mbit"

# Interval for continuous monitoring in seconds
CONTINUOUS_MONITOR_INTERVAL = 60

# Variables to store previous packet count and time
previous_packet_count = 0
previous_time = None

# List to store internal IP ranges
INTERNAL_IP_RANGES = []

# Function to set internal IP ranges
def set_internal_ip_ranges(internal_ip_ranges):
    global INTERNAL_IP_RANGES
    INTERNAL_IP_RANGES = [ipaddress.IPv4Network(range) for range in internal_ip_ranges.split(',')]
    print(f"Internal IP Ranges set to: {INTERNAL_IP_RANGES}")

# Continuous monitoring function to check packets per second
def continuous_monitoring():
    global previous_packet_count, previous_time
    while True:
        time.sleep(CONTINUOUS_MONITOR_INTERVAL)
        current_time = datetime.now()
        total_packets = sum(ip_packet_count.values())

        if previous_time is not None:
            packets_per_second = (total_packets - previous_packet_count) / CONTINUOUS_MONITOR_INTERVAL
            print(f"{current_time}: Current packets per second: {packets_per_second}")

        previous_packet_count = total_packets
        previous_time = current_time

# Function to detect DDoS attacks and take mitigation actions
def detect_ddos(src_ip):
    packet_count = ip_packet_count.get(src_ip, 0)
    current_time = datetime.now()

    if packet_count > THRESHOLD_PACKETS_PER_SECOND:
        log_attack(src_ip, packet_count)
        if is_malicious_ip(src_ip):
            block_ip(src_ip)
            mitigate_attack(src_ip)
        else:
            rate_limit_traffic(src_ip)
            divert_traffic_to_sinkhole(src_ip)
            change_routes(src_ip)

    if (current_time - ip_packet_count.get(src_ip+"_time", current_time)).seconds > THRESHOLD_TIME_INTERVAL:
        ip_packet_count[src_ip] = 0
        ip_packet_count[src_ip+"_time"] = current_time

# Function to check if IP address is within internal network ranges
def is_internal_network(ip_address):
    ip = ipaddress.IPv4Address(ip_address)
    for internal_range in INTERNAL_IP_RANGES:
        if ip in internal_range:
            return True
    return False

# Function to check if IP address is malicious using a reputation service
def is_malicious_ip(ip_address):
    try:
        if reputation_service_url.startswith("https://"):
            response = requests.get(reputation_service_url, params={'ip': ip_address}, verify=True)
        else:
            response = requests.get(reputation_service_url, params={'ip': ip_address}, verify=False)

        return response.json().get('malicious', False)
    except requests.RequestException as e:
        return False

# Function to block IP address using platform-specific commands
def block_ip(ip_address):
    system_platform = platform.system().lower()

    if system_platform == 'linux':
        # IPtables
        subprocess.run(['iptables', '-A', 'INPUT', '-s', ip_address, '-j', 'DROP'], check=True)
    elif system_platform == 'windows':
        # netsh
        subprocess.run(['netsh', 'advfirewall', 'firewall', 'add', 'rule', 'name="BlockIP"', 'dir=in', 'action=block', f'enable=yes', f'remoteip={ip_address}'], check=True)
    else:
        print(f"Unsupported platform: {system_platform}")

# Function to mitigate DDoS attacks
def mitigate_attack(src_ip):
    print(f"Mitigating DDoS attack from {src_ip}")

# Function to rate limit traffic from source IP
def rate_limit_traffic(src_ip):
    packet_count = ip_packet_count.get(src_ip, 0)
    if packet_count > MAX_PACKETS_ALLOWED:
        traffic_shaping(src_ip)

# Function to apply traffic shaping for rate limiting
def traffic_shaping(src_ip):
    latency_param = latency if latency else LATENCY_DEFAULT
    bandwidth_limit_param = bandwidth_limit if bandwidth_limit else BANDWIDTH_LIMIT_DEFAULT

    try:
        tcconfig.set_bandwidth(interface="eth0", rate=bandwidth_limit_param)
        tcconfig.set_network_emulation(interface="eth0", latency=latency_param)

        print(f"Traffic shaping applied for traffic from {src_ip}")
    except Exception as e:
        print(f"Error applying traffic shaping: {e}")

# Function to divert traffic to sinkhole IP
def divert_traffic_to_sinkhole(src_ip):
    print(f"Diverting traffic from {src_ip} to the sinkhole IP: {sinkhole_ip}")

# Function to change routes for traffic
def change_routes(src_ip):
    print(f"Changing routes for traffic from {src_ip} to the new route IP: {new_route_ip}")

# Function to set sinkhole IP
def set_sinkhole_ip(ip):
    global sinkhole_ip
    sinkhole_ip = ip

# Function to set new route IP
def set_new_route_ip(ip):
    global new_route_ip
    new_route_ip = ip

# Function to set reputation service URL
def set_reputation_service_url(url):
    global reputation_service_url
    reputation_service_url = url

# Function to set threshold values for detecting DDoS attacks
def set_threshold_values(threshold_packets, threshold_time, max_packets):
    global THRESHOLD_PACKETS_PER_SECOND, THRESHOLD_TIME_INTERVAL, MAX_PACKETS_ALLOWED
    THRESHOLD_PACKETS_PER_SECOND = threshold_packets
    THRESHOLD_TIME_INTERVAL = threshold_time
    MAX_PACKETS_ALLOWED = max_packets

# Function to set traffic shaping parameters
def set_traffic_shaping_params(latency_param, bandwidth_limit_param):
    global latency, bandwidth_limit
    latency = latency_param
    bandwidth_limit = bandwidth_limit_param

# Function to log DDoS attacks
def log_attack(src_ip, packet_count):
    with open('ddos_log.txt', 'a') as log_file:
        log_file.write(f"{datetime.now()}: DDoS attack detected from {src_ip}. Packets: {packet_count}\n")

# Packet callback function for sniffing packets
def packet_callback(packet):
    if scapy.IP in packet:
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        if scapy.TCP in packet:
            sport = packet[scapy.TCP].sport
            dport = packet[scapy.TCP].dport
        elif scapy.UDP in packet:
            sport = packet[scapy.UDP].sport
            dport = packet[scapy.UDP].dport
            if len(packet[scapy.UDP].payload) > 20:
                pass

        ip_packet_count[src_ip] = ip_packet_count.get(src_ip, 0) + 1
        detect_ddos(src_ip)

if __name__ == "__main__":
    continuous_monitor_thread = threading.Thread(target=continuous_monitoring, daemon=True)
    continuous_monitor_thread.start()

    scapy.sniff(prn=packet_callback, store=0, timeout=60)
