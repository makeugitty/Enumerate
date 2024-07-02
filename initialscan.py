import scapy.all as scapy
import nmap
import json
import os
import subprocess

# Function to scan the network for devices using ARP
def scan_network(ip_range):
    try:
        arp_request = scapy.ARP(pdst=ip_range)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

        devices = []
        for element in answered_list:
            device_info = {'ip': element[1].psrc, 'mac': element[1].hwsrc}
            devices.append(device_info)
        return devices
    except PermissionError as e:
        print("Permission Error: Please run the script as root.")
        exit(1)
    except Exception as e:
        print(f"An error occurred: {e}")
        exit(1)

# Function to run nmap scan with vulnerability scripts
def run_nmap_scan(ip):
    nm = nmap.PortScanner()
    scan_result = nm.scan(ip, arguments='-sV -O --script vuln')
    return scan_result

# Function to check if the device is up using ping
def is_device_up(ip):
    try:
        response = subprocess.run(['ping', '-c', '1', '-W', '1', ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return response.returncode == 0
    except Exception as e:
        print(f"Ping error for {ip}: {e}")
        return False

def main():
    ip_range = "192.168.1.0/24"  # Update this with your network's IP range
    devices = scan_network(ip_range)
    all_scan_results = []

    for device in devices:
        ip = device['ip']
        mac = device['mac']
        if is_device_up(ip):
            print(f"Scanning {ip} ({mac})...")
            scan_result = run_nmap_scan(ip)
            device['scan_result'] = scan_result
            all_scan_results.append(device)
            print(f"Scan complete for {ip}")
        else:
            print(f"Device {ip} is not reachable. Skipping...")

    # Save the results to a JSON file
    with open('network_scan_results.json', 'w') as f:
        json.dump(all_scan_results, f, indent=4)

    print("Network scan complete. Results saved to network_scan_results.json")

if __name__ == "__main__":
    main()
