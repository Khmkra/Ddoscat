#!/usr/bin/env python3

import os
import random
import subprocess
import sys
import requests

def install_dependencies():
    print("Updating package list and installing dependencies...")
    os.system("sudo apt update")
    os.system("sudo apt install -y squid python3-pip")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "requests"])

def get_vps_ip():
    ip_url = 'https://ipv4.icanhazip.com'
    response = requests.get(ip_url)
    return response.text.strip()

def configure_squid(num_proxies):
    print("Configuring Squid with common ports...")
    squid_conf_path = "/etc/squid/squid.conf"
    common_ports = [80, 443, 8080, 3128, 1080]  # Common proxy ports
    used_ports = set()

    with open(squid_conf_path, "a") as squid_conf:
        squid_conf.write("\n# Custom proxy ports configuration\n")
        for port in common_ports:
            squid_conf.write(f"http_port {port}\n")
            used_ports.add(port)
        
        for _ in range(num_proxies):
            port = random.randint(1024, 65500)
            squid_conf.write(f"http_port {port}\n")
            used_ports.add(port)
        
        squid_conf.write("\n# Allow access to the new proxy ports\n")
        squid_conf.write("acl localnet src 0.0.0.0/0\n")
        squid_conf.write("http_access allow localnet\n")
        squid_conf.write("http_access deny all\n")

    print("Restarting Squid to apply new configuration...")
    os.system("sudo systemctl restart squid")

    return used_ports

def configure_firewall(ports):
    print("Configuring firewall to allow Squid ports...")
    for port in ports:
        os.system(f"sudo ufw allow {port}/tcp")
    os.system("sudo ufw reload")

def save_proxies_to_file(ports, vps_ip):
    print("Saving proxy list to proxy.txt...")
    with open("proxy.txt", "w") as proxy_file:
        for port in ports:
            proxy_file.write(f"{vps_ip}:{port}\n")

def verify_ports(ports):
    print("Verifying that Squid is listening on the configured ports...")
    for port in ports:
        result = os.system(f"nc -zv 127.0.0.1 {port}")
        if result != 0:
            print(f"Warning: Squid is not listening on port {port}")
        else:
            print(f"Squid is listening on port {port}")

def main():
    num_proxies = 5  # You can increase this to 60000

    install_dependencies()
    
    vps_ip = get_vps_ip()
    print(f"VPS IP: {vps_ip}")

    ports = configure_squid(num_proxies)
    configure_firewall(ports)
    save_proxies_to_file(ports, vps_ip)

    verify_ports(ports)

    print("Proxy configuration completed and saved to proxy.txt")

if __name__ == "__main__":
    main()