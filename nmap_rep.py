from scapy.all import *
import socket
import sys
import threading
import time

def port_scan(host, port):
    #   Single port scan
    response = sr1(IP(dst=host)/TCP(dport=port, flags="S"), timeout = 1, verbose = 0)
    # print(response)
    if response and response.haslayer(TCP) and response[TCP].flags == "SA":
        open_ports.append(port)
    mess = f"Scanning port {port}"
    print("\r" + mess, end="", flush=True)

def SynScan(host, ports):
    global open_ports
    open_ports = []
    threads = []
    for port in ports:
        thread = threading.Thread(target=port_scan, args=(host, port))
        threads.append(thread)
        thread.start()
    #   Wait for all threads to complete
    for thread in threads:
        thread.join()
    open_ports.sort()
    return open_ports

def detect_service_OS(host, port):
    try:
        response = sr1(IP(dst=host)/TCP(dport=port, flags="S"), timeout = 1, verbose = 0)
        # print(f"{port}: {response}")
        if response and response.haslayer(TCP) and response.haslayer(IP):
            tcp_flags = response[TCP].flags
            ttl = response.ttl
            window_size = response[TCP].window
            ip_id = response[IP].id
        #   Service detect
            if tcp_flags == "SA":
                service_name = get_service_name(port)
                print(f"Port {port} is open - Service: {service_name}")
            elif tcp_flags == "RA":
                print(f"Port {port} is closed")
            else:
                print(f"Port {port} is filtered")
        #   OS Detect
            # print(f"{ttl};      {window_size};         {ip_id}")
            if ttl > 128:
                print(f"Detected iOS 12.4 (Cisco Routers) at port {port}")
            elif ttl > 64:
                print(f"Detected Windows OS at port {port}")
            elif ttl <= 64:
                if window_size == 5840:
                    print(f"Detected Linux OS(Kernel 2.4 and 2.6) at port {port}")
                elif window_size == 5720:
                    print(f"Detected Google Linux at port {port}")
                elif window_size == 65535:
                    print(f"Detected FreeBSD or Mac OS X at port {port}")
            else: print(f"Unknown OS at port {port}")
        else:
            print(f"No response received from {host}:{port}")
    except Exception as e:
        print(f"An error occurred: {e}")

def get_service_name(port):
    #   Dictionary mapping common ports to their corresponding services
    service_map = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        443: "HTTPS",
        110: "POP3",
        139: "SMB",
        445: "SMB",
        143: "IMAP",
        67: "DHCP",
        68: "DHCP",
        69: "TFTP",
        161: "SNMP",
        8080: "HTTP-proxy"
        #   Add more ports and services as needed
    }
    return service_map.get(port, "Unknown")

#   Main func
print("Enter ports range")
port_start = int(input("First port: "))
port_end = int(input("Last port: "))
ports = list(range(port_start, port_end+1))  #  [25,80,53,443,445,8080,8443] 
host = socket.gethostbyname(input("Host IP/website: "))
print(f"Host IP: {host}")
start_time = time.time()
open_port = SynScan(host, ports)
print("\n" + "*"*30)
if not open_port:
    print("No open port found!")
else:
    for port in open_port:
        detect_service_OS(host, port)
end_time = time.time()
print("Run time: {}".format(end_time-start_time))