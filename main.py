import os
import shlex
from scan import scan_hosts, scan_ifaces
from arp_spoofing import start_arp_poison
from dns_spoofing import start_dns_poison
import scapy.all as sc



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
		#Basic dns poison
        start_dns_poison(cmd)
    elif cmd.startswith("sslstrip"):
		#Basic arp poison
        sslstrip.start_iptables_redirect()
        sslstrip.start_sslstrip()

        start_arp_thread(cmd)
        start_arp_thread(cmd)
    elif cmd == "silent":
        print("[*] Starting in silent mode (stealthy ARP poisoning)...")
        # Start spoofing in silent mode
    elif cmd == "aggressive":
        print("[!] Starting in aggressive mode (heavy traffic injection)...")
        # Start spoofing with aggressive settings
    elif cmd == "stop":
        print("[*] Stopping attacks...")
        # Stop attacks 
    elif cmd == "help":
        print_commands()
    elif cmd == "exit":
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
