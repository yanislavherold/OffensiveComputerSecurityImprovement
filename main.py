import argparse
import sys
import os
from scan_hosts import scan_hosts


def print_title():
    os.system('cls' if os.name == 'nt' else 'clear') # clears the console when starting

    title = ("""
        ╔══════════════════════════════════════════╗
        ║                  Group 5                 ║
        ║      Default Project - Python + Scapy    ║
        ║       ARP + DNS Spoofing + SSLStrip      ║
        ╚══════════════════════════════════════════╝
            """)

    print(f"\033[92m{title}\033[0m")  # Green title
    
def print_commands():

    commands = """
        Available Commands:
        start         - Start the spoofing process in default mode
        scan          - Scan for available hosts
        silent        - Run in silent mode (minimal network disturbance)
        aggressive    - Run in "all out" mode (maximum disruption/logging)
        stop          - Stop all spoofing and restore network state
        help          - Show this help message
        exit          - Quit the tool
            """

    print(f"\033[94m{commands}\033[0m")  # Blue commands


def handle_command(cmd):
    cmd = cmd.strip().lower()

    if cmd == "start":
        print("[*] Starting spoofing in default mode...")
        # Call your ARP/DNS spoofing function here
    elif cmd == "scan":
        scan_hosts() # Scan available hosts
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
            cmd = input(">> ")
            handle_command(cmd)
        except KeyboardInterrupt:
            print("\n[!] Interrupted. Type 'stop' to clean up or 'exit' to quit.")


if __name__ == '__main__':
    main()





# def banner():
#     print("""
# ╔══════════════════════════════════════════╗
# ║                  Group 5                 ║
# ║      Default Project - Python + Scapy    ║
# ║       ARP + DNS Spoofing + SSLStrip      ║
# ╚══════════════════════════════════════════╝
#     """)

# def parse_args():
#     parser = argparse.ArgumentParser(description="MITM attack tool using ARP/DNS spoofing + SSL stripping")
#     parser.add_argument('--mode', choices=['silent', 'all_out'], default='silent', help='Operation mode')
#     parser.add_argument('--target', help='Target IP (optional in all_out mode)')
#     parser.add_argument('--iface', help='Network interface (e.g., eth0, wlan0)')
#     parser.add_argument('--gateway', help='Gateway IP (default: auto-detect)')
#     parser.add_argument('--dns-map', help='Domain spoofing map file (e.g., domain.com=1.2.3.4)', default=None)
#     return parser.parse_args()

# def load_domain_map(filepath):
#     domain_map = {}
#     if filepath and os.path.isfile(filepath):
#         with open(filepath) as f:
#             for line in f:
#                 if '=' in line:
#                     domain, ip = line.strip().split('=')
#                     domain_map[domain.strip()] = ip.strip()
#     return domain_map



    # args = parse_args()

    # iface = args.iface or get_iface()
    # gateway_ip = args.gateway or get_gateway_ip(iface)
    # domain_map = load_domain_map(args.dns_map)

    # if not iface or not gateway_ip:
    #     print("[!] Could not auto-detect network interface or gateway. Use --iface and --gateway manually.")
    #     sys.exit(1)

    # print(f"[i] Interface: {iface}")
    # print(f"[i] Gateway: {gateway_ip}")
    # print(f"[i] Mode: {args.mode}")

    # enable_ip_forwarding()

    # try:
    #     if args.mode == 'silent':
    #         silent_mode.run(args.target, gateway_ip, iface, domain_map)
    #     elif args.mode == 'all_out':
    #         all_out_mode.run(gateway_ip, iface, domain_map)
    # except KeyboardInterrupt:
    #     print("\n[!] Interrupted by user. Cleaning up...")
    # finally:
    #     disable_ip_forwarding()
    #     arp_spoof.restore_arp(args.target, gateway_ip, iface)
    #     print("[✓] Cleanup complete.")