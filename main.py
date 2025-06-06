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