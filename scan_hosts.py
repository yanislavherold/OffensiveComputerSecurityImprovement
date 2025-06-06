from scapy.all import arping, conf, get_if_addr, get_if_hwaddr

active_hosts = []

def get_default_interface():
    try:
        iface = conf.route.route("0.0.0.0")[0]
        print(f"[+] Automatically selected interface: {iface}")
        return iface
    except Exception as e:
        print(f"[!] Could not determine default interface: {e}")
        return None
    
def get_own_network_info(interface):
    try:
        ip_address = get_if_addr(interface)
        mac_address = get_if_hwaddr(interface)
        return ip_address, mac_address
    except Exception as e:
        print(f"[!] Error getting network info: {e}")
        return None, None
    
def scan_hosts():
    active_hosts.clear()
    print("[*] Host scanning initiated...")

    iface = get_default_interface()
    if not iface:
        print("[!] Cannot proceed without a valid network interface.")
        return

    host_ip, host_mac = get_own_network_info(iface)
    # print(f"HOST - {host_ip, host_mac}")

    if not host_ip:
        print("[!] Could not retrieve local IP address.")
        return

    subnet = ".".join(host_ip.split(".")[:3]) + ".0/24"
    print(f"[*] Scanning subnet: {subnet} on interface: {iface}")

    try:
        ans, _ = arping(subnet, iface=iface, verbose=False, timeout=2)
        for sent, recv in ans:
            if recv.psrc != host_ip:  # skip our own IP
                active_hosts.append({"ip_addr": recv.psrc, "mac_addr": recv.hwsrc})
        print(f"[+] Scan complete. {len(active_hosts)} active hosts found.")
        for host in active_hosts:
            print(host)
    except Exception as e:
        print(f"[!] ARP scan failed: {e}")