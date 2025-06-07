from scapy.all import arping, conf, get_if_addr, get_if_hwaddr

active_hosts = []

def get_default_interface():
    try:
        iface = conf.route.route("0.0.0.0")[0]
        print(f"\033[93m[+] Automatically selected interface: {iface}\033[0m")
        return iface
    except Exception as e:
        print(f"\033[31m[!] Could not determine default interface: {e}\033[0m")
        return None

def get_own_network_info(interface):
    try:
        ip_address = get_if_addr(interface)
        mac_address = get_if_hwaddr(interface)
        return ip_address, mac_address
    except Exception as e:
        print(f"\033[31m[!] Error getting network info: {e}\033[0m")
        return None, None


def scan_hosts():
    active_hosts.clear()
    print("\033[93m[*] Host scanning initiated...\033[0m")
    
    iface = get_default_interface()
    if not iface:
        print("\033[31m[!] Cannot proceed without a valid network interface.\033[0m")
        return

    host_ip, host_mac = get_own_network_info(iface)
    if not host_ip:
        print("\033[31m[!] Could not retrieve local IP address.\033[0m")
        return

    try:
        _, _, gateway_ip = conf.route.route("0.0.0.0")
        gw_ans, _ = arping(gateway_ip, iface=iface, timeout=2, verbose=False)
        if gw_ans:
            gateway_mac = gw_ans[0][1].hwsrc
            print("\n\033[96m[ Gateway Information ]\033[0m")
            print(f"Gateway IP:  {gateway_ip}")
            print(f"Gateway MAC: {gateway_mac}\n")
        else:
            print("\033[31m[!] No ARP response from gateway.\033[0m")
            gateway_mac = None
    except Exception as e:
        print(f"\033[31m[!] Could not retrieve gateway info: {e}\033[0m")
        gateway_ip, gateway_mac = None, None

    subnet = ".".join(host_ip.split(".")[:3]) + ".0/24"
    print(f"\033[93m[*] Scanning subnet: {subnet} on interface: {iface}\033[0m")

    try:
        ans, _ = arping(subnet, iface=iface, verbose=False, timeout=2)
        for sent, recv in ans:
            ip = recv.psrc
            mac = recv.hwsrc
            if ip != host_ip and ip != gateway_ip:
                active_hosts.append({"ip_addr": ip, "mac_addr": mac})
        print(f"\033[92m[+] Scan complete. {len(active_hosts)} active hosts found.\033[0m\n")

        for host in active_hosts:
            print(f"IP: {host['ip_addr']} | MAC: {host['mac_addr']}")
    except Exception as e:
        print(f"\033[31m[!] ARP scan failed: {e}\033[0m")