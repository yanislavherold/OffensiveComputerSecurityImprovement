from scapy.all import arping, conf, get_if_addr, get_if_hwaddr, get_if_list

active_hosts = []


def scan_ifaces():
    interfaces = get_if_list()
    print("\033[93m[*] Available network interfaces: \033[0m")
    for iface in interfaces:
        print(" - {}".format(iface))
    return interfaces

def get_own_network_info(interface):
    try:
        ip_address = get_if_addr(interface)
        mac_address = get_if_hwaddr(interface)
        return ip_address, mac_address
    except Exception as e:
        print("\033[31m[!] Error getting network info: \033[0m" + str(e))
        return None, None


def scan_hosts(iface):
    del active_hosts[:]
    print("\033[93m[*] Host scanning initiated...\033[0m")
    
    iface = iface
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
            print("Gateway IP: " + str(gateway_ip))
            print("Gateway MAC: " + str(gateway_mac))
        else:
            print("\033[31m[!] No ARP response from gateway.\033[0m")
            gateway_mac = None
    except Exception as e:
        print("\033[31m[!] Could not retrieve gateway info: \033[0m" + str(e))
        gateway_ip, gateway_mac = None, None

    subnet = ".".join(host_ip.split(".")[:3]) + ".0/24"
    print("\033[93m[*] Scanning subnet " + subnet + " on interface:\033[0m" + iface)

    try:
        ans, _ = arping(subnet, iface=iface, verbose=False, timeout=2)
        for sent, recv in ans:
            ip = recv.psrc
            mac = recv.hwsrc
            if ip != gateway_ip:
                active_hosts.append({"ip_addr": ip, "mac_addr": mac})
        print("\033[92m[+] Scan complete. Active hosts found:\033[0m" + str(len(active_hosts)))

        for host in active_hosts:
            print("IP: " + str(host['ip_addr']) + "| MAC: " + str(host['mac_addr']))
    except Exception as e:
        print("\033[31m[!] ARP scan failed: \033[0m" + str(e))
    
    return active_hosts
