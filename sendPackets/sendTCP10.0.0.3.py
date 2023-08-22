from scapy.all import *

src_ip = "192.168.1.1"
dst_ip = "10.0.0.3"
dst_port = 80 

payload_message = "GET / HTTP/1.1\r\nHost: meowhecker.com\r\n\r\n"

ip_packet = IP(src=src_ip, dst=dst_ip) / TCP(sport=RandShort(), dport=dst_port, flags="S") / Raw(load=payload_message)

send(ip_packet)

