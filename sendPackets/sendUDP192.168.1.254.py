from scapy.all import IP, UDP, Raw, send

src_ip = "192.168.1.1"
dst_ip = "192.168.1.254"

payload_message = "Meowhecker"

ip_packet = IP(src=src_ip, dst=dst_ip) / UDP() / Raw(load=payload_message)

send(ip_packet)

