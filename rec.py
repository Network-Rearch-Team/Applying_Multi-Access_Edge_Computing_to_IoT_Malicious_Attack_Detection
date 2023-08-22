import socket
import netfilterqueue
import os
from scapy.all import IP, Raw 
import hashlib

LS_IP = "10.0.0.3"
RS_IP = "11.0.0.3"


def packetParse(payload):
    data = payload.get_payload()
    pkt = IP(data)

    if IP in pkt:
        DST_IP = pkt[IP].dst
        SRC_IP = pkt[IP].src

        # if SRC_IP == LS_IP or SRC_IP == RS_IP:

        print(pkt.summary())
        print("src IP:", SRC_IP)
        print("dst IP:", DST_IP)

        payload_data=""
        if Raw in pkt:
            payload_data = pkt[Raw].load.decode('utf-8')
            print("Payload Data:", payload_data)
        else: print("no payload")

        print("=" * 40)

    payload.accept()

def main():
    os.system('iptables -A INPUT -j NFQUEUE --queue-num 0')

    queue = netfilterqueue.NetfilterQueue()
    queue.bind(0, packetParse)

    try:
        queue.run()  # Main loop
    except KeyboardInterrupt:
        queue.unbind()  # server to server concat
        # Rule delete
        os.system('iptables -D INPUT -j NFQUEUE --queue-num 0')

if __name__ == "__main__":
    main()
