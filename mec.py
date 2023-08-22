import socket
import netfilterqueue
import os
from scapy.all import IP, Raw, UDP, send
import hashlib

LS_IP = "10.0.0.3"
RS_IP = "11.0.0.3"


def packetParse(payload):
    data = payload.get_payload()
    pkt = IP(data)

    

    if IP in pkt:
        DST_IP = pkt[IP].dst
        SRC_IP = pkt[IP].src

        print("Destination IP:", DST_IP)
        
        # print packet payload
        payload_data=""
        if Raw in pkt:
            payload_data = pkt[Raw].load.decode('utf-8')
            print("Payload Data:", payload_data)

        # hash packet payload
        hash_data = payload_data
        hash_value = hashlib.sha256(hash_data.encode()).hexdigest()

        #(The data should be retrieved from the local server.)
        check1 = hashlib.sha256("hello".encode()).hexdigest()
        
        # print("Hash Value:", hash_value)
        if hash_value == check1:

            # 這裡應該要Send to LS 
            print("There is data on the local server.")
            ip_packet = IP(src=SRC_IP, dst=LS_IP) / UDP() / Raw(load=payload_data)
            send(ip_packet)
        else:

            print("There is no data on the local server.")
            ip_packet = IP(src=SRC_IP, dst=RS_IP) / UDP() / Raw(load=payload_data)
            send(ip_packet)
        
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

