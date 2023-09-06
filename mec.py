import socket
import netfilterqueue
import os
from scapy.all import *
import hashlib

# Forwarding
LS_IP = "10.0.0.3"
RS_IP = "12.0.0.4"

def hashValue(payload_data):

    # hash packet payload
    hash_data = payload_data
    hash_value = hashlib.sha256(hash_data.encode()).hexdigest()

    #(The data should be retrieved from the local server.)
    # check1 = hashlib.sha256("hello".encode()).hexdigest()

    # print("Hash Value:", hash_value)
    return hash_value


def packetParse(payload):

    allow = 0

    data = payload.get_payload()
    pkt = IP(data) 
    print("Receive Packet info:")
    print(pkt.summary())
   

    if IP in pkt and pkt[IP].dst == '12.0.0.4':

        DST_IP = pkt[IP].dst
        SRC_IP = pkt[IP].src
        DST_PORT = pkt[TCP].dport
        print(f"Destination IP:{DST_IP} Destination Port:{DST_PORT}")
        
        # print packet payload

        payload_data=""
        if Raw in pkt:
            payload_data = pkt[Raw].load.decode('utf-8')
            print("Payload Data:", payload_data)

           
            print("Send to LS to Analysis Packet")
            pkt[IP].dst = LS_IP
            payload_dataLS = payload_data + "allow:" + str(allow)
            ip_packet = IP(src=SRC_IP, dst=LS_IP) / TCP(dport=DST_PORT) / Raw(load=payload_dataLS)
            send(ip_packet)

            allow = 1

            if allow == 1:
                print("Send to RS")
                payload_dataRS = payload_data + "allow:" + str(allow) + "\n" +"Meow:Hacker"
                ip_packet = IP(src=SRC_IP, dst=DST_IP) / TCP(dport=DST_PORT) / Raw(load=payload_dataRS)
                send(ip_packet)
            
        print("=" * 40)
        payload.drop()
    else:
        payload.drop()

    # if allow == 1
    #     payload.accept()
    # else 
    #     payload.drop()


def main():

    #  queue 0 configuration (self-Host!!)
    # os.system('iptables -A INPUT -j NFQUEUE --queue-num 0')
    # queue0 = netfilterqueue.NetfilterQueue()
    # queue0.bind(0, packetParse)

    # queue 1 configruation (Forwarding)
    os.system('iptables -I FORWARD -j NFQUEUE --queue-num 1')
    queue1 = netfilterqueue.NetfilterQueue()
    queue1.bind(1, packetParse)

    # try:
    #     queue0.run()  # Main loop for queue 0
    # except KeyboardInterrupt:
    #     queue0.unbind()
    #     os.system('iptables -D INPUT -j NFQUEUE --queue-num 0')

    try:
        queue1.run()  # Main loop for queue 1
    except KeyboardInterrupt:
        queue1.unbind()
        os.system('iptables -D FORWARD -j NFQUEUE --queue-num 1')

if __name__ == "__main__":
    main()

