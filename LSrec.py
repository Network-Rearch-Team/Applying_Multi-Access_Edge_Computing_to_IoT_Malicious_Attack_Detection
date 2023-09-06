from scapy.all import *
import netfilterqueue
import os


def packetParse(packet):

    data = packet.get_payload()
    pkt = IP(data)
    #Detail information
    print(pkt.show())
    #print(pkt[Raw].load.decode())
    if IP in pkt:

        DST_IP = pkt[IP].dst
        SRC_IP = pkt[IP].src

        print(pkt.summary())
        print("src IP:", SRC_IP)
        print("dst IP:", DST_IP)

        payload_data=""
        if Raw in pkt:
            payload_data = pkt[Raw].load.decode('utf-8')
            print("Payload Data:", payload_data)
        else: print("no payload")

        print("=" * 40)

    packet.accept()

# def allowOrNotAllow():
#     if packet == "goodpkt":
#         allow = 1
#     else 
#         allow = 0
#     return pkt

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
