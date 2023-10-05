import socket
import netfilterqueue
import os
from scapy.all import *
import hashlib
import socket
import threading


hostIP = '10.0.0.254'
hostPORT = 4444

# Forwarding
LS_IP = "10.0.0.3"
RS_IP = "12.0.0.4"

def serverExeSystemCmd():

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((hostIP, hostPORT))
    server.listen(5)
    print(f'[*] Listening on {hostIP}:{hostPORT}')

    while True:

        client, address = server.accept()
        print(f'[*] Accepted connection from {address[0]}:{address[1]}')
        client_handler = threading.Thread(target=handle_client, args=(client,))
        client_handler.start()

def handle_client(client_socket):
    
    with client_socket as sock:
        request = sock.recv(1024)
        print(f'[*] Received: {request.decode("utf-8")}')
        blockIP = request.decode("utf-8")
       
        addIptableRule(blockIP)
        
        
        sock.send(b'ACK From Mec.py')

def addIptableRule(blockIP):
    #Check the Rule whether exists
    ruleNotExists = subprocess.call(["iptables", "-C", "INPUT", "-s", blockIP, "-j", "DROP"])

    if ruleNotExists == 1:
        os.system(f'iptables -t filter -A INPUT -j DROP -s {blockIP}')
        print("Rule Add!!")
    else:
        print("Rule exists!!")
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
   
   
    if IP in pkt:

        DST_IP = pkt[IP].dst
        SRC_IP = pkt[IP].src
        DST_PORT = pkt[TCP].dport
        print(f"Destination IP:{DST_IP} Destination Port:{DST_PORT}")
        
        # print packet payload

        payload_data=""

        print("Send to LS to Analysis Packet")
        #pkt[IP].dst = LS_IP
        ip_packet = IP(src=SRC_IP, dst=LS_IP) / TCP(dport=DST_PORT)


        if Raw in pkt and pkt[IP].dst == '12.0.0.4':

            payload_data = pkt[Raw].load.decode('utf-8')
            print("Payload Data:", payload_data)

           
            print("Send to LS to Analysis Packet")
            payload_dataLS = payload_data + "allow:" + str(allow)
            ip_packet = IP(src=SRC_IP, dst=LS_IP) / TCP(dport=DST_PORT) / Raw(load=payload_dataLS)

            # allow = 1

            # if allow == 1:
            #     print("Send to RS")
            #     payload_dataRS = payload_data + "allow:" + str(allow) + "\n" +"Meow:Hacker"
            #     ip_packet = IP(src=SRC_IP, dst=DST_IP) / TCP(dport=DST_PORT) / Raw(load=payload_dataRS)
            #     send(ip_packet)

            print("Raw")
            send(ip_packet)
            print("=" * 40)
            payload.accept()
        else:
            if pkt[IP].dst == '12.0.0.4':
                print("Send to LS to Analysis Packet")
                send(ip_packet)
                print("=" * 40)
            payload.accept()
      
    else:
        print(1)
    # if allow == 1
    #     payload.accept()
    # else 
    #     payload.drop()


def main():

    try:

        os.system('iptables -I FORWARD -j NFQUEUE --queue-num 1')
        queue1 = netfilterqueue.NetfilterQueue()
        queue1.bind(1, packetParse)

        queue_thread = threading.Thread(target=queue1.run)
        server_thread = threading.Thread(target=serverExeSystemCmd)

        queue_thread.start()
        server_thread.start()

        queue_thread.join()
        server_thread.join()

    except KeyboardInterrupt:
        os.system('iptables -D FORWARD -j NFQUEUE --queue-num 1')
        queue1.unbiexcept

if __name__ == "__main__":
    main()

