import socket

HOST = '10.0.0.254'
PORT = 4444
malDeviceIP = "1.1.1.1"
def block(malDeviceIP):

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((HOST, PORT))
    malDev = malDeviceIP.encode()
    client.send(malDev)
    response = client.recv(4096)
    print(response.decode('utf-8'))
    client.close()
    print(f'block:{malDeviceIP}')

block(malDeviceIP)