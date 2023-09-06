from mininet.net import Containernet
from mininet.node import Link
from mininet.cli import CLI
from mininet.link import TCLink

#h1 ping 不到 RS(docker)
def topology():
    net = Containernet(link=TCLink)

    h1  = net.addHost('h1')
    mec = net.addHost('mec')
    LS  = net.addHost('LS')
    h2  = net.addHost('h2')
    RS = net.addDocker("RS",ip='12.0.0.4/24' ,dimage="smallko/php-apache-dev:v10")

    Link(mec, h1)
    Link(mec, h2)
    Link(mec, LS)
    Link(h2 , RS)

    net.start()

    mec.cmd("echo 1 > /proc/sys/net/ipv4/ip_forward")
    h2. cmd("echo 1 > /proc/sys/net/ipv4/ip_forward")


    h1 .cmd("ifconfig h1-eth0 0")
    mec.cmd("ifconfig mec-eth0 0")
    mec.cmd("ifconfig mec-eth1 0")
    mec.cmd("ifconfig mec-eth2 0")
    h2 .cmd("ifconfig h2-eth0 0")
    h2 .cmd("ifconfig h2-eth1 0")
    LS .cmd("ifconfig LS-eth0 0")
    #RS .cmd("ifconfig RS-eth0 0")
    
    h1 .cmd("ip address add 192.168.1.1/24         dev h1-eth0")
    mec.cmd("ip address add 192.168.1.254/24 brd + dev mec-eth0")
    mec.cmd("ip address add 11.0.0.254/24    brd + dev mec-eth1")
    mec.cmd("ip address add 10.0.0.254/24    brd + dev mec-eth2")
    h2 .cmd("ip address add 11.0.0.253/24    brd + dev h2-eth0")
    h2 .cmd("ip address add 12.0.0.254/24    brd + dev h2-eth1")
    LS .cmd("ip address add 10.0.0.3/24            dev LS-eth0")
    #RS .cmd("ip address add 12.0.0.4/24            dev RS-eth0")

    h1 .cmd("ifconfig h1-eth0 up")
    mec.cmd("ifconfig mec-eth0 up")
    mec.cmd("ifconfig mec-eth1 up")
    mec.cmd("ifconfig mec-eth2 up")
    h2 .cmd("ifconfig h2-eth0 up")
    h2 .cmd("ifconfig h2-eth1 up")
    LS .cmd("ifconfig LS-eth0 up")
    #RS .cmd("ifconfig RS-eth0 up")


    #Static Routing
    #h1<--->RS
    mec.cmd("ip route add 12.0.0.0/24 via 11.0.0.253")
    h2.cmd("ip route add 192.168.1.0/24 via 11.0.0.254")
    
    #LS<--->RS
    h2.cmd("ip route add 10.0.0.0/24 via 11.0.0.254")

    
    h1 .cmd("ip route add default via 192.168.1.254")
    LS .cmd("ip route add default via 10.0.0.254")
    #RS .cmd("ip route add default via 12.0.0.254")


    #RS http Server Start
    #RS.cmd("/etc/init.d/apache2 start")

    CLI(net)
    net.stop()

if __name__ == '__main__':
    topology()
