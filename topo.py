from mininet.net import Containernet
from mininet.node import Link
from mininet.cli import CLI
from mininet.link import TCLink

def topology():
    net = Containernet(link=TCLink)

    h1  = net.addHost('h1')
    mec = net.addHost('mec')
    RS  = net.addHost('RS')
    LS  = net.addHost('LS')

    Link(h1, mec)
    Link(mec, RS)
    Link(mec, LS)
    net.build()

    #h1 .cmd("echo 1 > /proc/sys/net/ipv4/ip_forward")
    mec.cmd("echo 1 > /proc/sys/net/ipv4/ip_forward")
    #RS .cmd("echo 1 > /proc/sys/net/ipv4/ip_forward")
    #LS .cmd("echo 1 > /proc/sys/net/ipv4/ip_forward")

    h1 .cmd("ifconfig h1-eth0 0")
    mec.cmd("ifconfig mec-eth0 0")
    mec.cmd("ifconfig mec-eth1 0")
    mec.cmd("ifconfig mec-eth2 0")
    RS .cmd("ifconfig RS-eth0 0")
    LS .cmd("ifconfig LS-eth0 0")


    h1 .cmd("ip address add 192.168.1.1/24   dev h1-eth0")
    mec.cmd("ip address add 192.168.1.254/24 brd + dev mec-eth0")
    mec.cmd("ip address add 11.0.0.254/24 brd + dev mec-eth1")
    mec.cmd("ip address add 10.0.0.254/24 brd + dev mec-eth2")
    RS .cmd("ip address add 11.0.0.3/24      dev RS-eth0")
    LS .cmd("ip address add 10.0.0.3/24      dev LS-eth0")

    h1 .cmd("ifconfig h1-eth0 up")
    mec.cmd("ifconfig mec-eth0 up")
    mec.cmd("ifconfig mec-eth1 up")
    mec.cmd("ifconfig mec-eth2 up")
    RS .cmd("ifconfig RS-eth0 up")
    LS .cmd("ifconfig LS-eth0 up")

    h1 .cmd("ip route add default via 192.168.1.254")
    RS .cmd("ip route add default via 11.0.0.254")
    LS .cmd("ip route add default via 10.0.0.254")

    CLI(net)
    net.stop()

if __name__ == '__main__':
    topology()

