#!/usr/bin/python

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.util import dumpNodeConnections
from mininet.cli import CLI


class part1_topo(Topo):
    def build(self):
        pass
        # switch1 = self.addSwitch('switchname')
        # host1 = self.addHost('hostname')
        # self.addLink(hostname,switchname)
        # 1. Khai báo Switch
        # Yêu cầu: 1 switch tên là 's1'
        s1 = self.addSwitch('s1', failMode='standalone')

        # 2. Khai báo Hosts
        # Yêu cầu: 4 host tên h1, h2, h3, h4
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')
        h3 = self.addHost('h3')
        h4 = self.addHost('h4')

        # 3. Tạo liên kết (Links)
        # Yêu cầu: Nối tất cả các host vào switch s1
        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(h3, s1)
        self.addLink(h4, s1)


topos = {"part1": part1_topo}

if __name__ == "__main__":
    t = part1_topo()
    net = Mininet(topo=t, controller=None)
    net.start()
    print("--- Dumping host connections ---")
    dumpNodeConnections(net.hosts)
    print("--- Testing network connectivity ---")
    CLI(net)
    net.stop()
