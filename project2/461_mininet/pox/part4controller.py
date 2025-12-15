from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.arp import arp
from pox.lib.packet.ipv4 import ipv4

log = core.getLogger()

Ips = {
    "h10": "10.0.1.10",
    "h20": "10.0.2.20",
    "h30": "10.0.3.30",
    "serv1": "10.0.4.10",
    "hnotrust": "172.16.10.100",
}

class Part4Controller(object):
    def __init__(self, connection):
        self.connection = connection
        connection.addListeners(self)

        self.arpCache = {}
        self.pendingPackets = {}

        self.gatewayIps = {
            1: IPAddr("10.0.1.1"),
            2: IPAddr("10.0.2.1"),
            3: IPAddr("10.0.3.1"),
            4: IPAddr("10.0.4.1"),
            5: IPAddr("172.16.10.1"),
        }

        self.gatewayMacs = {
            1: EthAddr("02:aa:00:00:01:01"),
            2: EthAddr("02:aa:00:00:02:01"),
            3: EthAddr("02:aa:00:00:03:01"),
            4: EthAddr("02:aa:00:00:04:01"),
            5: EthAddr("02:aa:00:00:10:01"),
        }

        self.isCore = connection.dpid in {1, 2, 3, 21, 31} and connection.dpid == 21
        if not self.isCore:
            if connection.dpid in {1, 2, 3, 31}:
                self.setupFlood()
            else:
                self.setupFlood()
        else:
            self.setupCore()

    def setupFlood(self):
        msg = of.ofp_flow_mod()
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        self.connection.send(msg)

    def setupCore(self):
        self.installDrop(Ips["hnotrust"], Ips["serv1"], None)
        for h in ["h10", "h20", "h30", "serv1"]:
            self.installDrop(Ips["hnotrust"], Ips[h], 1)

        self.sendToController(0x0806, 200)
        self.sendToController(0x0800, 10)

        msg = of.ofp_flow_mod()
        msg.priority = 1
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        self.connection.send(msg)

    def sendToController(self, ethType, priority):
        match = of.ofp_match(dl_type=ethType)
        msg = of.ofp_flow_mod(priority=priority, match=match)
        msg.actions.append(of.ofp_action_output(port=of.OFPP_CONTROLLER))
        self.connection.send(msg)

    def installDrop(self, src, dst, proto):
        match = of.ofp_match(dl_type=0x0800, nw_src=IPAddr(src), nw_dst=IPAddr(dst))
        if proto is not None:
            match.nw_proto = proto
        self.connection.send(of.ofp_flow_mod(match=match, priority=300))

    def addFlow(self, match, actions):
        msg = of.ofp_flow_mod(match=match, priority=50, idle_timeout=30)
        for a in actions:
            msg.actions.append(a)
        self.connection.send(msg)

    def getPortForIp(self, ip):
        s = str(ip)
        if s.startswith("10.0.1."):
            return 1
        if s.startswith("10.0.2."):
            return 2
        if s.startswith("10.0.3."):
            return 3
        if s.startswith("10.0.4."):
            return 4
        if s.startswith("172.16.10."):
            return 5
        return None

    def sendPacket(self, data, port):
        msg = of.ofp_packet_out()
        msg.data = data
        msg.actions.append(of.ofp_action_output(port=port))
        self.connection.send(msg)

    def buildArp(self, opcode, hwsrc, hwdst, protosrc, protodst):
        a = arp()
        a.hwtype = arp.HW_TYPE_ETHERNET
        a.prototype = arp.PROTO_TYPE_IP
        a.hwlen = 6
        a.protolen = 4
        a.opcode = opcode
        a.hwsrc = hwsrc
        a.hwdst = hwdst
        a.protosrc = protosrc
        a.protodst = protodst
        return a

    def sendArpRequest(self, targetIp, port):
        a = self.buildArp(
            arp.REQUEST,
            self.gatewayMacs[port],
            EthAddr("00:00:00:00:00:00"),
            self.gatewayIps[port],
            IPAddr(str(targetIp)),
        )
        e = ethernet()
        e.type = ethernet.ARP_TYPE
        e.src = self.gatewayMacs[port]
        e.dst = EthAddr("ff:ff:ff:ff:ff:ff")
        e.payload = a
        self.sendPacket(e.pack(), port)

    def sendArpReply(self, pkt, outPort, replyMac, replyIp):
        req = pkt.payload
        a = self.buildArp(
            arp.REPLY,
            replyMac,
            req.hwsrc,
            replyIp,
            req.protosrc,
        )
        e = ethernet()
        e.type = ethernet.ARP_TYPE
        e.src = replyMac
        e.dst = req.hwsrc
        e.payload = a
        self.sendPacket(e.pack(), outPort)

    def isBlocked(self, ipPkt):
        src = IPAddr(ipPkt.srcip)
        dst = IPAddr(ipPkt.dstip)
        if src == IPAddr(Ips["hnotrust"]) and dst == IPAddr(Ips["serv1"]):
            return True
        if src == IPAddr(Ips["hnotrust"]) and ipPkt.protocol == ipv4.ICMP_PROTOCOL:
            if dst in {IPAddr(Ips["h10"]), IPAddr(Ips["h20"]), IPAddr(Ips["h30"]), IPAddr(Ips["serv1"])}:
                return True
        return False

    def forwardIp(self, packetData, ipPkt):
        dstIp = IPAddr(ipPkt.dstip)
        outPort = self.getPortForIp(dstIp)
        if outPort is None:
            return

        if dstIp not in self.arpCache:
            self.pendingPackets.setdefault(dstIp, []).append(packetData)
            self.sendArpRequest(dstIp, outPort)
            return

        dstMac, _ = self.arpCache[dstIp]
        srcMac = self.gatewayMacs[outPort]

        match = of.ofp_match(dl_type=0x0800, nw_src=IPAddr(ipPkt.srcip), nw_dst=dstIp)
        actions = [
            of.ofp_action_dl_addr.set_src(srcMac),
            of.ofp_action_dl_addr.set_dst(dstMac),
            of.ofp_action_output(port=outPort),
        ]
        self.addFlow(match, actions)

        msg = of.ofp_packet_out()
        msg.data = packetData
        for a in actions:
            msg.actions.append(a)
        self.connection.send(msg)

    def _handle_PacketIn(self, event):
        pkt = event.parsed
        if not pkt.parsed:
            return

        if not self.isCore:
            return

        inPort = event.ofp.in_port

        if pkt.type == ethernet.ARP_TYPE:
            a = pkt.payload
            if a.protosrc is not None and a.hwsrc is not None:
                self.arpCache[IPAddr(a.protosrc)] = (EthAddr(a.hwsrc), inPort)

            if a.opcode == arp.REQUEST:
                targetIp = IPAddr(a.protodst)
                for p, gwIp in self.gatewayIps.items():
                    if targetIp == gwIp:
                        self.sendArpReply(pkt, inPort, self.gatewayMacs[p], gwIp)
                        return

            if a.opcode == arp.REPLY:
                srcIp = IPAddr(a.protosrc)
                if srcIp in self.pendingPackets:
                    queued = self.pendingPackets.pop(srcIp)
                    for data in queued:
                        eth = ethernet(data)
                        if eth.type == ethernet.IP_TYPE and isinstance(eth.payload, ipv4):
                            self.forwardIp(data, eth.payload)
            return

        if pkt.type == ethernet.IP_TYPE and isinstance(pkt.payload, ipv4):
            ipPkt = pkt.payload
            self.arpCache[IPAddr(ipPkt.srcip)] = (EthAddr(pkt.src), inPort)
            if not self.isBlocked(ipPkt):
                self.forwardIp(event.ofp.data, ipPkt)

def launch():
    core.openflow.addListenerByName("ConnectionUp", lambda e: Part4Controller(e.connection))
