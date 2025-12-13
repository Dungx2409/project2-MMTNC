# Part 4 of UWCSE's Mininet-SDN project
#
# SDN router on the core switch (dpid=21):
# - replies to ARP for gateway IPs
# - learns IP->(MAC,port)
# - routes IP packets between subnets by rewriting L2 headers
# - enforces firewall policy for hnotrust1

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.arp import arp
from pox.lib.packet.ipv4 import ipv4

log = core.getLogger()

IPS = {
    "h10": "10.0.1.10",
    "h20": "10.0.2.20",
    "h30": "10.0.3.30",
    "serv1": "10.0.4.10",
    "hnotrust": "172.16.10.100",
}

SUBNETS = {
    "h10": "10.0.1.0/24",
    "h20": "10.0.2.0/24",
    "h30": "10.0.3.0/24",
    "serv1": "10.0.4.0/24",
    "hnotrust": "172.16.10.0/24",
}


class Part4Controller(object):
    def __init__(self, connection):
        print(connection.dpid)
        self.connection = connection
        connection.addListeners(self)

        # ARP cache learned at the core: IP -> (MAC, core_port)
        # We'll learn from ARP and also from IP src fields.
        self.arp_cache = {}

        # Pending packets waiting on ARP resolution:
        # dst_ip -> list of (packet_in_bytes, in_port)
        self.pending = {}

        # Core port layout based on your topo addLink order:
        # cores21 links: s1,s2,s3,dcs31,hnotrust1 (in that order)
        self.CORE_PORTS = {
            "to_s1": 1,
            "to_s2": 2,
            "to_s3": 3,
            "to_dcs31": 4,
            "to_hnotrust": 5,
        }

        # Router/gateway IPs for each subnet
        self.GW_IP_BY_PORT = {
            1: IPAddr("10.0.1.1"),
            2: IPAddr("10.0.2.1"),
            3: IPAddr("10.0.3.1"),
            4: IPAddr("10.0.4.1"),
            5: IPAddr("172.16.10.1"),
        }

        # Router MAC per "interface" (per core egress port)
        self.GW_MAC_BY_PORT = {
            1: EthAddr("02:aa:00:00:01:01"),
            2: EthAddr("02:aa:00:00:02:01"),
            3: EthAddr("02:aa:00:00:03:01"),
            4: EthAddr("02:aa:00:00:04:01"),
            5: EthAddr("02:aa:00:00:10:01"),
        }

        # Setup per switch
        if connection.dpid == 1:
            self.s_flood_setup()
        elif connection.dpid == 2:
            self.s_flood_setup()
        elif connection.dpid == 3:
            self.s_flood_setup()
        elif connection.dpid == 31:
            self.s_flood_setup()
        elif connection.dpid == 21:
            self.cores21_setup()
        else:
            print("UNKNOWN SWITCH")
            exit(1)

    # --- Helpers -------------------------------------------------------------

    def add_flow(self, match, actions, priority=10, idle_timeout=30, hard_timeout=0):
        msg = of.ofp_flow_mod()
        msg.match = match
        msg.priority = priority
        msg.idle_timeout = idle_timeout
        msg.hard_timeout = hard_timeout
        for a in actions:
            msg.actions.append(a)
        self.connection.send(msg)

    def drop_flow(self, match, priority=200):
        msg = of.ofp_flow_mod()
        msg.match = match
        msg.priority = priority
        # No actions => drop
        self.connection.send(msg)

    def flood_rule(self):
        msg = of.ofp_flow_mod()
        msg.priority = 1
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        self.connection.send(msg)

    def resend_packet(self, packet_in, out_port):
        msg = of.ofp_packet_out()
        msg.data = packet_in
        msg.actions.append(of.ofp_action_output(port=out_port))
        self.connection.send(msg)

    def _ip_to_core_port(self, ip):
        ip = IPAddr(str(ip))
        s = str(ip)
        if s.startswith("10.0.1."):
            return self.CORE_PORTS["to_s1"]
        if s.startswith("10.0.2."):
            return self.CORE_PORTS["to_s2"]
        if s.startswith("10.0.3."):
            return self.CORE_PORTS["to_s3"]
        if s.startswith("10.0.4."):
            return self.CORE_PORTS["to_dcs31"]
        if s.startswith("172.16.10."):
            return self.CORE_PORTS["to_hnotrust"]
        return None

    def _is_firewall_blocked(self, ip_pkt):
        """
        Policy:
        - drop any IP from hnotrust -> serv1
        - drop ICMP from hnotrust -> any internal host (h10,h20,h30,serv1)
        """
        src = IPAddr(ip_pkt.srcip)
        dst = IPAddr(ip_pkt.dstip)

        hnotrust_ip = IPAddr(IPS["hnotrust"])
        serv1_ip = IPAddr(IPS["serv1"])

        # Block hnotrust -> serv1 for all IP
        if src == hnotrust_ip and dst == serv1_ip:
            return True

        # Block ICMP from hnotrust to internal hosts (including serv1)
        if src == hnotrust_ip and ip_pkt.protocol == ipv4.ICMP_PROTOCOL:
            internal = {
                IPAddr(IPS["h10"]),
                IPAddr(IPS["h20"]),
                IPAddr(IPS["h30"]),
                IPAddr(IPS["serv1"]),
            }
            if dst in internal:
                return True

        return False

    def _send_arp_request(self, target_ip, out_port):
        """
        Send ARP request for target_ip out out_port using the router interface MAC/IP on that port.
        """
        gw_ip = self.GW_IP_BY_PORT[out_port]
        gw_mac = self.GW_MAC_BY_PORT[out_port]

        a = arp()
        a.hwtype = arp.HW_TYPE_ETHERNET
        a.prototype = arp.PROTO_TYPE_IP
        a.hwlen = 6
        a.protolen = 4
        a.opcode = arp.REQUEST
        a.hwdst = EthAddr("00:00:00:00:00:00")
        a.protodst = IPAddr(str(target_ip))
        a.hwsrc = gw_mac
        a.protosrc = gw_ip

        e = ethernet()
        e.type = ethernet.ARP_TYPE
        e.src = gw_mac
        e.dst = EthAddr("ff:ff:ff:ff:ff:ff")
        e.payload = a

        msg = of.ofp_packet_out()
        msg.data = e.pack()
        msg.actions.append(of.ofp_action_output(port=out_port))
        self.connection.send(msg)

    def _send_arp_reply(self, request_eth, in_port, reply_mac, reply_ip):
        """
        Reply to an ARP request (request_eth is ethernet containing ARP).
        """
        req = request_eth.payload  # arp

        a = arp()
        a.hwtype = req.hwtype
        a.prototype = req.prototype
        a.hwlen = req.hwlen
        a.protolen = req.protolen
        a.opcode = arp.REPLY
        a.hwsrc = reply_mac
        a.hwdst = req.hwsrc
        a.protosrc = reply_ip
        a.protodst = req.protosrc

        e = ethernet()
        e.type = ethernet.ARP_TYPE
        e.src = reply_mac
        e.dst = req.hwsrc
        e.payload = a

        msg = of.ofp_packet_out()
        msg.data = e.pack()
        msg.actions.append(of.ofp_action_output(port=in_port))
        self.connection.send(msg)

    def _forward_ip_packet(self, packet_in_bytes, ip_pkt, in_port):
        """
        Route IP packet by rewriting L2 and outputting on correct port.
        Installs a flow for (nw_src,nw_dst) to speed future packets.
        """
        dst_ip = IPAddr(ip_pkt.dstip)
        out_port = self._ip_to_core_port(dst_ip)
        if out_port is None:
            return

        # Need destination MAC learned
        entry = self.arp_cache.get(dst_ip)
        if entry is None:
            # Start ARP resolution and queue this packet
            self.pending.setdefault(dst_ip, []).append((packet_in_bytes, in_port))
            self._send_arp_request(dst_ip, out_port)
            return

        dst_mac, _ = entry
        src_mac = self.GW_MAC_BY_PORT[out_port]

        # Install flow: match IP src/dst, set dl_src/dl_dst, output
        match = of.ofp_match()
        match.dl_type = 0x0800
        match.nw_src = IPAddr(ip_pkt.srcip)
        match.nw_dst = dst_ip

        actions = [
            of.ofp_action_dl_addr.set_src(src_mac),
            of.ofp_action_dl_addr.set_dst(dst_mac),
            of.ofp_action_output(port=out_port),
        ]
        self.add_flow(match, actions, priority=50, idle_timeout=30)

        # Send this packet now
        po = of.ofp_packet_out()
        po.data = packet_in_bytes
        po.actions = actions
        self.connection.send(po)

    # --- Switch setups -------------------------------------------------------

    def s_flood_setup(self):
        # For s1/s2/s3/dcs31: simplest fabric — flood everything (tree topology => no loops).
        self.flood_rule()

    def cores21_setup(self):
        # Firewall drops (high priority) done as switch rules too.

        # Drop IP traffic from hnotrust -> serv1
        m = of.ofp_match()
        m.dl_type = 0x0800
        m.nw_src = IPAddr(IPS["hnotrust"])
        m.nw_dst = IPAddr(IPS["serv1"])
        self.drop_flow(m, priority=300)

        # Drop ICMP from hnotrust -> internal hosts (including serv1)
        internal = ["h10", "h20", "h30", "serv1"]
        for h in internal:
            m2 = of.ofp_match()
            m2.dl_type = 0x0800
            m2.nw_proto = 1  # ICMP
            m2.nw_src = IPAddr(IPS["hnotrust"])
            m2.nw_dst = IPAddr(IPS[h])
            self.drop_flow(m2, priority=300)

        # Send ARP to controller (so we can reply for gateway IPs and learn)
        m_arp = of.ofp_match()
        m_arp.dl_type = 0x0806
        self.add_flow(
            m_arp,
            [of.ofp_action_output(port=of.OFPP_CONTROLLER)],
            priority=200,
            idle_timeout=0,
        )

        # Send IP to controller (routing decisions + install flows)
        m_ip = of.ofp_match()
        m_ip.dl_type = 0x0800
        self.add_flow(
            m_ip,
            [of.ofp_action_output(port=of.OFPP_CONTROLLER)],
            priority=10,
            idle_timeout=0,
        )

        # Anything else: flood (safe here)
        self.flood_rule()

    # --- PacketIn handler ----------------------------------------------------

    def _handle_PacketIn(self, event):
        packet = event.parsed
        if not packet.parsed:
            log.warning("Ignoring incomplete packet")
            return

        dpid = event.connection.dpid
        packet_in = event.ofp
        in_port = packet_in.in_port

        # We only do routing logic on the core
        if dpid != 21:
            return

        # --- ARP handling ---
        if packet.type == ethernet.ARP_TYPE:
            a = packet.payload

            # learn sender mapping
            if a.protosrc is not None and a.hwsrc is not None:
                self.arp_cache[IPAddr(a.protosrc)] = (EthAddr(a.hwsrc), in_port)

            # If ARP request is for our gateway IP on this segment, reply
            if a.opcode == arp.REQUEST:
                target_ip = IPAddr(a.protodst)

                # Determine which interface should own this target_ip
                reply_port = None
                for p, gw_ip in self.GW_IP_BY_PORT.items():
                    if target_ip == gw_ip:
                        reply_port = p
                        break

                if reply_port is not None:
                    self._send_arp_reply(
                        request_eth=packet,
                        in_port=in_port,
                        reply_mac=self.GW_MAC_BY_PORT[reply_port],
                        reply_ip=self.GW_IP_BY_PORT[reply_port],
                    )
                    return

            # If ARP reply, we may be able to flush pending packets
            if a.opcode == arp.REPLY:
                src_ip = IPAddr(a.protosrc)
                self.arp_cache[src_ip] = (EthAddr(a.hwsrc), in_port)

                if src_ip in self.pending:
                    queued = self.pending.pop(src_ip)
                    for (pbytes, p_in_port) in queued:
                        # Re-parse to get IP fields
                        eth = ethernet(pbytes)
                        if eth.type == ethernet.IP_TYPE and isinstance(eth.payload, ipv4):
                            self._forward_ip_packet(pbytes, eth.payload, p_in_port)
            return

        # --- IP handling (routing) ---
        if packet.type == ethernet.IP_TYPE and isinstance(packet.payload, ipv4):
            ip_pkt = packet.payload

            # learn source mapping (best effort)
            self.arp_cache[IPAddr(ip_pkt.srcip)] = (EthAddr(packet.src), in_port)

            # firewall policy (controller-side too, in case)
            if self._is_firewall_blocked(ip_pkt):
                return

            # Route it
            self._forward_ip_packet(packet_in.data, ip_pkt, in_port)
            return

        # Otherwise ignore
        return


def launch():
    def start_switch(event):
        log.debug("Controlling %s" % (event.connection,))
        Part4Controller(event.connection)

    core.openflow.addListenerByName("ConnectionUp", start_switch)
