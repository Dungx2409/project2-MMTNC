# Part 3 of UWCSE's Mininet-SDN project
#
# based on Lab Final from UCSC's Networking Class
# which is based on of_tutorial by James McCauley

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr, IPAddr6, EthAddr

log = core.getLogger()

# Convenience mappings of hostnames to ips
IPS = {
    "h10": "10.0.1.10",
    "h20": "10.0.2.20",
    "h30": "10.0.3.30",
    "serv1": "10.0.4.10",
    "hnotrust": "172.16.10.100",
}

# Convenience mappings of hostnames to subnets
SUBNETS = {
    "h10": "10.0.1.0/24",
    "h20": "10.0.2.0/24",
    "h30": "10.0.3.0/24",
    "serv1": "10.0.4.0/24",
    "hnotrust": "172.16.10.0/24",
}

class Part3Controller(object):
    """
    A Connection object for that switch is passed to the __init__ function.
    """

    def __init__(self, connection):
        print(connection.dpid)
        # Keep track of the connection to the switch so that we can
        # send it messages!
        self.connection = connection

        # This binds our PacketIn event listener
        connection.addListeners(self)
        # use the dpid to figure out what switch is being created
        if connection.dpid == 1:
            self.s1_setup()
        elif connection.dpid == 2:
            self.s2_setup()
        elif connection.dpid == 3:
            self.s3_setup()
        elif connection.dpid == 21:
            self.cores21_setup()
        elif connection.dpid == 31:
            self.dcs31_setup()
        else:
            print("UNKNOWN SWITCH")
            exit(1)

    # --- HELPER FUNCTION: Add Flow ---
    # Hàm hỗ trợ để cài đặt rule nhanh hơn
    def add_flow(self, match, action_port, priority=10):
        msg = of.ofp_flow_mod()
        msg.match = match
        msg.priority = priority
        if action_port is not None:
            msg.actions.append(of.ofp_action_output(port=action_port))
        # Nếu action_port là None, nghĩa là DROP (không thêm action nào)
        self.connection.send(msg)
    
    # --- HELPER FUNCTION: Flood ---
    # Cài đặt switch hoạt động như hub/switch thường (Flood)
    def flood_setup(self):
        msg = of.ofp_flow_mod()
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        self.connection.send(msg)

    def s1_setup(self):
        # Switch s1: Chỉ cần chuyển tiếp mọi thứ (Allowed to flood)
        self.flood_setup()

    def s2_setup(self):
        # Switch s2: Chỉ cần chuyển tiếp mọi thứ (Allowed to flood)
        self.flood_setup()

    def s3_setup(self):
        # Switch s3: Chỉ cần chuyển tiếp mọi thứ (Allowed to flood)
        self.flood_setup()

    def dcs31_setup(self):
        # Switch Datacenter: Chỉ cần chuyển tiếp mọi thứ (Allowed to flood)
        self.flood_setup()

    def cores21_setup(self):
        # --- CORE SWITCH RULES ---
        # Đây là nơi xử lý logic chính
        
        # 1. ALLOW ARP (Quan trọng: Nếu chặn ARP, các máy không tìm thấy MAC của nhau)
        # Cho phép flood ARP qua tất cả các cổng
        match_arp = of.ofp_match()
        match_arp.dl_type = 0x0806 # Ethertype cho ARP
        self.add_flow(match_arp, of.OFPP_FLOOD, priority=100)

        # 2. FIREWALL RULES (Security - Priority cao hơn)
        
        # Rule a: Chặn IP traffic từ hnotrust1 -> serv1
        match_block_ip = of.ofp_match()
        match_block_ip.dl_type = 0x0800 # IP
        match_block_ip.nw_src = IPAddr(IPS["hnotrust"])
        match_block_ip.nw_dst = IPAddr(IPS["serv1"])
        self.add_flow(match_block_ip, None, priority=200) # Action None = Drop

        # Rule b: Chặn ICMP từ hnotrust1 -> Bất kỳ internal host nào
        # ICMP protocol number = 1
        internal_hosts = ["h10", "h20", "h30", "serv1"]
        for host in internal_hosts:
            match_block_icmp = of.ofp_match()
            match_block_icmp.dl_type = 0x0800 # IP
            match_block_icmp.nw_proto = 1     # ICMP
            match_block_icmp.nw_src = IPAddr(IPS["hnotrust"])
            match_block_icmp.nw_dst = IPAddr(IPS[host])
            self.add_flow(match_block_icmp, None, priority=200) # Action None = Drop

        # 3. ROUTING RULES (Forwarding - Priority thấp hơn firewall)
        # Dựa trên thứ tự addLink trong file part3.py để xác định port:
        # s1 -> port 1
        # s2 -> port 2
        # s3 -> port 3
        # dcs31 -> port 4
        # hnotrust1 -> port 5

        # Forward đến h10 (qua s1 - port 1)
        match_h10 = of.ofp_match()
        match_h10.dl_type = 0x0800
        match_h10.nw_dst = IPAddr(IPS["h10"])
        self.add_flow(match_h10, 1, priority=10)

        # Forward đến h20 (qua s2 - port 2)
        match_h20 = of.ofp_match()
        match_h20.dl_type = 0x0800
        match_h20.nw_dst = IPAddr(IPS["h20"])
        self.add_flow(match_h20, 2, priority=10)

        # Forward đến h30 (qua s3 - port 3)
        match_h30 = of.ofp_match()
        match_h30.dl_type = 0x0800
        match_h30.nw_dst = IPAddr(IPS["h30"])
        self.add_flow(match_h30, 3, priority=10)

        # Forward đến serv1 (qua dcs31 - port 4)
        match_serv1 = of.ofp_match()
        match_serv1.dl_type = 0x0800
        match_serv1.nw_dst = IPAddr(IPS["serv1"])
        self.add_flow(match_serv1, 4, priority=10)

        # Forward đến hnotrust1 (trực tiếp - port 5)
        match_hnotrust = of.ofp_match()
        match_hnotrust.dl_type = 0x0800
        match_hnotrust.nw_dst = IPAddr(IPS["hnotrust"])
        self.add_flow(match_hnotrust, 5, priority=10)

    def _handle_PacketIn(self, event):
        """
        Packets not handled by the router rules will be
        forwarded to this method to be handled by the controller
        """

        packet = event.parsed  # This is the parsed packet data.
        if not packet.parsed:
            log.warning("Ignoring incomplete packet")
            return

        packet_in = event.ofp  # The actual ofp_packet_in message.
        print("Unhandled packet from " + str(self.connection.dpid) + ":" + packet.dump())

def launch():
    """
    Starts the component
    """

    def start_switch(event):
        log.debug("Controlling %s" % (event.connection,))
        Part3Controller(event.connection)

    core.openflow.addListenerByName("ConnectionUp", start_switch)