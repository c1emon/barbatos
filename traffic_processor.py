from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet import packet, ether_types, ethernet, arp, ipv4, tcp, udp
from ryu.ofproto import ofproto_v1_3
import array

import logging
import copy

PRIVATE_IPS = [
    "192.168.0.0/16",
    "0.0.0.0/8",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "169.254.0.0/16",
    "224.0.0.0/4",
    "240.0.0.0/4"
]

proxy_ips = [
    "10.0.0.1/32"
]

proxy_macs = [
]

DEFAULT_GW = {
    "ip": "10.0.0.254/32",
    "mac": "76:7e:26:77:72:4a"
}

PROXY_GW = {
    "ip": "10.0.0.253/32",
    "mac": "76:7e:26:77:72:4b"
}

def _apply_controller_actions(datapath, actions={}, priority=0):
    ofproto = datapath.ofproto
    parser = datapath.ofproto_parser
    
    match = parser.OFPMatch(**actions)
            
    actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]

    # construct flow_mod message and send it.
    inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                        actions)]
    # msg
    mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                            match=match, instructions=inst)
    # send the instruction to ovs
    datapath.send_msg(mod)

class Tproxy(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    
    def __init__(self, *_args, **_kwargs):
        super(Tproxy, self).__init__(*_args, **_kwargs)
        self.name = self.__class__.__name__
        if hasattr(self.__class__, 'LOGGER_NAME'):
            self.logger = logging.getLogger(self.__class__.LOGGER_NAME)
        else:
            self.logger = logging.getLogger(self.name)
        
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        
        self.add_proxy_flow(datapath)
        self.add_private_flow(datapath)

    def _host2proxy(self, datapath, priority=100):
        matches = dict(
                eth_type=ether_types.ETH_TYPE_IP,
                eth_dst=DEFAULT_GW["mac"])
        for ip in proxy_ips:
            m = copy.deepcopy(matches)
            m.update(ipv4_src=ip)
            _apply_controller_actions(datapath, m, priority=priority)
            
        for mac in proxy_macs:
            m = copy.deepcopy(matches)
            m.update(eth_src=mac)
            _apply_controller_actions(datapath, m, priority=priority)
            
    
    def _proxy2host(self, datapath, priority=100):
        matches = dict(
                eth_type=ether_types.ETH_TYPE_IP,
                eth_src=PROXY_GW["mac"])
        for ip in proxy_ips:
            m = copy.deepcopy(matches)
            m.update(ipv4_dst=ip)
            _apply_controller_actions(datapath, m, priority=priority)
            
        for mac in proxy_macs:
            m = copy.deepcopy(matches)
            m.update(eth_dst=mac)
            _apply_controller_actions(datapath, m, priority=priority)
        
        
    
    def add_proxy_flow(self, datapath, priority=100):
        self._host2proxy(datapath, priority)
        self._proxy2host(datapath, priority)
            
        self.logger.debug("add proxy flow")
        
    def add_normal_flow(self, datapath, priority=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]

        # construct flow_mod message and send it.
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)
        self.logger.debug("add normal flow")
        
    def add_private_flow(self, datapath, ips=[],priority=10):
        """add default flow table, skip local private addresses.
        By this way, inter lan traffic should just by pass.
        But the traffic that go to outside should be hacked. 
        So this rule should has the lowest priority.
        e.g. DST_IP is WAN, DST_MAC is gatewat's mac.

        Args:
            datapath (datapath): datapath
            ips (list, optional): add more private ip cidr. Default to empty list.
            priority (int, optional): priority of default flow. Defaults to 1000.
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # allow arp
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP)
            
        actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                                actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)
        
        # allow private addresses
        for ip in set(PRIVATE_IPS + ips):
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=ip)
            
            actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                                actions)]
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
            datapath.send_msg(mod)
            
        self.logger.debug("add private flow")

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        p = packet.Packet(array.array("B", msg.data))
        
        self.logger.debug("======+Recv PKGs+======")
        eth_pkg = p.get_protocol(ethernet.ethernet)
        ipv4_pkg = p.get_protocol(ipv4.ipv4)
        tcp_pkg = p.get_protocol(tcp.tcp)
        udp_pkg = p.get_protocol(udp.udp)
        
        if ipv4_pkg and (tcp_pkg or udp_pkg) :
            pkg = tcp_pkg if tcp_pkg else udp_pkg
            self.logger.debug("%s: %s(%s) ---> %s(%s)", pkg.protocol_name, ipv4_pkg.src, eth_pkg.src, ipv4_pkg.dst, eth_pkg.dst)
            
        self.logger.debug("=======================")
        
        # parser.OFPActionSetField(),
        actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.match["in_port"],
            actions=actions, data=p)
        datapath.send_msg(out)
        
        