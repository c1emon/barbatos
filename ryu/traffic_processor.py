from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet import packet, ether_types, ethernet, arp, ipv4, tcp, udp
from ryu.ofproto import ofproto_v1_3
from netaddr import IPAddress, IPSet

from actions import *
from utils import *
from handler import *

import logging
import copy
from numba import jit


proxy_ips = [
    "10.0.0.1"
]

proxy_macs = [
]

DEFAULT_GW = {
    "ip": IPAddress("10.0.0.254"),
    "mac": "76:7e:26:77:72:4a"
}

PROXY_GW = {
    "ip": IPAddress("10.0.0.253"),
    "mac": "76:7e:26:77:72:4b"
}


class Tproxy(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    
    def __init__(self, *_args, **_kwargs):
        super(Tproxy, self).__init__(*_args, **_kwargs)
        self.name = self.__class__.__name__
        if hasattr(self.__class__, 'LOGGER_NAME'):
            self.logger = logging.getLogger(self.__class__.LOGGER_NAME)
        else:
            self.logger = logging.getLogger(self.name)
            
        self.proxy_ips = IPSet()
        [self.proxy_ips.add(ip) for ip in proxy_ips]
        self.proxy_macs = proxy_macs
        
        self.logger.info("proxy for: %s", self.proxy_ips)
        
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        
        # self.hack_dns(datapath)
        self.add_proxy_flow(datapath)
        self.add_normal_flow(datapath)

   
        
    def _host2proxy(self, datapath, priority=100):
        matches = dict(
                eth_type=ether_types.ETH_TYPE_IP,
                eth_dst=DEFAULT_GW["mac"])
        for ip in proxy_ips:
            m = copy.deepcopy(matches)
            m.update(ipv4_src=str(ip))
            # TCP
            m.update(ip_proto=6)
            add_proxy_flow(datapath, m, priority=priority)
            # UDP
            m.update(ip_proto=17)
            add_proxy_flow(datapath, m, priority=priority)
            
        for mac in proxy_macs:
            m = copy.deepcopy(matches)
            m.update(eth_src=mac)
            # TCP
            m.update(ip_proto=6)
            add_proxy_flow(datapath, m, priority=priority)
            # UDP
            m.update(ip_proto=17)
            add_proxy_flow(datapath, m, priority=priority)
            
    
    def _proxy2host(self, datapath, priority=100):
        matches = dict(
                eth_type=ether_types.ETH_TYPE_IP,
                eth_src=PROXY_GW["mac"])
        for ip in proxy_ips:
            m = copy.deepcopy(matches)
            m.update(ipv4_dst=str(ip))
            # TCP
            m.update(ip_proto=6)
            add_proxy_flow(datapath, m, priority=priority)
            # UDP
            m.update(ip_proto=17)
            add_proxy_flow(datapath, m, priority=priority)
            
        for mac in proxy_macs:
            m = copy.deepcopy(matches)
            m.update(eth_dst=mac)
            # TCP
            m.update(ip_proto=6)
            add_proxy_flow(datapath, m, priority=priority)
            # UDP
            m.update(ip_proto=17)
            add_proxy_flow(datapath, m, priority=priority)
        
    def add_proxy_flow(self, datapath, priority=100):
        self._host2proxy(datapath, priority)
        self._proxy2host(datapath, priority)
            
        self.logger.info("add proxy flow")
   
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        p = packet.Packet(msg.data)
        
        eth_pkg = p.get_protocol(ethernet.ethernet)
        ipv4_pkg = p.get_protocol(ipv4.ipv4)
        tcp_pkg = p.get_protocol(tcp.tcp)
        udp_pkg = p.get_protocol(udp.udp)
        # TODO: assert ipv4_pkg not None
        pkg = tcp_pkg if tcp_pkg else udp_pkg
        # body = eth_pkg.protocols[-1]

        if udp_pkg and pkg.dst_port == 53 and ipv4_pkg.src in self.proxy_ips:
            # dns req
            # hack to proxy:53
            self.logger.info("dns request(%s -> %s): %s", ipv4_pkg.src, ipv4_pkg.dst, udp_pkg.data)
            actions = [
                parser.OFPActionSetField(eth_dst=PROXY_GW["mac"]),
                parser.OFPActionSetField(ipv4_dst=str(PROXY_GW["ip"])),
                parser.OFPActionOutput(ofproto.OFPP_NORMAL, ofproto.OFPCML_NO_BUFFER)]
            out = parser.OFPPacketOut(
                datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.match["in_port"],
                actions=actions, data=p)
            datapath.send_msg(out)
            return
        
        if udp_pkg and pkg.src_port == 53 and ipv4_pkg.src == str(PROXY_GW["ip"]) and ipv4_pkg.dst in self.proxy_ips:
            self.logger.info("dns(p -> h): %s", udp_pkg)
            actions = [
                parser.OFPActionSetField(eth_src=DEFAULT_GW["mac"]),
                parser.OFPActionSetField(ipv4_src="114.114.114.114"),
                parser.OFPActionOutput(ofproto.OFPP_NORMAL, ofproto.OFPCML_NO_BUFFER)]
            out = parser.OFPPacketOut(
                datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.match["in_port"],
                actions=actions, data=p)
            datapath.send_msg(out)
            return
        
        if ipv4_pkg.src in self.proxy_ips and is_public(ipv4_pkg.dst):
            # TODO: host -> proxy
            
            self.logger.info("%s: %s(%s) ---> %s[(%s) map to (%s)]", pkg.protocol_name, ipv4_pkg.src, eth_pkg.src, ipv4_pkg.dst, eth_pkg.dst, PROXY_GW["mac"])
            actions = [
                parser.OFPActionSetField(eth_dst=PROXY_GW["mac"]), 
                parser.OFPActionOutput(ofproto.OFPP_NORMAL, ofproto.OFPCML_NO_BUFFER)]
            out = parser.OFPPacketOut(
                datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.match["in_port"],
                actions=actions, data=p)
            datapath.send_msg(out)
            return
        
        if ipv4_pkg.dst in self.proxy_ips and is_public(ipv4_pkg.src):
            # TODO: proxy -> host
            
            self.logger.info("%s: %s[(%s) map to (%s)] ---> %s(%s)", pkg.protocol_name, ipv4_pkg.src, eth_pkg.src, DEFAULT_GW["mac"], ipv4_pkg.dst, eth_pkg.dst)
            actions = [
                parser.OFPActionSetField(eth_src=DEFAULT_GW["mac"]), 
                parser.OFPActionOutput(ofproto.OFPP_NORMAL, ofproto.OFPCML_NO_BUFFER)]
            out = parser.OFPPacketOut(
                datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.match["in_port"],
                actions=actions, data=p)
            datapath.send_msg(out)
            return
        
        # NORMAL ACTION
        self.logger.info("Local: %s: %s(%s) ---> %s(%s)", pkg.protocol_name, ipv4_pkg.src, eth_pkg.src, ipv4_pkg.dst, eth_pkg.dst)
        actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL, ofproto.OFPCML_NO_BUFFER)]
        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.match["in_port"],
            actions=actions, data=p)
        datapath.send_msg(out)
        
        