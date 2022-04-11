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
import dns.message

import logging
from numba import jit


PROXY_HOSTS = [
    {"ip": "10.0.0.1"}
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
        self.dns_req = {}
        self.proxy_ips = []
        for host in PROXY_HOSTS:
            if "ip" not in host:
                continue
            self.proxy_ips.append(host["ip"])
            
        
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        
        add_dns_proxy_flow(datapath, PROXY_HOSTS)
        add_host_proxy_flow(datapath, PROXY_HOSTS, DEFAULT_GW, PROXY_GW)
        add_private_flow(datapath)
        add_normal_flow(datapath)
   
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
        
    
        if udp_pkg and (pkg.dst_port == 53 or pkg.src_port == 53):
            # dns req
            # hack to proxy:53
            dns_msg = dns.message.from_wire(p.protocols[-1])
            if not dns_msg.qr:
                self.logger.info("dns query(%s -> %s[%s])", ipv4_pkg.src, ipv4_pkg.dst, PROXY_GW["ip"])
                actions = [
                    parser.OFPActionSetField(eth_dst=PROXY_GW["mac"]),
                    parser.OFPActionSetField(ipv4_dst=str(PROXY_GW["ip"])),
                    parser.OFPActionOutput(ofproto.OFPP_NORMAL, ofproto.OFPCML_NO_BUFFER)]
                out = parser.OFPPacketOut(
                    datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.match["in_port"],
                    actions=actions, data=p)
                datapath.send_msg(out)
                self.dns_req[ipv4_pkg.src] = {[str(dns_msg.id)] : ipv4_pkg.dst}
                return
            else:
                raw_src_ip = self.dns_req[ipv4_pkg.dst].pop(str(dns_msg.id))
                self.logger.info("dns response(%s[%s] -> %s): %s", ipv4_pkg.src, raw_src_ip, ipv4_pkg.dst)
                
                actions = [
                    parser.OFPActionSetField(eth_src=DEFAULT_GW["mac"]),
                    parser.OFPActionSetField(ipv4_src=raw_src_ip),
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
        
        