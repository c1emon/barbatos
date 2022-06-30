from ryu.base import app_manager
from ryu.controller import ofp_event, dpset
from ryu.controller.handler import set_ev_cls, MAIN_DISPATCHER, CONFIG_DISPATCHER

from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp
from ryu.ofproto import ofproto_v1_3

from actions import *
from utils import *
from handler import *
from config import *
from dns_redis import *

import dns.message
import dns.flags

import logging

class Tproxy(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    
    def __init__(self, *_args, **_kwargs):
        super(Tproxy, self).__init__(*_args, **_kwargs)
        self.name = self.__class__.__name__
        self.logger = logging.getLogger(self.__class__.LOGGER_NAME) \
            if hasattr(self.__class__, 'LOGGER_NAME') else logging.getLogger(self.name)
        self.dpset = _kwargs['dpset']
        
        self.c = conf("barbatos.yaml")
        self.dr = dns_redis(self.c.redis_ip, self.c.redis_port)
        
        set_fakeip(self.c.fakeip)

    def update_flow(self):
        datapath = self.dpset.get_all()[0][1]
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
    
    def close(self):
        self.logger.info("exit app")
        
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        
        add_dns_proxy_flow(datapath, self.c.proxy_hosts)
        add_host_proxy_flow(datapath, self.c.proxy_hosts, self.c.default_gateway, self.c.proxy_gateway)
        add_private_flow(datapath)
        add_normal_flow(datapath)
        
    def _dns_handler(self, datapath, pkg, ipv4_src, ipv4_dst, msg):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        try:
            dns_msg = dns.message.from_wire(pkg.protocols[-1])
        except Exception as e:
            self.logger.warning(e)
            send_packet_out_normal(datapath, msg.buffer_id, pkg)
            
        id = "0x%x" % dns_msg.id
        if not dns_msg.flags & dns.flags.QR:
            self.logger.debug("dns query(%s -> %s[%s]): %s", ipv4_src, ipv4_dst, self.c.proxy_gateway.ip, id)
            actions = [
                parser.OFPActionSetField(eth_dst=self.c.proxy_gateway.mac),
                parser.OFPActionSetField(ipv4_dst=self.c.proxy_gateway.ip),
                parser.OFPActionOutput(ofproto.OFPP_NORMAL, 0)]
            send_packet_out(datapath, actions, msg.buffer_id, pkg)
            
            self.dr.set(id, {"src":ipv4_src, "dst": ipv4_dst})
        else:
            v = self.dr.get(id)
            if not v:
                self.logger.warning("drop dns response(%s[%s] -> %s): %s", ipv4_src, "null", ipv4_dst, id)
                actions = []
            else:
                raw_dst_ip = v["dst"]
                self.logger.debug("dns response(%s[%s] -> %s): %s", ipv4_src, raw_dst_ip, ipv4_dst, id)
                actions = [
                    parser.OFPActionSetField(eth_src=self.c.default_gateway.mac),
                    parser.OFPActionSetField(ipv4_src=raw_dst_ip),
                    parser.OFPActionOutput(ofproto.OFPP_NORMAL, 0)]
                
            send_packet_out(datapath, actions, msg.buffer_id, pkg)
        
    def _out_traffic_handler(self, datapath, pkg, msg):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        actions = [
            parser.OFPActionSetField(eth_dst=self.c.proxy_gateway.mac),
            parser.OFPActionOutput(ofproto.OFPP_NORMAL, 0)]
        send_packet_out(datapath, actions, msg.buffer_id, pkg)
        
    def _in_traffic_handler(self, datapath, pkg, msg):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        actions = [
            parser.OFPActionSetField(eth_src=self.c.default_gateway.mac),
            parser.OFPActionOutput(ofproto.OFPP_NORMAL, 0)]
        send_packet_out(datapath, actions, msg.buffer_id, pkg)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        # TODO: identity package by cookie
        # cookie = msg.cookie
        
        pkg = packet.Packet(msg.data)
        
        for proto_pkg in pkg.protocols:
            name = proto_pkg.protocol_name
            if name == "ethernet":
                eth_src = proto_pkg.src
                eth_dst = proto_pkg.dst
            elif name == "ipv4":
                ipv4_src = proto_pkg.src
                ipv4_dst = proto_pkg.dst
            elif name == "udp" or name == "tcp":
                src_port = proto_pkg.src_port
                dst_port = proto_pkg.dst_port
                
                if name == "udp" and (src_port == 53 or dst_port ==53):
                    self._dns_handler(datapath, pkg, ipv4_src, ipv4_dst, msg)
                    return
                
                if (eth_src in self.c.proxy_macs or ipv4_src in self.c.proxy_ips) and (is_public(ipv4_dst) or is_fakeip(ipv4_dst, self.c.fakeip)):
                    self.logger.debug("%s: %s(%s) ---> %s[(%s) map to (%s)]", name, ipv4_src, eth_src, ipv4_dst, eth_dst, self.c.proxy_gateway.mac)
                    self._out_traffic_handler(datapath, pkg, msg)
                    return
                
                if (eth_dst in self.c.proxy_macs or ipv4_dst in self.c.proxy_ips) and (is_public(ipv4_src) or is_fakeip(ipv4_dst, self.c.fakeip)):
                    self.logger.debug("%s: %s[(%s) map to (%s)] ---> %s(%s)", name, ipv4_src, eth_src, self.c.default_gateway.mac, ipv4_dst, eth_dst)
                    self._in_traffic_handler(datapath, pkg, msg)
                    return

        send_packet_out_normal(datapath, msg.buffer_id, pkg)
