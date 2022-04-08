from ryu.lib.packet import ether_types
from utils import PRIVATE_IPS

def add_proxy_flow(datapath, match={}, priority=20):
    ofproto = datapath.ofproto
    parser = datapath.ofproto_parser
        
    actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, 
                                        ofproto.OFPCML_NO_BUFFER)]

    mod = build_flow(datapath, priority, actions, match)
    datapath.send_msg(mod)
    
def add_normal_flow(datapath, match={}, priority=0):
    ofproto = datapath.ofproto
    parser = datapath.ofproto_parser
    actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL, 
                                        ofproto.OFPCML_NO_BUFFER)]
    
    mod = build_flow(datapath, priority, actions, match)
    datapath.send_msg(mod)
    
def add_private_flow(datapath, priority=50):
    ofproto = datapath.ofproto
    parser = datapath.ofproto_parser
    actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL, 
                                        ofproto.OFPCML_NO_BUFFER)]
    
    match = dict(eth_type=ether_types.ETH_TYPE_IP)
    for cidr in PRIVATE_IPS.iter_cidrs():
        c = str(cidr)
        match.update(ipv4_dst=c, ipv4_src=c)
        mod = build_flow(datapath, priority, actions, match)
        datapath.send_msg(mod)
    
# ??????
def add_dns_proxy_flow(datapath, ips=[], macs=[], priority=100):
    ofproto = datapath.ofproto
    parser = datapath.ofproto_parser
    
    # ipv4_src = private ips
    req_match = dict(
            eth_type=ether_types.ETH_TYPE_IP,
            ip_proto=17,
            udp_dst=53)
    
    # ipv4_dst = private ips
    resp_match = dict(
            eth_type=ether_types.ETH_TYPE_IP,
            ip_proto=17,
            udp_src=53)
    
    actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, 
                                        ofproto.OFPCML_NO_BUFFER)]
    
    for ip in ips:
        match.update(ipv4_src=str(ip))
        mod = build_flow(datapath, priority, actions, match)
        datapath.send_msg(mod)
        
    del match["ipv4_src"]
    for mac in macs:
        match.update(eth_src=str(mac))
        mod = build_flow(datapath, priority, actions, match)
        datapath.send_msg(mod)


def build_flow(datapath, priority, actions=[], match={}, **kwargs):
    ofproto = datapath.ofproto
    parser = datapath.ofproto_parser

    match = parser.OFPMatch(**match)
    
    # construct flow_mod message and send it.
    inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                                actions)]
    return parser.OFPFlowMod(datapath=datapath, priority=priority,
                            match=match, instructions=inst)