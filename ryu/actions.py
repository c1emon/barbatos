from ryu.lib.packet import ether_types, in_proto
from utils import PRIVATE_IPS

def add_proxy_flow(datapath, match={}, priority=20):
    ofproto = datapath.ofproto
    parser = datapath.ofproto_parser
        
    actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, 
                                        ofproto.OFPCML_NO_BUFFER)]

    mod = build_flow(datapath, priority, actions, match)
    datapath.send_msg(mod)
    
def add_host_proxy_flow(datapath, hosts, default_gw, proxy_gw, priority=20):

    out_match_tcp = dict(
            eth_type=ether_types.ETH_TYPE_IP,
            eth_dst=default_gw.mac,
            ip_proto=in_proto.IPPROTO_TCP)
    
    out_match_udp = dict(
            eth_type=ether_types.ETH_TYPE_IP,
            eth_dst=default_gw.mac,
            ip_proto=in_proto.IPPROTO_UDP)
    
    in_match_tcp = dict(
            eth_type=ether_types.ETH_TYPE_IP,
            eth_src=proxy_gw.mac,
            ip_proto=in_proto.IPPROTO_TCP)
    
    in_match_udp = dict(
            eth_type=ether_types.ETH_TYPE_IP,
            eth_src=proxy_gw.mac,
            ip_proto=in_proto.IPPROTO_UDP)
    
    for host in hosts:
        if host.mac:
            mac = host.mac
            out_match_tcp.update(eth_src=mac)
            add_proxy_flow(datapath, out_match_tcp, priority)
            del out_match_tcp["eth_src"]
            
            out_match_udp.update(eth_src=mac)
            add_proxy_flow(datapath, out_match_udp, priority)
            del out_match_udp["eth_src"]
            
            in_match_tcp.update(eth_dst=mac)
            add_proxy_flow(datapath, in_match_tcp, priority)
            del in_match_tcp["eth_dst"]
            
            in_match_udp.update(eth_dst=mac)
            add_proxy_flow(datapath, in_match_udp, priority)
            del in_match_udp["eth_dst"]
        else:
            ip = host.ip
            out_match_tcp.update(ipv4_src=ip)
            add_proxy_flow(datapath, out_match_tcp, priority)
            del out_match_tcp["ipv4_src"]
            
            out_match_udp.update(ipv4_src=ip)
            add_proxy_flow(datapath, out_match_udp, priority)
            del out_match_udp["ipv4_src"]
            
            in_match_tcp.update(ipv4_dst=ip)
            add_proxy_flow(datapath, in_match_tcp, priority)
            del in_match_tcp["ipv4_dst"]
            
            in_match_udp.update(ipv4_dst=ip)
            add_proxy_flow(datapath, in_match_udp, priority)
            del in_match_udp["ipv4_dst"]
            
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
        match.update(ipv4_dst=c)
        mod = build_flow(datapath, priority, actions, match)
        datapath.send_msg(mod)
    
def add_dns_proxy_flow(datapath, hosts, priority=100):
    """proxy dns of special hosts
       ignore hosts' dns server.

    Args:
        datapath (datapath): ryu datapath
        hosts (list): specific host's ip or mac. 
                      At least one of 'ip' or 'mac' is not empty. 
                      If both 'ip' and 'mac' are all inputed, 'mac' has higher priority than 'ip'.
                      e.g. [
                            {"ip"="10.0.0.1", "mac"="76:7e:26:77:72:4b"},
                            {"ip"="10.0.0.2", "mac"="88:7e:26:77:72:43"},
                            {"ip"="10.0.0.3"},
                            {"mac"="88:7e:26:77:72:40"}
                           ]
        priority (int, optional): priority. Defaults to 100.
    """
    
    # ipv4_src = private ips or eth_src = private macs
    req_match = dict(
            eth_type=ether_types.ETH_TYPE_IP,
            ip_proto=17,
            udp_dst=53)
    
    # ipv4_dst = private ips or eth_dst = private macs
    resp_match = dict(
            eth_type=ether_types.ETH_TYPE_IP,
            ip_proto=17,
            udp_src=53)
    
    for host in hosts:
        if host.mac:
            # req
            req_match.update(eth_src=host.mac)
            add_proxy_flow(datapath, req_match, priority)
            del req_match["eth_src"]
            # resp
            resp_match.update(eth_dst=host.mac)
            add_proxy_flow(datapath, resp_match, priority)
            del resp_match["eth_dst"]
        else:
            # req
            req_match.update(ipv4_src=host.ip)
            add_proxy_flow(datapath, req_match, priority)
            del req_match["ipv4_src"]
            # resp
            resp_match.update(ipv4_dst=host.ip)
            add_proxy_flow(datapath, resp_match, priority)
            del resp_match["ipv4_dst"]

def build_flow(datapath, priority, actions=[], match={}, **kwargs):
    ofproto = datapath.ofproto
    parser = datapath.ofproto_parser

    match = parser.OFPMatch(**match)
    
    # construct flow_mod message and send it.
    inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                                actions)]
    return parser.OFPFlowMod(datapath=datapath, priority=priority,
                            match=match, instructions=inst)

def send_packet_out(datapath, actions, buffer_id, data):
    ofproto = datapath.ofproto
    parser = datapath.ofproto_parser

    out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=buffer_id, 
            in_port=ofproto.OFPP_CONTROLLER,
            actions=actions, data=data)
    datapath.send_msg(out)