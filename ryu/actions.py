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
    ofproto = datapath.ofproto
    parser = datapath.ofproto_parser
    
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
    
    actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, 
                                        ofproto.OFPCML_NO_BUFFER)]
    
    for host in hosts:
        
        if "mac" in host:
            # req
            req_match.update(eth_src=str(host["mac"]))
            mod = build_flow(datapath, priority, actions, req_match)
            datapath.send_msg(mod)
            del req_match["eth_src"]
            # resp
            resp_match.update(eth_dst=str(host["mac"]))
            mod = build_flow(datapath, priority, actions, resp_match)
            datapath.send_msg(mod)
            del resp_match["eth_dst"]
        else:
            # req
            req_match.update(ipv4_src=str(host["ip"]))
            mod = build_flow(datapath, priority, actions, req_match)
            datapath.send_msg(mod)
            del req_match["ipv4_src"]
            # resp
            resp_match.update(ipv4_dst=str(host["ip"]))
            mod = build_flow(datapath, priority, actions, resp_match)
            datapath.send_msg(mod)
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