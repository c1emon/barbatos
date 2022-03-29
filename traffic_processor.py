from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet import packet
import array

# fake-ip mode
TARGET_NW_DST = "198.18.0.0/16"
# client mac addresses
SRC_MAC = []
class Tproxy(app_manager.RyuApp):
    
    def __init__(self, *_args, **_kwargs):
        super(Tproxy, self).__init__(*_args, **_kwargs)
        self.mac_to_port = {}
        
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        

        # install the table-miss flow entry.
        # self.add_default_flow(datapath, 100)
        self.add_normal_flow(datapath)

    def add_default_flow(self, datapath, priority):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]

        # construct flow_mod message and send it.
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        # msg
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        # send the instruction to ovs
        datapath.send_msg(mod)
        
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

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        pkt = packet.Packet(array.array('B', ev.msg.data))
        for p in pkt:
            print(p.protocol_name, p)
            if p.protocol_name == 'vlan':
                print('vid = ', p.vid)