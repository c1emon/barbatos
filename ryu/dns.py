from ryu.lib.packet import packet_base

class dns(packet_base.PacketBase):
    
    def __init__(self):
        super(dns, self).__init__()
        
    @classmethod
    def parser(cls, buf):
        pass
    
    def serialize(self, _payload=None, _prev=None):
        pass