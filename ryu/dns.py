from ryu.lib.packet import packet_base
import struct
class dns(packet_base.PacketBase):
    _DNS_PACK_HEADER = "!HBBHHHH"
    _MIN_LEN = struct.calcsize(_DNS_PACK_HEADER)
    
    def __init__(self):
        super(dns, self).__init__()
        
    @classmethod
    def parser(cls, buf):
        print(struct.unpack_from(cls._DNS_PACK_HEADER, buf))
    
    def serialize(self, _payload=None, _prev=None):
        pass