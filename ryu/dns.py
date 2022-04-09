"""
DNS packet parser/serializer
"""
# RFC 1035
# http://networksorcery.com/enp//protocol/dns.htm#Questions
# https://tools.ietf.org/html/rfc1035
# DNS packet format:
#  0                   1                   2                   3
#  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |        Identification         |            flags              |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |        Total Questions        |      Total Answer RRs         |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |      Total Authority RRs      |     Total Additional RRs      |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |                      Questions (variable)                     |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |                      Answer RRs [] :::                        |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |                     Authority RRs [] :::                      |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |                    Additional RRs [] :::                      |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# 
# flags format(16 bits):
# flags = QR(1bit)|Opcode(4bit)|AA(1bit)|TC(1bit)|RD(1bit)|RA(1bit)|Z(1bit)|AD(1bit)|CD(1bit)|Rcode(4bit)
# 

from ryu.lib.packet import packet_base
import struct
class dns(packet_base.PacketBase):
    _DNS_PACK_HEADER = "!HBBHHHH"
    _HEADER_LEN = struct.calcsize(_DNS_PACK_HEADER)
    
    def __init__(self):
        super(dns, self).__init__()
        self.id = None
        
    @classmethod
    def parser(cls, buf):
        header, rest_buf = dns._header_parser(buf)
        print("id: 0x%x\nquestions: %d\nanswer_rrs: %d\nauthority_rrs: %d\nadditional_rrs: %d\n" % (header[0], questions, answer_rrs, authority_rrs, additional_rrs))
        
        
    @classmethod
    def _header_parser(cls, buf):
        (id, flags1, flags2, questions, 
         answer_rrs, authority_rrs, additional_rrs) = struct.unpack_from(dns._DNS_PACK_HEADER, buf)

        qr, opcode, aa, tc, rd = flags1 & 0x80, flags1 & 0x78, flags1 & 0x04, flags1 & 0x02, flags1 & 0x01
        ra, z, ad, cd, rcode = flags2 & 0x80, flags2 & 0x40, flags2 & 0x20, flags2 & 0x10, flags2 & 0x0f
        
        return ((id, qr, opcode, aa, tc, rd, ra, z, ad, cd, rcode, questions, answer_rrs, authority_rrs, additional_rrs),
                buf[dns._HEADER_LEN:])
    
    def _body_parser(self, buf):
        struct.unpack_from(dns._DNS_PACK_HEADER, buf)
    
    def serialize(self, _payload=None, _prev=None):
        pass