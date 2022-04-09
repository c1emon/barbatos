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
# QR(1bit)|Opcode(4bit)|AA(1bit)|TC(1bit)|RD(1bit)|RA(1bit)|Z(1bit)|AD(1bit)|CD(1bit)|Rcode(4bit)
# 
# single question format:
#  0                   1                   2                   3
#  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |                     Query Name (variable)                     |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |             type              |            class              |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   Query Name format:
#       number of bytes | bytes0(8bits) bytes1 ... bytesn | number of bytes | bytes0 bytes1 ... bytesn | ... | 00(8bits) | QTYPE(16bits) | QCLASS(16bits)
# 
# 
# 
# 


from xml import dom
from ryu.lib.packet import packet_base
import struct
class dns(packet_base.PacketBase):
    _DNS_PACK_HEADER = "!HBBHHHH"
    _HEADER_LEN = struct.calcsize(_DNS_PACK_HEADER)
    
    def __init__(self, id, qr, opcode, aa, tc, rd, ra, z, ad, cd, rcode, questions, answer_rrs, authority_rrs, additional_rrs):
        super(dns, self).__init__()
        self.id = id
        self.qr = qr
        self.opcode = opcode
        self.aa = aa
        self.tc = tc
        self.rd = rd
        self.ra = ra
        self.z = z
        self.ad = ad
        self.cd =cd
        self.rcode = rcode
        self.questions = questions
        self.answer_rrs = answer_rrs 
        self.authority_rrs = authority_rrs
        self.additional_rrs = additional_rrs
        
    @classmethod
    def parser(cls, buf):
        header, rest_buf = cls._dns_header_parser(buf)
        questions, rest_buf = cls._dns_questions_parser(header[11], rest_buf)
        
        return (
            cls(*header),
            None,
            buf[cls._HEADER_LEN:]
        )
    
    def _body_parser(self, buf):
        struct.unpack_from(dns._DNS_PACK_HEADER, buf)
    
    def serialize(self, _payload=None, _prev=None):
        pass

    @classmethod
    def _dns_header_parser(cls, buf):
        (id, flags1, flags2, questions, 
            answer_rrs, authority_rrs, additional_rrs) = struct.unpack_from(cls._DNS_PACK_HEADER, buf)

        qr, opcode, aa, tc, rd = flags1 & 0x80, flags1 & 0x78, flags1 & 0x04, flags1 & 0x02, flags1 & 0x01
        ra, z, ad, cd, rcode = flags2 & 0x80, flags2 & 0x40, flags2 & 0x20, flags2 & 0x10, flags2 & 0x0f
        
        return ((id, qr, opcode, aa, tc, rd, ra, z, ad, cd, rcode, questions, answer_rrs, authority_rrs, additional_rrs),
                buf[cls._HEADER_LEN:])
    
    @classmethod
    def _dns_questions_parser(cls, n_questions, buf):
        pos = 0
        offsets = [0]
        questions = {}
        for i in range(n_questions):
            domain , p = cls._parse_label(buf[pos:])
            pos += p
            (qtype, qclass) = struct.unpack_from("!HH", buf[pos:])
            pos += 4
            questions[domain] = {
                "offset": cls._HEADER_LEN + offsets[i],
                "type": qtype,
                "class": qclass
            }
            offsets.append(pos)
        return questions, buf[pos:]

    @classmethod
    def _parse_label(cls, buf):
        pos = 0
        domain = []
        while buf[pos] != 0x00:
            len = buf[pos]
            s = struct.unpack_from("!%ds" % len, buf[pos+1:])[0]
            domain.append(str(s, encoding='utf-8'))
            pos += (len+1)
        
        # (qtype, qclass) = struct.unpack_from("!HH", buf[offset:])
        return ".".join(domain), pos+1