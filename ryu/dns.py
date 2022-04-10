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
#  Query Name format shown in function ```_parse_domain_label```
# 
# 
# 
# 
# 


from ryu.lib.packet import packet_base
import struct

class dns(packet_base.PacketBase):
    _DNS_PACK_HEADER = "!HBBHHHH"
    _HEADER_LEN = struct.calcsize(_DNS_PACK_HEADER)
    
    def __init__(self, id, qr, opcode, aa, tc, rd, ra, ad, cd, rcode, qdcount, ancount, nscount, arcount):
        super(dns, self).__init__()
        self.id = id
        self.qr = qr
        self.opcode = opcode
        self.aa = aa
        self.tc = tc
        self.rd = rd
        self.ra = ra
        # self.z = z
        self.ad = ad
        self.cd =cd
        self.rcode = rcode
        self.qdcount = qdcount
        self.ancount = ancount 
        self.nscount = nscount
        self.arcount = arcount
        
    @classmethod
    def parser(cls, buf):
        
        (id, flags1, flags2, 
         qdcount, ancount, 
         nscount, arcount) = struct.unpack_from(cls._DNS_PACK_HEADER, buf)
        rest_buf = buf[cls._HEADER_LEN:]
        
        qr, opcode, aa, tc, rd = flags1 & 0x80, flags1 & 0x78, flags1 & 0x04, flags1 & 0x02, flags1 & 0x01
        ra, ad, cd, rcode = flags2 & 0x80, flags2 & 0x20, flags2 & 0x10, flags2 & 0x0f
        
        q, rest_buf = dns_question.parser(rest_buf, qdcount)
        
        if qr:
            # resp
            pass
        
        return (
            cls(id, qr, opcode, aa, tc, rd, ra, ad, cd, rcode, qdcount, ancount, nscount, arcount),
            None,
            rest_buf
        )
    
    def serialize(self, _payload=None, _prev=None):
        pass

   

class dns_question(object):
    
    OFFSET = dns._HEADER_LEN
    
    def __init__(self, questions):
        self.questions = questions
    
    @classmethod
    def parser(cls, buf, qdcount):
        pos = 0
        offsets = [0]
        questions = {}
        for i in range(qdcount):
            domain , p = _parse_domain_label(buf[pos:])
            pos += p
            (qtype, qclass) = struct.unpack_from("!HH", buf[pos:])
            pos += 4
            questions[domain] = {
                "offset": cls.OFFSET + offsets[i],
                "type": qtype,
                "class": qclass
            }
            offsets.append(pos)
            
        return cls(questions), buf[pos:]
    
    def serialize(self, _payload=None, _prev=None):
        pass
    
    
class dns_answer(object):
    def __init__(self) -> None:
        pass
    
    @classmethod
    def parser(cls, buf, ancount):
        pass
    
    def serialize(self, _payload=None, _prev=None):
        pass
    
class dns_authority(object):
    def __init__(self) -> None:
        pass
    
    @classmethod
    def parser(cls, buf, nscount):
        pass
    
    def serialize(self, _payload=None, _prev=None):
        pass

class dns_additional(object):
    def __init__(self) -> None:
        pass
    
    @classmethod
    def parser(cls, buf, arcount):
        pass
    
    def serialize(self, _payload=None, _prev=None):
        pass
    
def _parse_domain_label(buf):
    """Domain name in the label format shown below:
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    length[0](8bit) | char[0] | char[1] | .... | char[length[0]-1] |
    length[1](8bit) | char[0] | char[1] | .... | char[length[1]-1] |
    ........
    length[n](8bit) | char[0] | char[1] | .... | char[length[n]-1] |
    0(8bit)
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    Every single part should be divide by "." to build raw domain string.
    And the last "0" indicate the domian string has finished.
    Every length[x] should be '00xx xxxx' in binary format. The first two bits should be zeros.
    
    The input buf must come first with vaild domain label. And this function just parses first domain label.
    Args:
        buf (bytearray): input byte array

    Returns:
        domain (string): domain name
        length (int): length of this domain in buf
    """
    pos = 0
    domain = []
    while buf[pos] != 0x00:
        len = buf[pos]
        # TODO: assert len & 0xc0
        s = struct.unpack_from("!%ds" % len, buf[pos+1:])[0]
        domain.append(str(s, encoding='utf-8'))
        pos += (len+1)
    
    return ".".join(domain), pos+1
    