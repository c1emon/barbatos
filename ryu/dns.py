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
#  |                      Answer RRs (variable)                    |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |                     Authority RRs (variable)                  |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |                    Additional RRs (variable)                  |
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
# 3 kinds of resource record share same formart.
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
        
        pos = 0
        rest_buf = buf
        (id, flags1, flags2, 
         qdcount, ancount, 
         nscount, arcount) = struct.unpack_from(cls._DNS_PACK_HEADER, rest_buf)
        
        qr, opcode, aa, tc, rd = flags1 & 0x80, flags1 & 0x78, flags1 & 0x04, flags1 & 0x02, flags1 & 0x01
        ra, ad, cd, rcode = flags2 & 0x80, flags2 & 0x20, flags2 & 0x10, flags2 & 0x0f
        pos += cls._HEADER_LEN
        rest_buf = rest_buf[cls._HEADER_LEN:]
        
        question, offset_pointer, length = dns_question.parser(rest_buf, qdcount, pos)
        pos += length
        rest_buf = rest_buf[length:]
        
        if ancount:
            answer, offset_pointer, length = record.parser(rest_buf, ancount, pos, offset_pointer)
            pos += length
            rest_buf = rest_buf[length:]
        
        if nscount:
            authority, offset_pointer, length = record.parser(rest_buf, nscount, pos, offset_pointer)
            pos += length
            rest_buf = rest_buf[length:]
            
        if arcount:
            additional, offset_pointer, length = record.parser(rest_buf, arcount, pos, offset_pointer)
            pos += length
            rest_buf = rest_buf[length:]
        
        
        return (
            cls(id, qr, opcode, aa, tc, rd, ra, ad, cd, rcode, qdcount, ancount, nscount, arcount),
            None,
            rest_buf if rest_buf else None
        )
    
    def serialize(self, _payload=None, _prev=None):
        pass


class dns_question(object):
    
    _HEADER_OFFSET = dns._HEADER_LEN
    _QPROPS = "!HH"
    _QPROPS_LEN = struct.calcsize(_QPROPS)
    
    def __init__(self, question):
        self.question = question
    
    @classmethod
    def parser(cls, buf, qdcount, offset=12):
        pos = 0
        offset_pointer = {}
        question = {}
        for _ in range(qdcount):
            name , _pos, _ = _parse_domain_label(buf[pos:])
            offset_pointer[str(offset + pos)] = name
            pos += _pos
            
            (qtype, qclass) = struct.unpack_from(cls._QPROPS, buf[pos:])
            pos += cls._QPROPS_LEN
            
            question[name] = {
                "qtype": qtype,
                "qclass": qclass
            }
            
        return cls(question), offset_pointer, pos
    
    def serialize(self, _payload=None, _prev=None):
        pass
    
   
class record(object):
    
    _RRPROPS = "!HHIH"
    _RRPROPS_LEN = struct.calcsize(_RRPROPS)
    
    def __init__(self, record) -> None:
        self.record = record
    
    @classmethod
    def parser(cls, buf, count, offset, offset_pointer):
        pos = 0
        record = []
        for i in range(count):
            name , _pos, p = _parse_domain_label(buf[pos:], offset_pointer)
            if not p:
                offset_pointer[str(offset + pos)] = name
            pos += _pos
            
            (rrtype, rrclass, ttl, rdlength) = struct.unpack_from(cls._RRPROPS, buf[pos:])
            pos += cls._RRPROPS_LEN
            
            rdata = _rdata.parser(buf[pos:pos+rdlength], rrtype, rrclass, offset + pos, offset_pointer)
            pos += rdlength
            
            record.append({
                "name": name,
                "type": rrtype,
                "class": rrclass,
                "ttl": ttl,
                "rdlength": rdlength,
                "rdata": rdata
            })
            
            
        return cls(record), offset_pointer, pos
    
    def serialize(self, _payload=None, _prev=None):
        pass


class _rdata(object):
    
    _IPV4_ADDR_STR = "!BBBB"
    
    def __init__(self, rtype, rdata) -> None:
        self.rtype = rtype
        self.rdata = rdata
    
    @classmethod
    def parser(cls, buf, rrtype, rrclass, offset=None, offset_pointer=None):
        if rrtype == 0x01 and rrclass == 0x01:
            ipv4_addr = struct.unpack_from(cls._IPV4_ADDR_STR, buf)
            return cls("ipv4", ".".join([str(i) for i in ipv4_addr]))
        
        if rrtype == 0x05 and rrclass == 0x01:
            cname, _, _ = _parse_domain_label(buf)
            offset_pointer[str(offset)] = cname
            return cls("cname", cname)
    
    def serialize(self, _payload=None, _prev=None):
        pass
    

def _parse_domain_label(buf, offset_pointer=None):
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
    name = []
    while buf[pos] != 0x00:
        if pos == 0 and buf[pos] & 0xc0:
            
            offset = ((buf[pos] & 0x3f) << 8) | (buf[pos+1] & 0xff)
            return offset_pointer[str(offset)], 2, True
        else:    
            length = buf[pos]
            pos += 1
            
            s = struct.unpack_from("!%ds" % length, buf[pos:])[0]
            pos += length
            
            name.append(str(s, encoding='utf-8'))
        
    
    return ".".join(name), pos+1, False
    