from netaddr import IPAddress, EUI, mac_unix_expanded
import uuid

class host(object):
    def __init__(self, ip=None, mac=None, name=None) -> None:
        assert ip or mac
        
        self._ip = IPAddress(ip) if ip else ''
        self._mac = EUI(mac, dialect=mac_unix_expanded) if mac else ''
            # self._mac.dialect = mac_unix_expanded
        self._name = name if name else str(uuid.uuid4()).replace('-', '')[0:12]
        
    @property
    def mac(self):
        return "%s" % self._mac
    
    @property
    def ip(self):
        return "%s" % self._ip
    
    @property
    def name(self):
        return self.name
    
    def __str__(self) -> str:
        return "%s: [ip:%s    mac:%s]" % (self._name, self._ip, self._mac)