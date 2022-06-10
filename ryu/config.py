import yaml
from hosts import *
from netaddr import IPNetwork

class conf(object):
    def __init__(self, path) -> None:
        self._path = path
        self.proxy_hosts = []
        self.default_gateway = None
        self.proxy_gateway = None
        self.read_config()
        
        self._proxy_ips = []
        self._proxy_macs = []
        for host in self.proxy_hosts:
            if host.ip:
                self._proxy_ips.append(host.ip)
            else:
                self._proxy_macs.append(host.mac)
    
    def read_config(self):
        with open(self._path, 'r') as f:
            conf = yaml.safe_load(f)
        for h in conf["host"]:
            self.proxy_hosts.append(host(**h))
        self.default_gateway = host(**conf["default_gateway"][0])
        self.proxy_gateway = host(**conf["proxy_gateway"][0])
        
        if "redis" in conf.keys():
            self._redis_ip = conf['redis']['ip'] if "ip" in conf['redis'].keys() else "127.0.0.1"
            self._redis_port = int(conf['redis']['port']) if "port" in conf['redis'].keys() else 6379
        else:
            self._redis_ip = "127.0.0.1"
            self._redis_port = 6379
            
        _fakeip = conf['fakeIpRange'] if "fakeIpRange" in conf.keys() else "198.18.0.0/16"
        self._fakeip = IPNetwork(_fakeip)
        
        
    @property 
    def proxy_ips(self):
        return self._proxy_ips
    
    @property
    def proxy_macs(self):
        return self._proxy_macs
    
    @property
    def redis_ip(self):
        return self._redis_ip
    
    @property
    def redis_port(self):
        return self._redis_port
    
    @property
    def fakeip(self):
        self._fakeip
        
    def __str__(self):
        s = "default gateway %s\nproxy   gateway %s\nproxy hosts:\n" % (self.default_gateway, self.proxy_gateway)
        for h in self.proxy_hosts:
            s += ("%s\n" % h)
        return s
        