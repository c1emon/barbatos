from threading import local
import yaml
from host import *
from netaddr import IPNetwork
from pathlib import Path

def _path_adapter(name, path):
    _path = Path.cwd() if Path.cwd().joinpath(name).is_file() else Path(path)
    conf_path = _path.joinpath(name)
    return str(conf_path)
    
class conf(object):
    def __init__(self, name="barbatos.yaml", path="/etc/ryu_app") -> None:
        self._path = _path_adapter(name, path)
        
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
        
        _redis_conf = conf.get("redis", {"ip": "127.0.0.1", "port": 6379})
        self._redis_ip = str(_redis_conf.get("ip", "127.0.0.1"))
        self._redis_port = int(_redis_conf.get("port", 6379))
        
        self._fakeip = IPNetwork(conf.get('fakeIpRange', "198.18.0.0/16"))
        
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
        return self._fakeip
        
    def __str__(self):
        return ("default gateway: %s\n" + \
             "proxy   gateway: %s\n" + \
             "proxy     hosts: %s\n" + \
             "redis: %s") % (self.default_gateway, self.proxy_gateway, " ".join(self.proxy_hosts), "%s:%s" % (self._redis_ip, self._redis_port))
