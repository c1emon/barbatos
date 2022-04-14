from tkinter.messagebox import NO
import yaml
from hosts import *

class conf(object):
    def __init__(self, path) -> None:
        self._path = path
        self.proxy_hosts = []
        self.default_gateway = None
        self.proxy_gateway = None
        self.read_config()
    
    def read_config(self):
        with open(self._path, 'r') as f:
            conf = yaml.safe_load(f)
        for h in conf["host"]:
            self.proxy_hosts.append(host(**h))
        self.default_gateway = host(**conf["default_gateway"][0])
        self.proxy_gateway = host(**conf["proxy_gateway"][0])
        
    def __str__(self):
        s = "default gateway %s\nproxy   gateway %s\nproxy hosts:\n" % (self.default_gateway, self.proxy_gateway)
        for h in self.proxy_hosts:
            s += ("%s\n" % h)
        return s
        