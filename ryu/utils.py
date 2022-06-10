from tkinter.messagebox import NO
from netaddr import IPAddress, IPSet

PRIVATE_IPS = IPSet([
    "192.168.0.0/16",
    "0.0.0.0/8",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "169.254.0.0/16",
    "224.0.0.0/4",
    "240.0.0.0/4"
])

FAKEIP_RANGE = None

def is_public(ip):
    ip = IPAddress(ip)
    return ip.is_unicast() and not ip.is_private()

def set_fakeip(ip):
    FAKEIP_RANGE = ip

def is_fakeip(ip, r):
    ip = IPAddress(ip)
    return ip in r

def is_private(ip):
    return IPAddress(ip).is_private()

# print(str(PRIVATE_IPS.iter_cidrs()[0]))