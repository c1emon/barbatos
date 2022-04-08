from netaddr import IPAddress

def is_public(ip):
    ip = IPAddress(ip)
    return ip.is_unicast() and not ip.is_private()