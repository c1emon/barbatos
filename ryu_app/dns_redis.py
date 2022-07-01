import redis
import json

class dns_redis(object):
    def __init__(self, host='127.0.0.1', port=6379):
        self.r = redis.StrictRedis(host=host, port=port, db=0, decode_responses=True)
        
    def set(self, k, v, ttl=300):
        self.r.set(k, json.dumps(v), ex=ttl)
        
    def get(self, k):
        v = self.r.get(k)
        return json.loads(v) if v else None
    
    
if __name__ == "__main__":
    dr = dns_redis("192.168.88.90")
    # dr.set("0x12", {"src":"192.168.88.123", "dst": "192.168.88.254"})
    # dr.set("0x13", {"src":"192.168.88.123", "dst": "192.168.88.254"})
    dr.set("0x14", {"src":"192.168.88.123", "dst": "192.168.88.254"})
    print(dr.get("0x14"))
    print(dr.get("0x14"))
    
    