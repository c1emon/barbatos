# Barbatos
A traffic controller/proxy based on openvswitch and ryu controller.
## network architecture
![network_arch](https://github.com/lexsaints/powershell/blob/master/doc/network_arch.svg)
Traffic between hosts to be proxied and two gateways should all go through the openflow switch. By this way, controller can rule those tarffic.

## require
1. [ryu sdn controller](https://ryu-sdn.org/) runs on a host
2. openflow switch such as [openvswitch](https://www.openvswitch.org/)
3. a proxy gateway such as calsh in tproxy mode 


## run
1. clone this repo and `cd` to the dictory
2. run `ryu-manager traffic_processor.py`
3. run gateways
4. make your switch connect to this controller
5. enjoy it!
