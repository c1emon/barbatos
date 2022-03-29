#!/usr/bin/env sh

set -e

while [ $# -gt 0 ]; do
	case "$1" in
		--dry-run)
			DRY_RUN=1
			;;
        --clean)
            CLEAN=1
            ;;
        --set)
            SET=1
            ;;
		--*)
			echo "Illegal option $1"
			;;
	esac
	shift $(( $# > 0 ? 1 : 0 ))
done

cmd_exists() {
	command -v "$@" > /dev/null 2>&1
}

SURUN="sudo -E sh -c"
if [ "$(id -un 2>/dev/null || true)" != 'root' ]; then
    if cmd_exists sudo; then
        SURUN='sudo -E sh -c'
    elif cmd_exists su; then
        SURUN='su -c'
    else
        echo "insufficient permissions"
        exit 1
    fi
fi

is_dry_run() {
	if [ -z "$DRY_RUN" ]; then
		return 1
	else
		return 0
	fi
}

if is_dry_run; then
	SURUN="echo sudo"
fi

set_ipt() {
    # ENABLE ipv4 forward
    $SURUN "sysctl -w net.ipv4.ip_forward=1"

    # ROUTE RULES
    $SURUN "ip rule add fwmark 666 lookup 666"
    $SURUN "ip route add local 0.0.0.0/0 dev lo table 666"

    # clash 链负责处理转发流量 
    $SURUN "iptables -t mangle -N clash"

    # 目标地址为局域网或保留地址的流量跳过处理
    # 保留地址参考: https://zh.wikipedia.org/wiki/%E5%B7%B2%E5%88%86%E9%85%8D%E7%9A%84/8_IPv4%E5%9C%B0%E5%9D%80%E5%9D%97%E5%88%97%E8%A1%A8
    $SURUN "iptables -t mangle -A clash -d 0.0.0.0/8 -j RETURN"
    $SURUN "iptables -t mangle -A clash -d 127.0.0.0/8 -j RETURN"
    $SURUN "iptables -t mangle -A clash -d 10.0.0.0/8 -j RETURN"
    $SURUN "iptables -t mangle -A clash -d 172.16.0.0/12 -j RETURN"
    $SURUN "iptables -t mangle -A clash -d 192.168.0.0/16 -j RETURN"
    $SURUN "iptables -t mangle -A clash -d 169.254.0.0/16 -j RETURN"

    $SURUN "iptables -t mangle -A clash -d 224.0.0.0/4 -j RETURN"
    $SURUN "iptables -t mangle -A clash -d 240.0.0.0/4 -j RETURN"

    # 其他所有流量转向到 7893 端口，并打上 mark
    $SURUN "iptables -t mangle -A clash -p tcp -j TPROXY --on-port 7893 --tproxy-mark 666"
    $SURUN "iptables -t mangle -A clash -p udp -j TPROXY --on-port 7893 --tproxy-mark 666"

    # 转发所有 DNS 查询到 1053 端口
    # 此操作会导致所有 DNS 请求全部返回虚假 IP(fake ip 198.18.0.1/16)
    $SURUN "iptables -t nat -I PREROUTING -p udp --dport 53 -j REDIRECT --to 1053"

    # 如果想要 dig 等命令可用, 可以只处理 DNS SERVER 设置为当前内网的 DNS 请求
    #iptables -t nat -I PREROUTING -p udp --dport 53 -d 192.168.0.0/16 -j REDIRECT --to 1053

    # 最后让所有流量通过 clash 链进行处理
    $SURUN "iptables -t mangle -A PREROUTING -j clash"
}

set_ipt_local() {
    # clash_local 链负责处理网关本身发出的流量
    $SURUN "iptables -t mangle -N clash_local"
    
    # 跳过内网流量
    $SURUN "iptables -t mangle -A clash_local -d 0.0.0.0/8 -j RETURN"
    $SURUN "iptables -t mangle -A clash_local -d 127.0.0.0/8 -j RETURN"
    $SURUN "iptables -t mangle -A clash_local -d 10.0.0.0/8 -j RETURN"
    $SURUN "iptables -t mangle -A clash_local -d 172.16.0.0/12 -j RETURN"
    $SURUN "iptables -t mangle -A clash_local -d 192.168.0.0/16 -j RETURN"
    $SURUN "iptables -t mangle -A clash_local -d 169.254.0.0/16 -j RETURN"
    
    $SURUN "iptables -t mangle -A clash_local -d 224.0.0.0/4 -j RETURN"
    $SURUN "iptables -t mangle -A clash_local -d 240.0.0.0/4 -j RETURN"
    
    # 为本机发出的流量打 mark
    $SURUN "iptables -t mangle -A clash_local -p tcp -j MARK --set-mark 666"
    $SURUN "iptables -t mangle -A clash_local -p udp -j MARK --set-mark 666"
    
    # 跳过 clash 程序本身发出的流量, 防止死循环(clash 程序需要使用 "clash" 用户启动)
    $SURUN "iptables -t mangle -A OUTPUT -p tcp -m owner --uid-owner clash -j RETURN"
    $SURUN "iptables -t mangle -A OUTPUT -p udp -m owner --uid-owner clash -j RETURN"
    
    # 让本机发出的流量跳转到 clash_local
    # clash_local 链会为本机流量打 mark, 打过 mark 的流量会重新回到 PREROUTING 上
    $SURUN "iptables -t mangle -A OUTPUT -j clash_local"
}

set_ipt_fake_icmp() {
    # 修复 ICMP(ping)
    # 这并不能保证 ping 结果有效(clash 等不支持转发 ICMP), 只是让它有返回结果而已
    # --to-destination 设置为一个可达的地址即可
    $SURUN "sysctl -w net.ipv4.conf.all.route_localnet=1"
    $SURUN "iptables -t nat -A PREROUTING -p icmp -d 198.18.0.0/16 -j DNAT --to-destination 127.0.0.1"
}

cleanup() {
    $SURUN "sysctl -w net.ipv4.ip_forward=0"
    $SURUN "sysctl -w net.ipv4.conf.all.route_localnet=0"

    $SURUN "ip rule del fwmark 666 table 666 || true"
    $SURUN "ip route del local 0.0.0.0/0 dev lo table 666 || true"

    $SURUN "iptables -t nat -F"
    $SURUN "iptables -t nat -X"
    $SURUN "iptables -t mangle -F"
    $SURUN "iptables -t mangle -X clash || true"

    $SURUN "iptables -t mangle -X clash_local || true"
}
