#!/usr/bin/env sh

set -e

CLASH_URL="https://github.com/Dreamacro/clash/releases/download/premium/clash-linux-amd64-2022.03.21.gz"
USER="clash"
CLASH_PATH="/etc/clash"
CLASH_EXEC="/usr/local/bin/clash"

DRY_RUN=${DRY_RUN:-}
while [ $# -gt 0 ]; do
	case "$1" in
		--dry-run)
			DRY_RUN=1
			;;
		--*)
			echo "Illegal option $1"
			;;
	esac
	shift $(( $# > 0 ? 1 : 0 ))
done

is_dryrun() {
	if [ -z "$DRY_RUN" ]; then
		return 1
	else
		return 0
	fi
}

cmd_exists() {
	command -v "$@" > /dev/null 2>&1
}

RUN="sh -c"
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

if is_dryrun; then
	RUN="echo"
    SURUN="echo sudo"
fi

install_clash() {
    PKG="/tmp/clash-linux-amd64.gz"
    $RUN "wget $CLASH_URL -O $PKG"
    $RUN "gzip -d $PKG"
    $SURUN "mv \"/tmp/clash-linux-amd64-2022.03.21\" $CLASH_EXEC"
    $RUN "chmod +x $CLASH_EXEC"
    $SURUN "mkdir $CLASH_PATH"
    $SURUN "cp iptables.sh $CLASH_PATH"
}

add_user() {
    $SURUN "useradd -M -s /usr/sbin/nologin $USER"
}

# nft_tproxy() {
#     chmod +x ./iptables.sh
#     ./iptables.sh
# }

create_service() {

SERVICE_PATH="/lib/systemd/system/clash.service"

SERVICE=$(cat <<- EOF
[Unit]
Description=Clash TProxy
After=network.target

[Service]
Type=simple
User=$USER
Group=$USER
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
Restart=on-failure

ExecStartPre=+/usr/bin/sh $CLASH_PATH/iptables.sh clean
ExecStart=$CLASH_EXEC -d $CLASH_PATH
ExecStartPost=+/usr/bin/sh $CLASH_PATH/iptables.sh set

ExecStopPost=+/usr/bin/sh $CLASH_PATH/iptables.sh clean

[Install]
WantedBy=multi-user.target
EOF
)
$SURUN "echo '$SERVICE' >> $SERVICE_PATH"
}

run() {
    $SURUN "-u $USER $CLASH_EXEC -d $CLASH_PATH"
}

run