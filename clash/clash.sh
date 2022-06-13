#!/usr/bin/env sh

set -e

CLASH_URL="https://github.com/Dreamacro/clash/releases/download/premium/clash-linux-amd64-2022.03.21.gz"
USER="clash"
CLASH_PATH="/etc/clash"
CLASH_EXEC="/usr/local/bin/clash"

SERVICE_NAME="clash.service"
ACTION=0
DRY_RUN=${DRY_RUN:-}
while [ $# -gt 0 ]; do
	case "$1" in
		--dry-run)
			DRY_RUN=1
			;;
        install)
			ACTION=0
			;;
        run)
            ACTION=1
            ;;
        uninstall)
            ACTION=2
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
    echo "Start install clash"
    if [ -f "clash" ]; then
        echo "Find clash exists locally, just move to $CLASH_EXEC"
        $SURUN "cp ./clash $CLASH_EXEC"
    else
        echo "Download clash..."
        PKG="/tmp/clash-linux-amd64.gz"
        $RUN "wget $CLASH_URL -O $PKG"
        $RUN "gzip -d $PKG"
        $SURUN "mv \"/tmp/clash-linux-amd64-2022.03.21\" $CLASH_EXEC"
    fi
    
    $RUN "chmod +x $CLASH_EXEC"
    $SURUN "mkdir $CLASH_PATH"
    $SURUN "cp iptables.sh $CLASH_PATH"
}

add_user() {
    echo "Add user 'clash'"
    $SURUN "useradd -M -s /usr/sbin/nologin $USER"
    $SURUN "chown -R $USER $CLASH_PATH"
}

# nft_tproxy() {
#     chmod +x ./iptables.sh
#     ./iptables.sh
# }

create_service() {

    echo "Create service for clash"
    
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
ExecReload=/bin/kill -s HUP \$MAINPID
ExecStop=/bin/kill -s HUP \$MAINPID
KillMode=process
TimeoutStopSec=5
ExecStopPost=+/usr/bin/sh $CLASH_PATH/iptables.sh clean

[Install]
WantedBy=multi-user.target
EOF
)
$SURUN "echo '$SERVICE' >> /lib/systemd/system/${SERVICE_NAME}"

    echo "Enable the service by systemctl enable ${SERVICE_NAME} && systemctl start ${SERVICE_NAME}"
    
}

run() {
    $SURUN "setcap 'cap_net_admin,cap_net_bind_service=+ep' $CLASH_EXEC"
    $SURUN "$CLASH_EXEC -d $CLASH_PATH"
}

uninstall() {
    echo "Uninstall clash"
    $SURUN "rm -rf $CLASH_EXEC"
    $SURUN "rm -rf $CLASH_PATH"
    echo "Remove service of clash"
    $SURUN "systemctl stop clash"
    $SURUN "systemctl disable clash"
    $SURUN "rm -rf $SERVICE_PATH"
}

case "$ACTION" in
    0)
        install_clash
        add_user
        create_service
        echo "Done!"
        ;;
    1)
        run
        ;;
    2)
        uninstall
        echo "Done!"
        ;;
    *)
        echo "Illegal option $ACTION"
        ;;
esac
