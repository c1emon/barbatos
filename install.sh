#!/usr/bin/env sh

set -e

SERVICE_NAME="ryu-app.service"
PIP_SRC="-i https://pypi.tuna.tsinghua.edu.cn/simple"

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

install_dependencies() {
    $SURUN 'apt update >/dev/null'
    $SURUN 'apt -y upgrade >/dev/null'
    $SURUN 'apt -y install python3-pip redis >/dev/null's
}

install_ovs() {
    $SURUN 'apt -y install openvswitch-switch >/dev/null'
}

install_ruy() {
	# bug fix: 
	# ImportError: cannot import name 'ALREADY_HANDLED' from 'eventlet.wsgi' (/usr/local/lib/python3.8/dist-packages/eventlet/wsgi.py)
	$SURUN "pip3 install -r requirements.txt $PIP_SRC >/dev/null"
    echo "Ryu sdn controller installed"
    $SURUN "cp -r ./ryu_app /etc"
}

create_service() {

    echo "Create service ${SERVICE_NAME}"
    
    SERVICE=$(cat <<- EOF
[Unit]
Description=RYU APP
After=network.target

[Service]
Type=simple
Restart=on-failure

ExecStart=ryu-manager /etc/ryu_app/traffic_processor.py
ExecReload=/bin/kill -s HUP $MAINPID
KillMode=process
TimeoutStopSec=5


[Install]
WantedBy=multi-user.target
EOF
)
$SURUN "echo '$SERVICE' >> /lib/systemd/system/${SERVICE_NAME}"
    
    echo "Enable the service by systemctl enable ${SERVICE_NAME} && systemctl start ${SERVICE_NAME}"
}

case "$ACTION" in
    0)
        install_dependencies
        install_ovs
        install_ruy
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
