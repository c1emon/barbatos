#!/usr/bin/env sh

PIP_SRC="-i https://pypi.tuna.tsinghua.edu.cn/simple"

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

command_exists() {
	command -v "$@" > /dev/null 2>&1
}

user="$(id -un 2>/dev/null || true)"

sh_c='sh -c'
if [ "$user" != 'root' ]; then
    if command_exists sudo; then
        sh_c='sudo -E sh -c'
    elif command_exists su; then
        sh_c='su -c'
    else
        echo "err"
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
	sh_c="echo"
fi

install_dependencies() {
    $sh_c 'apt-get install -y curl >/dev/null'
}

install_ovs() {
    $sh_c 'apt-get install -y openvswitch-switch >/dev/null'
}

install_ruy() {
    $sh_c "pip3 install ryu $PIP_SRC >/dev/null"
}

install_dependencies
