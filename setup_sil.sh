#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
DATA_DIR="$ROOT/data"
STAGING_DIR="$ROOT/staging"

BPFFS_DIR="/sys/fs/bpf"
SIL_BPFFS_DIR="/sys/fs/bpf/sil"

CGM_ATTACH_BIN="$ROOT/staging/bin/utils/control_group_monitoring/SIL_CGM_ATTACH"
CGM_LD_BIN="$ROOT/staging/bin/utils/control_group_monitoring/SIL_CGM_LD"

say() {
	printf '[setup] %s\n' "$*"
}

need_root() {
	if [[ "${EUID}" -ne 0 ]]; then
		echo "This operation requires root." >&2
		exit 1
	fi
}

ensure_dir() {
	mkdir -p "$1"
}

create_project_dirs() {
	say "creating project directories"
	ensure_dir "$DATA_DIR/cgm"
	ensure_dir "$DATA_DIR/ps"
	ensure_dir "$DATA_DIR/logs"
	ensure_dir "$DATA_DIR/instances"
	ensure_dir "$DATA_DIR/tmp"

	ensure_dir "$STAGING_DIR/bin/bpf"
	ensure_dir "$STAGING_DIR/bin/opt"
	ensure_dir "$STAGING_DIR/bin/orc"
	ensure_dir "$STAGING_DIR/bin/orc/dp"
	ensure_dir "$STAGING_DIR/bin/orc/cli"
	ensure_dir "$STAGING_DIR/bin/orc/tui"
	ensure_dir "$STAGING_DIR/bin/orc/gui"
	ensure_dir "$STAGING_DIR/bin/utils/control_group_monitoring"
	ensure_dir "$STAGING_DIR/bin/utils/process_snapshot"

	ensure_dir "$STAGING_DIR/obj/bpf"
	ensure_dir "$STAGING_DIR/obj/opt"
	ensure_dir "$STAGING_DIR/obj/orc"
	ensure_dir "$STAGING_DIR/obj/utils/control_group_monitoring"
	ensure_dir "$STAGING_DIR/obj/utils/process_snapshot"
}

fix_bpffs_access() {
	need_root

	# Ensure non-root traversal of bpffs.
	chmod 755 "$BPFFS_DIR" || true

	# Ensure SIL subtree exists and is accessible.
	mkdir -p "$SIL_BPFFS_DIR"
	chmod 755 "$SIL_BPFFS_DIR" || true

	# If invoked via sudo, hand ownership of the SIL subtree back to the user.
	if [[ -n "${SUDO_UID:-}" && -n "${SUDO_GID:-}" ]]; then
		chown "${SUDO_UID}:${SUDO_GID}" "$SIL_BPFFS_DIR"
	fi
}

mount_bpffs_if_needed() {
	need_root

	mkdir -p "$BPFFS_DIR"

	if mountpoint -q "$BPFFS_DIR"; then
		say "bpffs already mounted at $BPFFS_DIR"
	else
		say "mounting bpffs at $BPFFS_DIR"
		mount -t bpf bpf "$BPFFS_DIR"
	fi

	fix_bpffs_access
}

ensure_bpffs_tree() {
	need_root
	mount_bpffs_if_needed
	fix_bpffs_access
}

reset_bpffs_pins() {
	need_root
	mount_bpffs_if_needed

	if [[ -d "$SIL_BPFFS_DIR" ]]; then
		say "removing stale SIL bpffs pins at $SIL_BPFFS_DIR"
		rm -rf "$SIL_BPFFS_DIR"
	fi

	say "recreating $SIL_BPFFS_DIR"
	mkdir -p "$SIL_BPFFS_DIR"

	fix_bpffs_access
}

reset_runtime_data() {
	say "removing runtime instance data"
	rm -rf "$DATA_DIR/instances"
	mkdir -p "$DATA_DIR/instances"

	say "removing runtime tmp files"
	rm -rf "$DATA_DIR/tmp"
	mkdir -p "$DATA_DIR/tmp"

	mkdir -p "$DATA_DIR/cgm" "$DATA_DIR/ps" "$DATA_DIR/logs"
}

grant_cgm_caps() {
	need_root

	if [[ ! -x "$CGM_ATTACH_BIN" ]]; then
		echo "Missing binary: $CGM_ATTACH_BIN" >&2
		exit 1
	fi

	if [[ ! -x "$CGM_LD_BIN" ]]; then
		echo "Missing binary: $CGM_LD_BIN" >&2
		exit 1
	fi

	say "granting file capabilities to CGM binaries"

	# Recent kernels may still require CAP_SYS_ADMIN for some verifier paths
	# even when CAP_BPF + CAP_NET_ADMIN are present.
	setcap cap_sys_admin,cap_net_admin,cap_bpf=ep "$CGM_ATTACH_BIN"

	# Loader for pinned objects/maps.
	setcap cap_bpf=ep "$CGM_LD_BIN"

	say "current capabilities:"
	getcap "$CGM_ATTACH_BIN" "$CGM_LD_BIN" || true
}

clear_cgm_caps() {
	need_root
	say "removing file capabilities from CGM binaries"
	setcap -r "$CGM_ATTACH_BIN" 2>/dev/null || true
	setcap -r "$CGM_LD_BIN" 2>/dev/null || true
}

show_caps() {
	getcap "$CGM_ATTACH_BIN" "$CGM_LD_BIN" 2>/dev/null || true
}

usage() {
	cat <<EOF
Usage:
  ./setup_sil.sh init
  sudo ./setup_sil.sh init-root
  sudo ./setup_sil.sh grant-cgm-caps
  sudo ./setup_sil.sh clear-cgm-caps
  ./setup_sil.sh show-cgm-caps
  sudo ./setup_sil.sh reset-pins
  ./setup_sil.sh reset-runtime

Commands:
  init            create repo-local data/staging directories
  init-root       create dirs and ensure bpffs + /sys/fs/bpf/sil exist
  grant-cgm-caps  assign CAP_BPF/CAP_NET_ADMIN to exact CGM binaries
  clear-cgm-caps  remove CGM file capabilities
  show-cgm-caps   display current file capabilities
  reset-pins      remove stale pinned BPF state under /sys/fs/bpf/sil
  reset-runtime   remove runtime instance/tmp data under ./data
EOF
}

main() {
	cmd="${1:-}"

	case "$cmd" in
		init)
			create_project_dirs
			say "done"
			;;
		init-root)
			create_project_dirs
			ensure_bpffs_tree
			say "done"
			;;
		grant-cgm-caps)
			grant_cgm_caps
			say "done"
			;;
		clear-cgm-caps)
			clear_cgm_caps
			say "done"
			;;
		show-cgm-caps)
			show_caps
			;;
		reset-pins)
			reset_bpffs_pins
			say "done"
			;;
		reset-runtime)
			reset_runtime_data
			say "done"
			;;
		*)
			usage
			exit 1
			;;
	esac
}

main "$@"
