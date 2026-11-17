#!/bin/bash
# Install or remove tuxchange.service. Re-run after updating the checkout.
# The code is copied because a root service must not run files a desktop user can edit.
set -euo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)
UNIT=/etc/systemd/system/tuxchange.service
DEFAULTS=/etc/default/tuxchange
POLKIT=/etc/polkit-1/rules.d/50-tuxchange.rules
DESKTOP=/usr/share/applications/tuxchange-gui.desktop
KEYDIR=/etc/tuxchange
HOOKS=/etc/tuxchange-hooks
LIB=/opt/tuxchange
STATE=/var/lib/tuxchange
RELAY_ENV=$STATE/relay.env
GUI_USER=${SUDO_USER:-${GUI_USER:-}}
PY=$(command -v python3 || true)
# Owners allowed to control anything the service runs or writes through.
TRUSTED_UIDS=0

die() { echo "$*" >&2; exit 1; }
need_root() { [ "$(id -u)" -eq 0 ] || die "needs root; re-run with sudo."; }

# True if a trusted owner holds this one entry and, unless it is a symlink, nobody else can write it.
owned_safely() {
  local st uid mode u
  st=$(stat -c '%u %a' -- "$1") || return 1
  uid=${st%% *}
  mode=${st#* }
  if [ ! -L "$1" ] && (( (8#$mode & 8#022) != 0 )); then return 1; fi
  for u in $TRUSTED_UIDS; do [ "$uid" = "$u" ] && return 0; done
  return 1
}

# Prints where an absolute path leads, if only a trusted owner can change any part of the way:
# every directory passed through, every symlink, and every path a symlink names in turn. Parts that
# do not exist yet are fine, as only a trusted owner can create them under the last one that does.
trusted_path() {
  local cur=/ next comp target hops=0
  local -a todo more
  case "$1" in /*) ;; *) return 1 ;; esac
  case "$1" in *$'\n'*) return 1 ;; esac
  owned_safely / || return 1
  IFS=/ read -ra todo <<< "${1#/}"
  while [ ${#todo[@]} -gt 0 ]; do
    comp=${todo[0]}
    todo=("${todo[@]:1}")
    case "$comp" in
      ''|.) continue ;;
      ..) cur=$(dirname "$cur"); continue ;;
    esac
    next=${cur%/}/$comp
    if [ -L "$next" ]; then
      hops=$((hops + 1))
      [ "$hops" -le 40 ] || return 1
      owned_safely "$next" || return 1
      target=$(readlink -- "$next") || return 1
      case "$target" in ''|*$'\n'*) return 1 ;; /*) cur=/ ;; esac
      IFS=/ read -ra more <<< "${target#/}"
      todo=("${more[@]}" "${todo[@]}")
    elif [ -e "$next" ]; then
      owned_safely "$next" || return 1
      cur=$next
    else
      cur=$next
    fi
  done
  printf '%s\n' "$cur"
}

# These are written into the unit and desktop file, so keep them to characters sed and systemd
# take literally.
plain_path() { [[ $1 =~ ^/[A-Za-z0-9_./+-]*$ ]]; }

# The last SP_STORE an environment file sets, or nothing.
env_store() {
  [ -f "$1" ] || return 0
  sed -n 's/^[[:space:]]*SP_STORE=//p' "$1" | tail -n 1 | sed -e 's/^"\(.*\)"$/\1/' -e "s/^'\(.*\)'$/\1/"
}

# The directory the running service was started in, if it is running.
running_root() {
  local pid
  pid=$(systemctl show -p MainPID --value tuxchange.service 2>/dev/null) || return 0
  [ -n "$pid" ] && [ "$pid" != 0 ] || return 0
  readlink "/proc/$pid/cwd" 2>/dev/null || true
}

# Everything that can be checked before the first change.
preflight() {
  local c d store
  need_root
  for c in systemctl systemd-analyze install sed stat readlink find mktemp getent date cp mv cut; do
    command -v "$c" >/dev/null || die "missing $c, which the installer needs."
  done
  [ -f "$HERE/tuxchange.service.in" ] || die "missing tuxchange.service.in"
  for d in tuxchange gui scripts; do
    [ -d "$ROOT/$d" ] || die "missing $ROOT/$d"
  done
  if [ -z "$PY" ] || ! plain_path "$PY" || ! trusted_path "$PY" >/dev/null; then
    echo "python3 (${PY:-not found}) can be changed by a non-root user, and the service runs as root." >&2
    die "Install python3 from your distribution and re-run."
  fi
  if [ -n "$GUI_USER" ]; then
    [[ $GUI_USER =~ ^[A-Za-z_][A-Za-z0-9_.-]*$ ]] && getent passwd "$GUI_USER" >/dev/null \
      || die "GUI user '$GUI_USER' is not a user on this system."
  fi
  plain_path "$LIB" || die "$LIB is not a plain absolute path."
  for d in "$LIB" "$UNIT" "$DEFAULTS" "$KEYDIR" "$HOOKS" "$STATE" "$POLKIT" "$DESKTOP"; do
    trusted_path "$d" >/dev/null \
      || die "$d, or a directory on the way to it, can be changed by a non-root user. Fix that and re-run."
  done
  store=$(env_store "$DEFAULTS")
  if [ -n "$(env_store "$RELAY_ENV")" ]; then store=$(env_store "$RELAY_ENV"); fi
  STORE_PATH=${store:-$STATE}
  if ! plain_path "$STORE_PATH" || ! trusted_path "$STORE_PATH" >/dev/null; then
    echo "SP_STORE=$STORE_PATH can be changed by a non-root user, and the service writes there as root." >&2
    die "Set SP_STORE in $DEFAULTS to a root-owned directory such as $STATE, then re-run."
  fi
}

RELEASE=
BACKUP=
PENDING=
PUBLISHED=()

# Copies regular files only, so a symlink in the checkout cannot lead root back to user files.
# Each install gets a new directory, so a running service keeps the tree it started from.
stage_code() {
  local list f mode
  local -a files
  install -d -o root -g root -m 0755 "$LIB"
  RELEASE=$(mktemp -d "$LIB/release-$(date +%Y%m%d%H%M%S)-XXXXXX")
  list=$RELEASE/.files
  (cd "$ROOT" && find tuxchange gui scripts -type f ! -path '*/__pycache__/*' -print0) > "$list" \
    || die "could not list the files in $ROOT"
  mapfile -d '' files < "$list"
  rm -f "$list"
  for f in "${files[@]}"; do
    mode=0644
    [ -x "$ROOT/$f" ] && mode=0755
    install -D -o root -g root -m "$mode" "$ROOT/$f" "$RELEASE/$f"
  done
  chmod 0755 "$RELEASE"
}

# Moves a finished file into place, keeping what it replaces until the install succeeds.
publish() {
  local src=$1 dest=$2 tmp
  [ -n "$BACKUP" ] || BACKUP=$(mktemp -d "$LIB/.backup-XXXXXX")
  if [ -e "$dest" ]; then
    cp -p -- "$dest" "$BACKUP/${#PUBLISHED[@]}"
  fi
  PUBLISHED+=("$dest")
  tmp=$(mktemp "$dest.XXXXXX")
  PENDING=$tmp
  install -o root -g root -m 0644 "$src" "$tmp"
  mv -f -- "$tmp" "$dest"
  PENDING=
}

rollback() {
  local i dest
  for i in "${!PUBLISHED[@]}"; do
    dest=${PUBLISHED[$i]}
    if [ -e "$BACKUP/$i" ]; then
      mv -f -- "$BACKUP/$i" "$dest" || echo "could not restore $dest" >&2
    else
      rm -f -- "$dest"
    fi
  done
  [ ${#PUBLISHED[@]} -eq 0 ] || systemctl daemon-reload || true
  [ -z "$RELEASE" ] || rm -rf -- "$RELEASE"
  [ -z "$BACKUP" ] || rm -rf -- "$BACKUP"
  [ -z "$PENDING" ] || rm -f -- "$PENDING"
}

on_install_exit() {
  local rc=$?
  [ "$rc" -eq 0 ] && return 0
  trap - EXIT
  rollback
  echo "INSTALL FAILED; the previous installation, if any, is unchanged." >&2
  exit "$rc"
}

# Removes other releases, the old flat layout and backups, but never the tree the running service
# was started from.
prune() {
  local live d
  live=$(running_root)
  live=${live% (deleted)}
  for d in "$LIB"/release-*; do
    [ -d "$d" ] || continue
    [ "$d" = "$RELEASE" ] || [ "$d" = "$live" ] || rm -rf -- "$d"
  done
  if [ "$live" != "$LIB" ]; then
    rm -rf -- "${LIB:?}/tuxchange" "${LIB:?}/gui" "${LIB:?}/scripts"
  fi
  rm -rf -- "$BACKUP"
}

write_defaults() {
  cat <<EOF
# Tunables for tuxchange.service. Edit here, then: systemctl restart tuxchange
# Empty picks an adapter that supports active monitor, preferring ath9k, else an unconnected
# adapter for mixed mode.
SP_IFACE=
# auto, active or mixed. Mixed mode suits adapters without active monitor support.
SP_MODE=auto
SP_MON=mon0
SP_STORE=$STATE
SP_CHANNELS=1,6,11
SP_WINDOW=180
SP_IDLE=2
# Extra arguments passed straight to \`sp_relay.py run\`, e.g.
#   SP_EXTRA=--exchange-gap 300 --keep-runs 100
# --rotate-identity presents a new MAC per exchange, which no real console can do and which
# defeats the peer's own rate limit. Leave it off unless you mean it.
SP_EXTRA=
EOF
}

do_install() {
  local f k user_cfg out
  preflight
  trap on_install_exit EXIT

  stage_code
  sed -e "s|__ROOT__|$RELEASE|g" -e "s|__PY__|$PY|g" -e "s|__GUI_USER__|$GUI_USER|g" \
      "$HERE/tuxchange.service.in" > "$RELEASE/tuxchange.service"
  if ! out=$(systemd-analyze verify "$RELEASE/tuxchange.service" 2>&1); then
    printf '%s\n' "$out" >&2
    die "systemd rejected the generated unit."
  fi
  [ -z "$out" ] || printf '%s\n(verify emitted the above)\n' "$out"

  install -d -o root -g root -m 0755 "$STATE"
  # Event hook scripts. Not /etc/tuxchange as that is 0700 for keys etc, and hooks run as the desktop user.
  install -d -o root -g root -m 0755 "$HOOKS"
  for f in "$HERE"/hooks/*.example; do
    if [ -f "$f" ] && [ ! -L "$f" ]; then
      install -o root -g root -m 0644 "$f" "$HOOKS/$(basename "$f")"
    fi
  done

  if [ ! -e "$DEFAULTS" ]; then
    write_defaults > "$RELEASE/defaults"
    publish "$RELEASE/defaults" "$DEFAULTS"
    echo "wrote $DEFAULTS"
  else
    echo "kept the existing $DEFAULTS"
  fi

  # Lets the GUI start, stop and restart this one unit without a stored password.
  if [ -n "$GUI_USER" ] && [ -d "$(dirname "$POLKIT")" ] && [ -f "$HERE/50-tuxchange.rules.in" ]; then
    sed -e "s|__GUI_USER__|$GUI_USER|g" "$HERE/50-tuxchange.rules.in" > "$RELEASE/polkit.rules"
    publish "$RELEASE/polkit.rules" "$POLKIT"
    echo "wrote $POLKIT  (lets $GUI_USER manage only tuxchange.service)"
  else
    echo "NOTE: no polkit rule written; the GUI will need a polkit agent to start/stop the service"
  fi

  if [ -f "$HERE/tuxchange-gui.desktop.in" ] && [ -d "$(dirname "$DESKTOP")" ]; then
    sed -e "s|__ROOT__|$RELEASE|g" -e "s|__PY__|$PY|g" -e "s|__STORE__|$STORE_PATH|g" \
        "$HERE/tuxchange-gui.desktop.in" > "$RELEASE/tuxchange-gui.desktop"
    publish "$RELEASE/tuxchange-gui.desktop" "$DESKTOP"
    echo "wrote $DESKTOP  (menu entry for the GUI)"
  fi

  # The service runs as root, so it reads keys from /etc/tuxchange.
  install -d -o root -g root -m 0700 "$KEYDIR"
  chmod 0700 "$KEYDIR"
  if [ -n "$GUI_USER" ]; then
    user_cfg=$(getent passwd "$GUI_USER" | cut -d: -f6)/.config/tuxchange
    for k in aes_keys.txt tuxchange.keys; do
      if [ -f "$user_cfg/$k" ] && [ ! -f "$KEYDIR/$k" ]; then
        install -m 0600 -o root -g root "$user_cfg/$k" "$KEYDIR/$k"
        echo "copied $k into $KEYDIR (the service runs as root and cannot read \$HOME)"
      fi
    done
  fi
  if [ ! -f "$KEYDIR/aes_keys.txt" ]; then
    echo "WARNING: no $KEYDIR/aes_keys.txt, so the daemon cannot derive a link key."
    echo "      See the wiki page \"Getting your keys\"."
  fi

  publish "$RELEASE/tuxchange.service" "$UNIT"
  systemctl daemon-reload
  systemctl enable tuxchange.service
  trap - EXIT

  prune || echo "NOTE: could not remove every old copy under $LIB" >&2
  if command -v update-desktop-database >/dev/null; then
    update-desktop-database -q 2>/dev/null || true
  fi
  echo
  echo "INSTALLED to $RELEASE."
  if [ -n "$(running_root)" ]; then
    echo "The running service still uses the previous copy until: sudo systemctl restart tuxchange"
  fi
  echo "To start tuxchange from CLI:"
  echo "  sudo systemctl start tuxchange      # or: sudo $0 start"
  echo "  systemctl status tuxchange"
  echo "  journalctl -u tuxchange -f"
}

do_uninstall() {
  need_root
  systemctl disable --now tuxchange.service 2>/dev/null || true
  rm -f "$UNIT" "$POLKIT" "$DESKTOP"
  rm -rf "${LIB:?}"
  systemctl daemon-reload
  if command -v update-desktop-database >/dev/null; then
    update-desktop-database -q 2>/dev/null || true
  fi
  echo "removed $UNIT, $POLKIT, $DESKTOP and $LIB"
  echo "left alone: $DEFAULTS, $KEYDIR (your keys) and the store in $STATE"
}

main() {
  case "${1:-}" in
  install) do_install ;;
  uninstall) do_uninstall ;;
  start|stop|restart|status)
    need_root
    systemctl "$1" tuxchange.service
    ;;
  logs)
    journalctl -u tuxchange -n "${2:-60}" --no-pager
    ;;
  *)
    die "usage: install.sh {install|uninstall|start|stop|restart|status|logs [n]}" ;;
  esac
}

# The self-test sources this file to point it at a fake root.
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  main "$@"
fi
