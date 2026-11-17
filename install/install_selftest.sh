#!/bin/bash
# Runs install.sh against a fake root with fake systemctl, systemd-analyze and install, as an
# ordinary user. Nothing outside a temporary directory is touched.
set -euo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REAL_INSTALL=$(command -v install)
FAILS=0

base=$(mktemp -d "${INSTALL_TEST_DIR:-$HOME}/.tuxchange-install-test.XXXXXX")
trap 'rm -rf "$base"' EXIT
chmod 0755 "$base"

# The fake root stands in for root-owned paths, so its owner is trusted here, but its parents must
# still pass the same rule as a real install.
if ! ( . "$HERE/install.sh"; TRUSTED_UIDS="0 $(id -u)"; trusted_path "$base" >/dev/null ); then
  echo "SKIP: $base has a parent others can write to; set INSTALL_TEST_DIR to somewhere that has not."
  exit 0
fi

check() {
  if eval "$2"; then echo "ok    $1"; else echo "FAIL  $1"; FAILS=$((FAILS + 1)); fi
}

fresh() {
  R=$base/root
  L=$R/opt/tuxchange
  rm -rf "$R"
  mkdir -p "$R"/{bin,etc/systemd/system,etc/default,etc/polkit-1/rules.d,usr/share/applications} \
           "$R"/{opt,var/lib,usr/bin,src/tuxchange,src/gui,src/scripts,home/user/.config/tuxchange}
  printf '#!/bin/sh\n' > "$R/usr/bin/python3"
  chmod 0755 "$R/usr/bin/python3"
  echo 'print(1)' > "$R/src/tuxchange/sp_relay.py"
  echo 'print(2)' > "$R/src/gui/sp_gui.py"
  printf '#!/bin/sh\n' > "$R/src/scripts/sp_monitor.sh"
  chmod 0755 "$R/src/scripts/sp_monitor.sh"
  echo 'aeskey' > "$R/home/user/.config/tuxchange/aes_keys.txt"
  : > "$R/calls"
  : > "$R/fail"

  cat > "$R/bin/systemctl" <<EOF
#!/bin/sh
echo "systemctl \$*" >> "$R/calls"
grep -qx "systemctl \$1" "$R/fail" && exit 1
[ "\$1" = show ] && echo 0
exit 0
EOF
  cat > "$R/bin/systemd-analyze" <<EOF
#!/bin/sh
echo "systemd-analyze \$*" >> "$R/calls"
grep -qx "systemd-analyze" "$R/fail" && { echo "bad unit"; exit 1; }
pre=\$(sed -n 's/^ExecStartPre=\\([^ ]*\\).*/\\1/p' "\$2")
[ -x "\$pre" ] || { echo "\$pre is not executable"; exit 1; }
exit 0
EOF
  cat > "$R/bin/install" <<EOF
#!/bin/bash
args=()
while [ \$# -gt 0 ]; do
  case "\$1" in -o|-g) shift 2 ;; *) args+=("\$1"); shift ;; esac
done
exec "$REAL_INSTALL" "\${args[@]}"
EOF
  cat > "$R/bin/getent" <<EOF
#!/bin/sh
echo "\$2:x:1000:1000::$R/home/user:/bin/sh"
EOF
  printf '#!/bin/sh\nexit 0\n' > "$R/bin/update-desktop-database"
  chmod 0755 "$R"/bin/*

  cat > "$R/driver.sh" <<EOF
. "$HERE/install.sh"
UNIT=$R/etc/systemd/system/tuxchange.service
DEFAULTS=$R/etc/default/tuxchange
POLKIT=$R/etc/polkit-1/rules.d/50-tuxchange.rules
DESKTOP=$R/usr/share/applications/tuxchange-gui.desktop
KEYDIR=$R/etc/tuxchange
HOOKS=$R/etc/tuxchange-hooks
LIB=$R/opt/tuxchange
STATE=$R/var/lib/tuxchange
RELAY_ENV=\$STATE/relay.env
ROOT=$R/src
PY=\${TEST_PY:-$R/usr/bin/python3}
GUI_USER=\${TEST_GUI_USER:-}
TRUSTED_UIDS="0 $(id -u)"
need_root() { :; }
running_root() { cat "$R/running" 2>/dev/null || true; }
main "\$@"
EOF
}

run() {
  RC=0
  OUT=$(PATH="$R/bin:$PATH" bash "$R/driver.sh" "$@" 2>&1) || RC=$?
}

snapshot() { (cd "$R" && find etc opt usr/share -print0 | sort -z | xargs -0 ls -ld --time-style=+ 2>/dev/null; cat etc/systemd/system/tuxchange.service 2>/dev/null || true) | md5sum; }

leftovers() { find "$R/opt/tuxchange" -mindepth 1 -maxdepth 1 ! -name tuxchange ! -name gui ! -name scripts | wc -l; }

echo "== a clean install"
fresh
TEST_GUI_USER=user run install
check "succeeds" '[ $RC -eq 0 ]'
check "says so" '[[ $OUT == *INSTALLED* ]]'
check "copies the code into $L" '[ -f "$L/tuxchange/sp_relay.py" ] && [ -x "$L/scripts/sp_monitor.sh" ] && [ -f "$L/gui/sp_gui.py" ]'
check "the unit runs from there" 'grep -q "WorkingDirectory=$L\$" "$R/etc/systemd/system/tuxchange.service"'
check "the unit runs the checked python" 'grep -q "exec $R/usr/bin/python3 " "$R/etc/systemd/system/tuxchange.service"'
check "the unit was verified, reloaded and enabled" 'grep -q "^systemd-analyze verify" "$R/calls" && grep -qx "systemctl daemon-reload" "$R/calls" && grep -qx "systemctl enable tuxchange.service" "$R/calls"'
check "writes the defaults, polkit rule and desktop file" '[ -f "$R/etc/default/tuxchange" ] && [ -f "$R/etc/polkit-1/rules.d/50-tuxchange.rules" ] && grep -q "$L/gui" "$R/usr/share/applications/tuxchange-gui.desktop"'
check "copies the keys" '[ "$(cat "$R/etc/tuxchange/aes_keys.txt")" = aeskey ]'
check "leaves no backups or temporary files" '[ "$(leftovers)" -eq 0 ] && [ -z "$(find "$R/etc" "$R/usr/share" -name "*.??????")" ]'

echo "== a reinstall"
echo 'print(3)' > "$R/src/tuxchange/sp_relay.py"
touch "$L/tuxchange/stale.py"
run install
check "succeeds" '[ $RC -eq 0 ]'
check "replaces the code in place" '[ "$(cat "$L/tuxchange/sp_relay.py")" = "print(3)" ] && [ ! -e "$L/tuxchange/stale.py" ] && [ "$(leftovers)" -eq 0 ]'
echo "$L" > "$R/running"
run install
check "says a running service needs a restart" '[ $RC -eq 0 ] && [[ $OUT == *"restart tuxchange"* ]]'
rm -f "$R/running"
mkdir -p "$L/release-20260101000000-abcdef/tuxchange"
run install
check "removes release directories from older installers" '[ $RC -eq 0 ] && [ "$(leftovers)" -eq 0 ]'
mkdir -p "$L/release-20260101000000-abcdef/tuxchange"
echo "$L/release-20260101000000-abcdef" > "$R/running"
run install
check "but not one a running service started from" '[ $RC -eq 0 ] && [ -d "$L/release-20260101000000-abcdef" ]'
rm -rf "$R/running" "$L/release-20260101000000-abcdef"

echo "== failures leave the previous install in place"
echo 'print(4)' > "$R/src/tuxchange/sp_relay.py"
for step in "systemctl enable" "systemctl daemon-reload" "systemd-analyze"; do
  echo "$step" > "$R/fail"
  old_unit=$(cat "$R/etc/systemd/system/tuxchange.service")
  run install
  check "$step failing exits non-zero" '[ $RC -ne 0 ]'
  check "$step failing never claims success" '[[ $OUT != *INSTALLED* ]] && [[ $OUT == *"INSTALL FAILED"* ]]'
  check "$step failing restores the unit" '[ "$(cat "$R/etc/systemd/system/tuxchange.service")" = "$old_unit" ]'
  check "$step failing restores the code" '[ "$(cat "$L/tuxchange/sp_relay.py")" = "print(3)" ] && [ -x "$L/scripts/sp_monitor.sh" ]'
  check "$step failing leaves no backups" '[ "$(leftovers)" -eq 0 ]'
  : > "$R/fail"
done

old_unit=$(cat "$R/etc/systemd/system/tuxchange.service")
chmod 000 "$R/src/gui/sp_gui.py"
if [ -r "$R/src/gui/sp_gui.py" ]; then
  echo "skip  an unreadable source file (running as root)"
else
  run install
  check "an unreadable source file fails the install" '[ $RC -ne 0 ] && [[ $OUT != *INSTALLED* ]]'
  check "and leaves the unit and code alone" '[ "$(cat "$R/etc/systemd/system/tuxchange.service")" = "$old_unit" ] && [ "$(cat "$L/tuxchange/sp_relay.py")" = "print(3)" ] && [ "$(leftovers)" -eq 0 ]'
fi
chmod 0644 "$R/src/gui/sp_gui.py"

echo "== python must be root's all the way"
fresh
mkdir -p "$R/home/user/bin"
chmod 0777 "$R/home/user/bin"
ln -s "$R/usr/bin/python3" "$R/home/user/bin/python3"
before=$(snapshot)
TEST_PY=$R/home/user/bin/python3 run install
check "a symlink in a directory others can write is refused" '[ $RC -ne 0 ] && [[ $OUT == *"python3"*"non-root"* ]]'
check "before anything changes" '[ "$(snapshot)" = "$before" ] && [ ! -e "$R/opt/tuxchange" ] && [ ! -s "$R/calls" ]'

mkdir -p "$R/usr/lib/py"
ln -s "$R/home/user/bin" "$R/usr/lib/py/bin"
TEST_PY=$R/usr/lib/py/bin/python3 run install
check "a trusted symlink to a directory others can write is refused" '[ $RC -ne 0 ] && [ ! -e "$R/opt/tuxchange" ]'

rm "$R/home/user/bin/python3"
printf '#!/bin/sh\n' > "$R/home/user/bin/python3.real"
chmod 0755 "$R/home/user/bin/python3.real"
ln -s "$R/home/user/bin/python3.real" "$R/usr/bin/python3x"
TEST_PY=$R/usr/bin/python3x run install
check "a trusted symlink to a file in such a directory is refused" '[ $RC -ne 0 ] && [ ! -e "$R/opt/tuxchange" ]'

ln -s "../usr/bin" "$R/usr/lib/py/sys"
ln -s "python3" "$R/usr/bin/python3-link"
TEST_PY=$R/usr/lib/py/sys/python3-link run install
check "a chain of trusted symlinks is accepted" '[ $RC -eq 0 ]'
check "and the unit keeps the path it was given" 'grep -q "exec $R/usr/lib/py/sys/python3-link " "$R/etc/systemd/system/tuxchange.service"'

fresh
chmod 0666 "$R/usr/bin/python3"
run install
check "a python others can write is refused" '[ $RC -ne 0 ] && [ ! -e "$R/opt/tuxchange" ]'

echo "== destinations and the store"
fresh
chmod 0777 "$R/opt"
before=$(snapshot)
run install
check "a writable parent of the install directory is refused" '[ $RC -ne 0 ] && [[ $OUT == *"tuxchange, or a directory on the way"* ]]'
check "before anything changes" '[ "$(snapshot)" = "$before" ] && [ ! -s "$R/calls" ]'

fresh
chmod 0777 "$R/etc/systemd/system"
run install
check "a writable unit directory is refused" '[ $RC -ne 0 ] && [ ! -e "$R/opt/tuxchange" ]'

fresh
run install
mkdir -p "$R/home/user/shared"
chmod 0777 "$R/home/user/shared"
mkdir -p "$R/var/lib/store"
ln -s "$R/var/lib/store" "$R/home/user/shared/store"
sed -i "s|^SP_STORE=.*|SP_STORE=$R/home/user/shared/store|" "$R/etc/default/tuxchange"
before=$(snapshot)
: > "$R/calls"
run install
check "a store reached through a writable directory is refused" '[ $RC -ne 0 ] && [[ $OUT == *SP_STORE* ]]'
check "and the previous install is left as it was" '[ "$(snapshot)" = "$before" ] && [ ! -s "$R/calls" ]'

sed -i "s|^SP_STORE=.*|SP_STORE=$R/var/lib/store|" "$R/etc/default/tuxchange"
echo "SP_STORE=$R/home/user/shared/store" > "$R/var/lib/tuxchange/relay.env"
run install
check "the daemon's own saved store is checked too" '[ $RC -ne 0 ] && [[ $OUT == *SP_STORE* ]]'
rm "$R/var/lib/tuxchange/relay.env"
run install
check "a root-only store passes" '[ $RC -eq 0 ] && grep -q -- "--store $R/var/lib/store" "$R/usr/share/applications/tuxchange-gui.desktop"'

echo
if [ "$FAILS" -eq 0 ]; then
  echo "installer self-test: all passed"
else
  echo "installer self-test: $FAILS FAILED"
  exit 1
fi
