#!/usr/bin/env sh
set -eu

PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 022

fail() {
  echo "$1" >&2
  exit 1
}

if [ "$(id -u)" -ne 0 ]; then
  fail "Run this installer as root."
fi

package_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
install_root=/opt/copilot-security
lock_dir=/opt/.copilot-security-install.lock
staging_dir=
previous_root=
lock_acquired=0
previous_moved=0
app_committed=0
install_complete=0
launcher_tmp=/usr/local/bin/.copilot-security-gui.$$
desktop_tmp=/usr/share/applications/.copilot-security.desktop.$$
icon_tmp=/usr/share/icons/hicolor/scalable/apps/.copilot-security.svg.$$

cleanup() {
  status=$?
  trap - 0 1 2 15
  set +e
  rm -f -- "$launcher_tmp" "$desktop_tmp" "$icon_tmp"
  if [ "$install_complete" -ne 1 ]; then
    if [ "$app_committed" -eq 1 ]; then
      rm -rf -- /opt/copilot-security
    fi
    if [ "$previous_moved" -eq 1 ] && [ ! -e "$install_root" ] && [ ! -L "$install_root" ]; then
      mv -- "$previous_root" "$install_root"
    fi
  fi
  if [ -n "$staging_dir" ]; then
    rm -rf -- "$staging_dir"
  fi
  if [ "$lock_acquired" -eq 1 ]; then
    rmdir -- "$lock_dir" 2>/dev/null
  fi
  exit "$status"
}

trap cleanup 0
trap 'exit 129' 1
trap 'exit 130' 2
trap 'exit 143' 15

if ! mkdir -m 0700 -- "$lock_dir"; then
  fail "Another Copilot Security installation is already running."
fi
lock_acquired=1

staging_dir=$(mktemp -d /opt/.copilot-security-package.XXXXXX)
previous_root="$staging_dir/previous-app"
staged_package="$staging_dir/package"
mkdir -m 0700 -- "$staged_package"

# Freeze the user-owned extraction into a root-owned tree. Preserve relative
# package links, but never preserve the extracting user's ownership.
cp -a --no-preserve=ownership -- "$package_dir/." "$staged_package/"

special_path=$(find "$staged_package" ! -type d ! -type f ! -type l -print -quit)
if [ -n "$special_path" ]; then
  fail "The package contains an unsupported special file."
fi
find "$staged_package" -type d -exec chmod 0755 {} +
find "$staged_package" -type f -exec chmod a-s,o-w {} +

# pnpm production dependencies legitimately contain relative links. They are
# the only allowed links, and every one must resolve to an existing object in
# the root-owned staged package. xargs preserves arbitrary path bytes.
# The single-quoted program is intentionally evaluated by the child shell.
# shellcheck disable=SC2016
if ! find "$staged_package" -type l -print0 | xargs -0 -r sh -c '
  root=$1
  allowed_root=$root/app/scanner/node_modules
  shift
  for link do
    target=$(readlink -- "$link") || exit 1
    case "$target" in
      /*) exit 1 ;;
    esac
    case "$link" in
      "$allowed_root"/*) ;;
      *) exit 1 ;;
    esac
    resolved=$(realpath -e -- "$link") || exit 1
    case "$resolved" in
      "$root"/*) ;;
      *) exit 1 ;;
    esac
  done
' sh "$staged_package"; then
  fail "The package contains an unsafe symbolic link."
fi

if [ ! -f "$staged_package/app/CopilotSecurity" ] || [ ! -x "$staged_package/app/CopilotSecurity" ]; then
  fail "The package is incomplete: app/CopilotSecurity is missing or not executable."
fi
if [ ! -f "$staged_package/app/scanner/bin/copilot-security.mjs" ] || [ ! -x "$staged_package/app/scanner/bin/copilot-security.mjs" ]; then
  fail "The package is incomplete: the standalone scanner entry point is missing or not executable."
fi
if [ ! -d "$staged_package/app/scanner/node_modules/@github/copilot-sdk" ]; then
  fail "The package is incomplete: the standalone scanner production dependencies are missing."
fi
for asset in copilot-security-gui copilot-security.desktop copilot-security.svg; do
  if [ ! -f "$staged_package/$asset" ]; then
    fail "The package is incomplete: $asset is missing or not a regular file."
  fi
done

if [ -L "$install_root" ] || { [ -e "$install_root" ] && [ ! -d "$install_root" ]; }; then
  fail "The existing application path is not a regular directory."
fi
for destination in \
  /usr/local/bin/copilot-security-gui \
  /usr/share/applications/copilot-security.desktop \
  /usr/share/icons/hicolor/scalable/apps/copilot-security.svg
do
  if [ -L "$destination" ] || [ -d "$destination" ]; then
    fail "An installation destination is not a regular file path."
  fi
done

chmod 0755 "$staged_package/app/CopilotSecurity"
chmod 0755 "$staged_package/app/scanner/bin/copilot-security.mjs"
install -d -m 0755 /usr/share/icons/hicolor/scalable/apps
install -m 0755 "$staged_package/copilot-security-gui" "$launcher_tmp"
install -m 0644 "$staged_package/copilot-security.desktop" "$desktop_tmp"
install -m 0644 "$staged_package/copilot-security.svg" "$icon_tmp"

if [ -d "$install_root" ]; then
  mv -- "$install_root" "$previous_root"
  previous_moved=1
fi
mv -- "$staged_package/app" "$install_root"
app_committed=1
mv -- "$launcher_tmp" /usr/local/bin/copilot-security-gui
mv -- "$desktop_tmp" /usr/share/applications/copilot-security.desktop
mv -- "$icon_tmp" /usr/share/icons/hicolor/scalable/apps/copilot-security.svg
install_complete=1

echo "Copilot Security installed. Start it from the application menu or run copilot-security-gui."
