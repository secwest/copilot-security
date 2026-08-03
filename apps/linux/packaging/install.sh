#!/usr/bin/env sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
  echo "Run this installer as root." >&2
  exit 1
fi

package_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if [ ! -x "$package_dir/app/CopilotSecurity" ]; then
  echo "The package is incomplete: app/CopilotSecurity is missing or not executable." >&2
  exit 1
fi
if [ ! -x "$package_dir/app/scanner/bin/copilot-security.mjs" ]; then
  echo "The package is incomplete: the standalone scanner entry point is missing or not executable." >&2
  exit 1
fi
if [ ! -d "$package_dir/app/scanner/node_modules/@github/copilot-sdk" ]; then
  echo "The package is incomplete: the standalone scanner production dependencies are missing." >&2
  exit 1
fi

install -d -m 0755 /opt/copilot-security
cp -R "$package_dir/app/." /opt/copilot-security/
chmod 0755 /opt/copilot-security/CopilotSecurity
chmod 0755 /opt/copilot-security/scanner/bin/copilot-security.mjs
install -m 0755 "$package_dir/copilot-security-gui" /usr/local/bin/copilot-security-gui
install -m 0644 "$package_dir/copilot-security.desktop" /usr/share/applications/copilot-security.desktop
install -d -m 0755 /usr/share/icons/hicolor/scalable/apps
install -m 0644 "$package_dir/copilot-security.svg" /usr/share/icons/hicolor/scalable/apps/copilot-security.svg

echo "Copilot Security installed. Start it from the application menu or run copilot-security-gui."
