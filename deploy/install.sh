#!/usr/bin/env bash
set -euo pipefail
# Устанавливаем только файлы панели. Закреплённые версии движков должны быть
# получены из официальных источников заранее — установщик их не подменяет.
if [[ $(id -u) -ne 0 ]]; then echo 'Run as root on a Linux systemd VPS.' >&2; exit 1; fi
command -v systemctl >/dev/null
[[ -x /usr/bin/node ]] || { echo 'Node.js 24 must be installed at /usr/bin/node.' >&2; exit 1; }
[[ $(/usr/bin/node -p 'process.versions.node.split(".")[0]') == 24 ]] || { echo 'Node.js 24 required.' >&2; exit 1; }
for binary in caddy mita xray; do
  [[ -x /usr/local/bin/$binary ]] || { echo "Missing /usr/local/bin/$binary; see README." >&2; exit 1; }
done
for binary in /usr/bin/ss /usr/bin/id; do [[ -x "$binary" ]] || { echo "Missing $binary" >&2; exit 1; }; done
source_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
if [[ -e /opt/trident-panel ]]; then echo '/opt/trident-panel exists. Back up and use the documented update procedure.' >&2; exit 1; fi
id trident >/dev/null 2>&1 || useradd --system --home-dir /var/lib/trident --shell /usr/sbin/nologin trident
install -d -m 0755 /opt/trident-panel
for dir in src public scripts deploy docs; do cp -R -- "$source_dir/$dir" /opt/trident-panel/; done
cp -- "$source_dir/package.json" "$source_dir/README.md" "$source_dir/VALIDATION.md" "$source_dir/CHANGELOG.md" /opt/trident-panel/
# Исходники читает привилегированный агент: веб-процесс не должен их изменять.
chown -R root:root /opt/trident-panel
chmod -R go-w /opt/trident-panel
install -d -m 0700 -o trident -g trident /var/lib/trident
install -d -m 0700 -o trident -g trident /var/lib/trident-caddy
install -d -m 0750 -o root -g trident /var/lib/trident-agent
for unit in "$source_dir"/deploy/*.service; do install -m 0644 "$unit" /etc/systemd/system/; done
systemctl daemon-reload
# Первый запуск доступен только через loopback. Агент включается после
# настройки домена/портов; установщик не открывает firewall и не рвёт SSH.
systemctl enable --now trident-panel
echo 'Panel is listening on 127.0.0.1:8787.'
echo 'Use an SSH tunnel to create the admin password and configure the domain.'
echo 'Then run: systemctl enable --now trident-agent'
echo 'No firewall rules have been changed. Proxy engines are started by the agent.'
