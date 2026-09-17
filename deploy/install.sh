#!/usr/bin/env bash
set -euo pipefail
# Локальный этап установки. Загрузку релизов выполняет deploy/bootstrap.sh;
# при ручном запуске движки должны быть заранее установлены по README.
if [[ $(id -u) -ne 0 ]]; then echo 'Run as root on a Linux systemd VPS.' >&2; exit 1; fi
command -v systemctl >/dev/null
node_binary=${TRIDENT_NODE_BINARY:-$(command -v node || true)}
[[ $node_binary == /* && -x $node_binary ]] || { echo 'Node.js 24 required. Set TRIDENT_NODE_BINARY to its absolute path.' >&2; exit 1; }
[[ $("$node_binary" -p 'process.versions.node.split(".")[0]') == 24 ]] || { echo 'Node.js 24 required.' >&2; exit 1; }
for binary in caddy mita xray; do
  [[ -x /usr/local/bin/$binary ]] || { echo "Missing /usr/local/bin/$binary; see README." >&2; exit 1; }
done
for binary in /usr/bin/ss /usr/bin/id; do [[ -x "$binary" ]] || { echo "Missing $binary" >&2; exit 1; }; done
source_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
if [[ -e /opt/trident-panel || -L /opt/trident-panel ]]; then echo '/opt/trident-panel exists. Back up and use the documented update procedure.' >&2; exit 1; fi
[[ -z $(ss -H -ltn 'sport = :8787') ]] || { echo 'TCP port 8787 is already in use.' >&2; exit 1; }
id trident >/dev/null 2>&1 || useradd --system --home-dir /var/lib/trident --shell /usr/sbin/nologin trident
# mita проверяет собственный Unix user/group при создании RPC socket.
id mita >/dev/null 2>&1 || useradd --system --user-group --home-dir /var/lib/mita --shell /usr/sbin/nologin mita
install -d -m 0755 /opt/trident-panel
install -d -m 0755 /opt/trident-panel/runtime
install -m 0755 "$node_binary" /opt/trident-panel/runtime/node
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
# systemctl start подтверждает запуск процесса, но ещё не готовность HTTP.
ready=false
for ((attempt = 0; attempt < 30; attempt++)); do
  if /opt/trident-panel/runtime/node --input-type=module -e 'const r=await fetch("http://127.0.0.1:8787/healthz",{signal:AbortSignal.timeout(1000)}); if(!r.ok || (await r.json()).status!=="ok") process.exit(1)' >/dev/null 2>&1; then ready=true; break; fi
  sleep 1
done
if [[ $ready != true ]]; then
  echo 'Panel did not become ready. Inspect: journalctl -u trident-panel -n 100 --no-pager' >&2
  exit 1
fi
echo 'Панель установлена: http://127.0.0.1:8787 (на VPS).'
echo 'На своём компьютере выполните: ssh -L 8787:127.0.0.1:8787 USER@VPS_IP'
echo 'Откройте http://127.0.0.1:8787 и задайте пароль, домен и порты.'
echo 'После настройки на VPS выполните: sudo systemctl enable --now trident-agent'
echo 'Firewall не изменён. Правила публичных портов перечислены в README.'
