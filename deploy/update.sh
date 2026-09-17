#!/usr/bin/env bash
# Обновляет только TRIDENT; база, master.key и сертификаты сохраняются.
set -euo pipefail
die() { printf 'TRIDENT: %s\n' "$*" >&2; exit 1; }
[[ $(id -u) == 0 ]] || die 'Запустите через sudo bash.'
[[ -x /opt/trident-panel/runtime/node && -f /var/lib/trident/master.key ]] || die 'Установка TRIDENT с private Node runtime не найдена.'
[[ $(/opt/trident-panel/runtime/node -p 'process.versions.node.split(".")[0]') == 24 ]] || die 'Нужен Node.js 24.'
ref=${TRIDENT_REF:-main}
[[ $ref == main || $ref =~ ^[0-9a-f]{40}$ ]] || die 'TRIDENT_REF: main либо полный SHA.'
umask 077
work_dir=$(mktemp -d /tmp/trident-update.XXXXXXXX)
cleanup() { [[ $work_dir == /tmp/trident-update.* && -d $work_dir ]] && rm -rf -- "$work_dir"; }
trap cleanup EXIT
curl -fSL --retry 3 --connect-timeout 20 --proto '=https' --proto-redir '=https' \
  "https://github.com/Gleb808/trident-panel/archive/$ref.tar.gz" -o "$work_dir/source.tar.gz"
mkdir "$work_dir/source"
tar -xzf "$work_dir/source.tar.gz" --strip-components=1 --no-same-owner -C "$work_dir/source"
for file in src/server.mjs src/agent.mjs deploy/trident-mita.service; do
  [[ -f $work_dir/source/$file ]] || die "В архиве отсутствует $file"
done
for file in "$work_dir/source"/src/*.mjs "$work_dir/source"/public/app.js; do /opt/trident-panel/runtime/node --check "$file"; done
# Всё скачано и проверено до остановки работающей панели.
backup_dir=$(mktemp -d /var/backups/trident-update.XXXXXXXX)
agent_active=false
systemctl is-active --quiet trident-agent && agent_active=true
backed_up=false
rollback() {
  local result=$?
  trap - ERR
  set +e
  systemctl stop trident-agent trident-panel
  # Источники восстанавливаем из закрытой копии; данные обновитель не меняет.
  if [[ $backed_up == true ]]; then
    cp -a "$backup_dir/app/." /opt/trident-panel/
    cp -a "$backup_dir/units/." /etc/systemd/system/
  fi
  systemctl daemon-reload
  systemctl start trident-panel
  if [[ $agent_active == true ]]; then systemctl start trident-agent; fi
  printf 'Обновление не завершено; исходники восстановлены. Копия: %s\n' "$backup_dir" >&2
  exit "$result"
}
trap rollback ERR
systemctl stop trident-agent trident-panel
cp -a /opt/trident-panel "$backup_dir/app"
cp -a /var/lib/trident "$backup_dir/data"
mkdir "$backup_dir/units"
cp -a /etc/systemd/system/trident-*.service "$backup_dir/units/"
backed_up=true
id mita >/dev/null 2>&1 || useradd --system --user-group --home-dir /var/lib/mita --shell /usr/sbin/nologin mita
for dir in src public scripts deploy docs; do cp -a "$work_dir/source/$dir/." "/opt/trident-panel/$dir/"; done
for file in package.json README.md VALIDATION.md CHANGELOG.md; do cp "$work_dir/source/$file" /opt/trident-panel/; done
chown -R root:root /opt/trident-panel
chmod -R a+rX,go-w /opt/trident-panel
for unit in "$work_dir/source"/deploy/*.service; do install -m 0644 "$unit" /etc/systemd/system/; done
systemctl daemon-reload
systemctl start trident-panel
curl --fail --silent --show-error --retry 15 --retry-connrefused --retry-delay 1 http://127.0.0.1:8787/healthz
if [[ $agent_active == true ]]; then systemctl start trident-agent; fi
trap - ERR
printf '\nTRIDENT обновлён. Резервная копия: %s\n' "$backup_dir"
printf '%s\n' 'Пользователи, пароли и ключи сохранены. Скачайте новые VLESS XHTTP + REALITY конфиги.'
printf '%s\n' 'После настройки домена включите агент: sudo systemctl enable --now trident-agent'
printf '%s\n' 'Проверьте статус применения в панели; обновление исходников не подтверждает доступность прокси.'
