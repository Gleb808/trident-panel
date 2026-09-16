#!/usr/bin/env bash
# Только для одноразового Ubuntu runner: проверяем реально установленную панель.
set -euo pipefail
source_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
# shellcheck source=../deploy/bootstrap.sh
. "$source_dir/deploy/bootstrap.sh"
fixture=$(mktemp)
trap 'rm -f -- "$fixture"' EXIT
printf 'checksum fixture\n' > "$fixture"
expected=$(sha256sum "$fixture")
verify_checksum "$fixture" "${expected%% *}"
if verify_checksum "$fixture" '0000000000000000000000000000000000000000000000000000000000000000'; then
  die 'Несовпадение checksum не остановило проверку.'
fi

node=/opt/trident-panel/runtime/node
"$node" --input-type=module -e '
  const response = await fetch("http://127.0.0.1:8787/api/session");
  const session = await response.json();
  if (!response.ok || !session.setupRequired || session.authenticated) throw new Error("Unexpected initial state");
'
[[ $(systemctl is-active trident-panel) == active ]]
[[ $(stat -c %U /opt/trident-panel/runtime/node) == root ]]
[[ $(stat -c %a /var/lib/trident) == 700 ]]
[[ -z $(find /opt/trident-panel -perm /022 -print) ]]
[[ $(ss -H -ltn 'sport = :8787') == *127.0.0.1:8787* ]]
for unit in trident-agent trident-caddy trident-mita trident-xray; do
  if systemctl is-active --quiet "$unit"; then die "$unit запущен до настройки администратором."; fi
done

# Повторный запуск обязан остановиться раньше скачиваний и записи данных.
if bash "$source_dir/deploy/bootstrap.sh" > "$fixture" 2>&1; then
  die 'Повторная установка должна завершаться отказом.'
fi
grep -q '/opt/trident-panel уже существует' "$fixture"
[[ $(systemctl is-active trident-panel) == active ]]
systemctl restart trident-panel
curl --fail --silent --show-error --retry 10 --retry-connrefused --retry-delay 1 http://127.0.0.1:8787/healthz
printf '\nUbuntu installation smoke test passed.\n'
