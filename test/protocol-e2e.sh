#!/usr/bin/env bash
# Только одноразовый GitHub runner! Меняет /etc/hosts и устанавливает тестовые конфиги.
set -euo pipefail
[[ ${GITHUB_ACTIONS:-} == true && $(id -u) == 0 ]] || { echo 'Disposable GitHub runner only' >&2; exit 1; }
source_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
# shellcheck source=../deploy/bootstrap.sh
. "$source_dir/deploy/bootstrap.sh"
work_dir=$(mktemp -d /tmp/trident-e2e.XXXXXXXX)
trap 'rm -rf -- "$work_dir"' EXIT
mkdir "$work_dir/naive" "$work_dir/mieru"
download_verified 'https://github.com/klzgrad/naiveproxy/releases/download/v150.0.7871.63-1/naiveproxy-v150.0.7871.63-1-linux-x64.tar.xz' \
  "$work_dir/naive.tar.xz" '0c4f506ce66a7881892fd6932b542c53fc06ac2351987756096c61e753c687bf'
download_verified 'https://github.com/enfein/mieru/releases/download/v3.37.0/mieru_3.37.0_linux_amd64.tar.gz' \
  "$work_dir/mieru.tar.gz" '6c83b01454ab5d6628be0edc486ead659513acde22112bcca764ffcfbbed4a7b'
tar -xJf "$work_dir/naive.tar.xz" --strip-components=1 -C "$work_dir/naive"
tar -xzf "$work_dir/mieru.tar.gz" -C "$work_dir/mieru"
printf '\n127.0.0.1 proxy.test reality.test\n' >> /etc/hosts
# Документационный адрес маршрутизируется локально; production ACL не ослабляется.
ip address add 203.0.113.10/32 dev lo
install -d -o trident -g trident -m 0700 /var/lib/trident-caddy/test-tls
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj '/CN=proxy.test' \
  -addext 'subjectAltName=DNS:proxy.test,DNS:reality.test' \
  -keyout /var/lib/trident-caddy/test-tls/key.pem -out /var/lib/trident-caddy/test-tls/cert.pem 2>/dev/null
chown trident:trident /var/lib/trident-caddy/test-tls/*.pem
chmod 0600 /var/lib/trident-caddy/test-tls/*.pem
TRIDENT_E2E_DIR="$work_dir" /opt/trident-panel/runtime/node "$source_dir/test/protocol-e2e.mjs"
