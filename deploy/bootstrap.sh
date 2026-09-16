#!/usr/bin/env bash
# Загрузчик для чистого Ubuntu VPS. Выполняется только после полной загрузки файла.
# Релизы закреплены вместе с SHA256; обновлять версии и хеши нужно одновременно.
set -euo pipefail

die() { printf 'TRIDENT: %s\n' "$*" >&2; exit 1; }
log() { printf '\n== TRIDENT: %s ==\n' "$*"; }

verify_checksum() {
  local file=$1 expected=$2
  printf '%s  %s\n' "$expected" "$file" | sha256sum --check --status
}

download() {
  curl --fail --show-error --location --retry 3 --connect-timeout 20 \
    --proto '=https' --proto-redir '=https' "$1" --output "$2"
}

download_verified() {
  download "$1" "$2"
  verify_checksum "$2" "$3" || die "Контрольная сумма не совпала: $(basename -- "$2"). Установка остановлена."
}

cleanup() {
  # Удалять разрешено только приватный временный каталог, созданный этим запуском.
  if [[ ${work_dir:-} == /tmp/trident-install.* && -d $work_dir ]]; then
    rm -rf -- "$work_dir"
  fi
}

main() {
  [[ $(id -u) -eq 0 ]] || die 'Запустите установщик через sudo bash.'
  [[ -r /etc/os-release ]] || die 'Не удалось определить ОС.'
  # Файл поставляется операционной системой, а не репозиторием.
  # shellcheck disable=SC1091
  . /etc/os-release
  [[ ${ID:-} == ubuntu && ${VERSION_ID:-} == 24.04 ]] || die 'Автоматическая установка поддерживает Ubuntu 24.04.'
  [[ $(uname -m) == x86_64 ]] || die 'Нужен VPS x86_64/amd64. Для ARM64 нет готового Caddy naive в закреплённом выпуске.'
  [[ -d /run/systemd/system ]] || die 'Нужен VPS с работающим systemd.'
  command -v systemctl >/dev/null || die 'Не найден systemctl.'

  # Повторная установка и чужие бинарники требуют ручного разбора, а не перезаписи.
  for path in /opt/trident-panel /var/lib/trident /var/lib/trident-agent /var/lib/trident-caddy; do
    [[ ! -e $path && ! -L $path ]] || die "$path уже существует. Это установщик новой панели; используйте резервное копирование и процедуру обновления."
  done
  for binary in caddy mita xray; do
    [[ ! -e /usr/local/bin/$binary && ! -L /usr/local/bin/$binary ]] || die "/usr/local/bin/$binary уже существует. Используйте ручную установку из README."
    if command -v "$binary" >/dev/null; then die "$binary уже установлен в PATH. Используйте ручную установку из README."; fi
  done
  if getent passwd trident >/dev/null || getent group trident >/dev/null; then
    die 'Пользователь или группа trident уже существует. Требуется ручная проверка сервера.'
  fi
  for unit in trident-panel trident-agent trident-caddy trident-mita trident-xray; do
    [[ $(systemctl show "$unit.service" --property=LoadState --value) == not-found ]] || die "Служба $unit уже установлена."
  done
  local ref=${TRIDENT_REF:-main}
  [[ $ref == main || $ref =~ ^[0-9a-f]{40}$ ]] || die 'TRIDENT_REF должен быть main либо полным SHA коммита.'

  log 'Установка системных зависимостей'
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    ca-certificates curl tar xz-utils unzip iproute2 openssl libstdc++6
  [[ -z $(ss -H -ltn 'sport = :8787') ]] || die 'TCP-порт 8787 уже занят. Освободите его перед установкой.'

  umask 022
  work_dir=$(mktemp -d /tmp/trident-install.XXXXXXXX)
  trap cleanup EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  mkdir -p "$work_dir/source" "$work_dir/node" "$work_dir/xray" "$work_dir/mita" "$work_dir/caddy"
  log "Загрузка репозитория Gleb808/trident-panel ($ref)"
  download "https://github.com/Gleb808/trident-panel/archive/$ref.tar.gz" "$work_dir/source.tar.gz"
  tar -xzf "$work_dir/source.tar.gz" --strip-components=1 --no-same-owner -C "$work_dir/source"
  [[ -f $work_dir/source/deploy/install.sh ]] || die 'В архиве нет deploy/install.sh.'

  log 'Загрузка Node.js 24.21.0, Xray 26.3.27, mita 3.37.0 и Caddy naive 2.11.2'
  download_verified 'https://nodejs.org/dist/v24.21.0/node-v24.21.0-linux-x64.tar.xz' \
    "$work_dir/node.tar.xz" 'fd8e59d5a511510f6a298afb548f18c7d2b1be404d8b4a27d94fbe49f56cb2d6'
  download_verified 'https://github.com/XTLS/Xray-core/releases/download/v26.3.27/Xray-linux-64.zip' \
    "$work_dir/xray.zip" '23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae'
  download_verified 'https://github.com/enfein/mieru/releases/download/v3.37.0/mita_3.37.0_linux_amd64.tar.gz' \
    "$work_dir/mita.tar.gz" 'ebd7a4f13204ac69864a385a9841708ac17e6622c1d7ef1f4415b39502c08591'
  download_verified 'https://github.com/klzgrad/forwardproxy/releases/download/v2.11.2-naive/caddy-forwardproxy-naive.tar.xz' \
    "$work_dir/caddy.tar.xz" '19eccb7321dd877a5fb4a3dba6ef1b745185188b616c96cc6201f1a1fc0380a8'

  # Распаковка и запуск разрешены только после проверки всех четырёх архивов.
  tar -xJf "$work_dir/node.tar.xz" --strip-components=1 --no-same-owner -C "$work_dir/node"
  unzip -q "$work_dir/xray.zip" -d "$work_dir/xray"
  tar -xzf "$work_dir/mita.tar.gz" --no-same-owner -C "$work_dir/mita"
  tar -xJf "$work_dir/caddy.tar.xz" --strip-components=1 --no-same-owner -C "$work_dir/caddy"
  local node_binary="$work_dir/node/bin/node"
  [[ $("$node_binary" --version) == v24.21.0 ]] || die 'Неожиданная версия Node.js.'
  [[ $("$work_dir/xray/xray" version) == *26.3.27* ]] || die 'Неожиданная версия Xray.'
  [[ $("$work_dir/mita/mita" version) == *3.37.0* ]] || die 'Неожиданная версия mita.'
  [[ $("$work_dir/caddy/caddy" version) == *2.11.2* ]] || die 'Неожиданная версия Caddy.'
  local modules
  modules=$("$work_dir/caddy/caddy" list-modules)
  [[ $modules == *http.handlers.forward_proxy* ]] || die 'В Caddy отсутствует forward_proxy.'

  log 'Установка движков и панели'
  install -d -m 0755 /usr/local/bin
  install -m 0755 "$work_dir/xray/xray" /usr/local/bin/xray
  install -m 0755 "$work_dir/mita/mita" /usr/local/bin/mita
  install -m 0755 "$work_dir/caddy/caddy" /usr/local/bin/caddy
  # Node копируется в private runtime панели и не заменяет системный /usr/bin/node.
  TRIDENT_NODE_BINARY="$node_binary" bash "$work_dir/source/deploy/install.sh"
}

# Можно source-нуть файл для изолированной проверки checksum-функции без установки.
if [[ ${BASH_SOURCE[0]} == "$0" ]]; then main "$@"; fi
