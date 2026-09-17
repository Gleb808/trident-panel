#!/usr/bin/env bash
set -euo pipefail
[[ ${GITHUB_ACTIONS:-} == true && $(id -u) == 0 ]] || exit 1
source_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
node=/opt/trident-panel/runtime/node
fixture=$(mktemp)
trap 'rm -f -- "$fixture"' EXIT
systemctl stop trident-panel
# Записываем базу прежнего формата: без xhttpPath, с пользователем и администратором.
"$node" --input-type=module -e '
  import {Store} from "/opt/trident-panel/src/store.mjs";
  import {writeFileSync} from "node:fs";
  const s=new Store("/var/lib/trident");
  const settings=s.settings(); delete settings.xhttpPath; s.setMeta("settings",settings);
  s.setup("ephemeral-CI-admin-password");
  const u=s.create({name:"Update fixture",status:"active"});
  writeFileSync(process.argv[1],JSON.stringify({u,settings})); s.close();
' "$fixture"
chown -R trident:trident /var/lib/trident
key_before=$(sha256sum /var/lib/trident/master.key)
systemctl start trident-panel
TRIDENT_REF="$GITHUB_SHA" bash "$source_dir/deploy/update.sh"
[[ $(sha256sum /var/lib/trident/master.key) == "$key_before" ]]
"$node" --input-type=module -e '
  import {Store} from "/opt/trident-panel/src/store.mjs";
  import {readFileSync} from "node:fs";
  import assert from "node:assert/strict";
  const expected=JSON.parse(readFileSync(process.argv[1],"utf8"));
  const s=new Store("/var/lib/trident",{readOnly:true});
  assert.deepEqual(s.users(),[expected.u]);
  assert.deepEqual(s.settings(),{xhttpPath:"/trident",...expected.settings});
  assert.equal(s.authenticate("ephemeral-CI-admin-password"),true); s.close();
' "$fixture"
[[ $(systemctl is-active trident-panel) == active ]]
id mita >/dev/null
[[ -z $(find /opt/trident-panel -perm /022 -print) ]]
printf 'PASS: update preserves encrypted users, administrator, REALITY keys and master.key\n'
