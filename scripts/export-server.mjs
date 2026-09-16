import { resolve, join } from 'node:path';
import { mkdirSync, writeFileSync } from 'node:fs';
import { Store } from '../src/store.mjs';
import { serverFiles } from '../src/configs.mjs';
// Экспорт создаёт файлы с открытыми серверными секретами, но не запускает и не меняет сервисы.
// DATA_DIR задаёт исходную базу, первый аргумент CLI — каталог результата.
const dir = resolve(process.env.DATA_DIR || 'data'), out = resolve(process.argv[2] || 'runtime/export');
const store = new Store(dir, { readOnly:true });
try { const files = serverFiles(store.settings(), store.users()); mkdirSync(out, { recursive:true, mode:0o700 });
  for (const [name, text] of Object.entries(files)) writeFileSync(join(out, name), text, { mode:0o600 });
  console.log(`Серверные конфиги сохранены: ${out}. Они содержат секреты.`);
} finally { store.close(); }
