import { backup } from 'node:sqlite';
import { mkdirSync, copyFileSync, chmodSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { Store } from '../src/store.mjs';
// SQLite backup API создаёт согласованную копию работающей базы, в том числе при включённом WAL.
// Простое копирование panel.sqlite могло бы пропустить ещё не перенесённые из WAL изменения.
const source = resolve(process.env.DATA_DIR || 'data');
const dest = resolve(process.argv[2] || `runtime/backup-${Date.now()}`);
mkdirSync(dest, { recursive:true, mode:0o700 });
const store = new Store(source, {readOnly:true});
// master.key необходим для восстановления зашифрованных записей. Доступ к каталогу копии
// следует защищать как доступ к оригинальной базе: в нём находятся и шифротекст, и ключ.
try { await backup(store.db, join(dest,'panel.sqlite')); copyFileSync(join(source,'master.key'), join(dest,'master.key')); chmodSync(join(dest,'panel.sqlite'),0o600); chmodSync(join(dest,'master.key'),0o600); console.log(`Резервная копия: ${dest}. База и master.key должны храниться вместе в защищённом месте.`); } finally {store.close();}
