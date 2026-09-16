import { DatabaseSync } from 'node:sqlite';
import { mkdirSync, readFileSync, writeFileSync, existsSync, chmodSync } from 'node:fs';
import { join } from 'node:path';
import { randomBytes, createCipheriv, createDecipheriv, scryptSync, timingSafeEqual } from 'node:crypto';
import { defaults, validateSettings, validateUser, credentials, token, digest, fail } from './domain.mjs';

/**
 * SQLite хранит желаемое состояние панели, а не подтверждение работы серверных протоколов.
 * Пользовательские записи и значения meta шифруются; ID, сессии и журнал имеют отдельные поля.
 * Это шифрование записей приложения, а не всего файла SQLite.
 */
export class Store {
  constructor(dir, { readOnly = false } = {}) {
    this.dir = dir;
    if (!readOnly) mkdirSync(dir, { recursive: true, mode: 0o700 });
    // Общий 256-битный ключ не записывается в SQLite. Без исходного master.key база не читается.
    // Резервная копия должна включать оба файла; доступ к обоим позволяет расшифровать секреты.
    const keyPath = join(dir, 'master.key');
    if (!existsSync(keyPath) && !readOnly) writeFileSync(keyPath, randomBytes(32), { mode: 0o600, flag: 'wx' });
    this.key = readFileSync(keyPath);
    if (this.key.length !== 32) throw new Error('master.key must contain exactly 32 bytes');
    this.db = new DatabaseSync(join(dir, 'panel.sqlite'), { readOnly });
    this.db.exec('PRAGMA busy_timeout=5000;');
    if (readOnly) return;
    this.db.exec(`PRAGMA journal_mode=WAL;
      CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, record TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS sessions (hash TEXT PRIMARY KEY, csrf TEXT NOT NULL, expires INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY, at TEXT NOT NULL, action TEXT NOT NULL, subject TEXT NOT NULL);`);
    if (!this.getMeta('settings')) this.setMeta('settings', defaults());
    chmodSync(join(dir, 'panel.sqlite'), 0o600);
  }
  /** AES-GCM: новый 12-байтовый IV на запись, затем 16-байтовый тег и шифротекст. */
  seal(value) {
    const iv = randomBytes(12), cipher = createCipheriv('aes-256-gcm', this.key, iv);
    const data = Buffer.concat([cipher.update(JSON.stringify(value)), cipher.final()]);
    return Buffer.concat([iv, cipher.getAuthTag(), data]).toString('base64');
  }
  // final() проверяет тег: неверный ключ или изменённая запись завершаются ошибкой.
  unseal(value) {
    const b = Buffer.from(value, 'base64'), d = createDecipheriv('aes-256-gcm', this.key, b.subarray(0, 12));
    d.setAuthTag(b.subarray(12, 28));
    return JSON.parse(Buffer.concat([d.update(b.subarray(28)), d.final()]).toString());
  }
  getMeta(key) { const r = this.db.prepare('SELECT value FROM meta WHERE key=?').get(key); return r ? this.unseal(r.value) : null; }
  setMeta(key, value) { this.db.prepare('INSERT INTO meta VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value').run(key, this.seal(value)); }
  // Колбэк должен быть синхронным. Изменение данных и запись аудита фиксируются вместе;
  // эта транзакция не охватывает применение конфигурации внешними сервисами.
  transaction(fn) {
    this.db.exec('BEGIN IMMEDIATE');
    try { const r = fn(); this.db.exec('COMMIT'); return r; } catch (e) { this.db.exec('ROLLBACK'); throw e; }
  }
  settings() { return this.getMeta('settings'); }
  updateSettings(input) {
    // Белый список не позволяет API произвольно подменить серверный ключ REALITY.
    const old = this.settings(), allowed = ['host', 'naivePort', 'naiveQuic', 'vlessPort', 'mieruStart', 'mieruEnd', 'panelPort', 'realitySni', 'realityTargetPort', 'acmeEmail'];
    const next = { ...old };
    for (const k of allowed) if (Object.hasOwn(input, k)) next[k] = input[k];
    validateSettings(next);
    this.transaction(() => { this.setMeta('settings', next); this.audit('settings.updated', next.host); });
    return next;
  }
  users() { return this.db.prepare('SELECT record FROM users ORDER BY rowid DESC').all().map(r => this.unseal(r.record)); }
  user(id) { const r = this.db.prepare('SELECT record FROM users WHERE id=?').get(id); if (!r) fail('Пользователь не найден', 404); return this.unseal(r.record); }
  save(u) { this.db.prepare('INSERT INTO users VALUES (?,?) ON CONFLICT(id) DO UPDATE SET record=excluded.record').run(u.id, this.seal(u)); return u; }
  create(input) {
    const u = { ...validateUser(input), secrets: credentials(), shareToken: token() };
    return this.transaction(() => { this.save(u); this.audit('user.created', u.name); return u; });
  }
  update(id, input) {
    const old = this.user(id), u = { ...old, ...validateUser({ ...old, ...input }, old) };
    return this.transaction(() => { this.save(u); this.audit('user.updated', u.name); return u; });
  }
  // Перевыпуск одного протокола сохраняет остальные доступы. 'all' отзывает также ссылку выдачи;
  // изменения протокольных секретов вступают в силу после успешного применения агентом.
  rotate(id, protocol = 'all') {
    if (!['all', 'naive', 'mieru', 'vless', 'share'].includes(protocol)) fail('Неизвестный протокол');
    const u = this.user(id), fresh = credentials();
    if (protocol === 'all') { u.secrets = fresh; u.shareToken = token(); }
    else if (protocol === 'share') u.shareToken = token();
    else u.secrets[protocol] = fresh[protocol];
    return this.transaction(() => { this.save(u); this.audit(`user.rotated.${protocol}`, u.name); return u; });
  }
  remove(id) {
    const u = this.user(id);
    this.transaction(() => { this.db.prepare('DELETE FROM users WHERE id=?').run(id); this.audit('user.deleted', u.name); });
  }
  audit(action, subject) { this.db.prepare('INSERT INTO audit(at,action,subject) VALUES(?,?,?)').run(new Date().toISOString(), action, subject); }
  events() { return this.db.prepare('SELECT * FROM audit ORDER BY id DESC LIMIT 80').all(); }
  // Админский пароль хранится как scrypt-хеш с солью, а не как восстанавливаемый пароль.
  setup(password) {
    if (typeof password !== 'string' || password.length < 12 || password.length > 256) fail('Пароль администратора: от 12 до 256 символов');
    return this.transaction(() => {
      if (this.getMeta('admin')) fail('Администратор уже создан', 409);
      const salt = randomBytes(16).toString('hex');
      this.setMeta('admin', { salt, hash: scryptSync(password, salt, 64).toString('hex') });
      this.audit('admin.created', 'admin');
    });
  }
  authenticate(password) {
    const admin = this.getMeta('admin');
    if (!admin || typeof password !== 'string' || password.length > 256) return false;
    return timingSafeEqual(scryptSync(password, admin.salt, 64), Buffer.from(admin.hash, 'hex'));
  }
  // В cookie выдаётся случайный токен, в таблицу попадает только SHA-256 от него.
  // Отдельный CSRF-токен нужен для изменяющих запросов; сессия живёт 12 часов.
  newSession() {
    const id = token(), csrf = token(), expires = Date.now() + 12 * 3600_000;
    this.db.prepare('DELETE FROM sessions WHERE expires < ?').run(Date.now());
    this.db.prepare('INSERT INTO sessions VALUES(?,?,?)').run(digest(id), csrf, expires);
    return { id, csrf, expires };
  }
  session(id) { return id ? this.db.prepare('SELECT csrf,expires FROM sessions WHERE hash=? AND expires>?').get(digest(id), Date.now()) : null; }
  logout(id) { this.db.prepare('DELETE FROM sessions WHERE hash=?').run(digest(id || '')); }
  close() { this.db.close(); }
}
