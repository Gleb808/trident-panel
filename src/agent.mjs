import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdirSync, writeFileSync, readFileSync, existsSync, renameSync, chmodSync, chownSync, rmSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import net from 'node:net';
import tls from 'node:tls';
import { Store } from './store.mjs';
import { serverFiles } from './configs.mjs';
import { digest, deploymentWarnings, effectiveStatus } from './domain.mjs';

const exec = promisify(execFile);
// Имена сервисов и пути команд заданы кодом, а не приходят из HTTP-запроса.
const services = { naive: 'trident-caddy', vless: 'trident-xray', mieru: 'trident-mita' };
const commands = { caddy: '/usr/local/bin/caddy', xray: '/usr/local/bin/xray', mita: '/usr/local/bin/mita', systemctl: '/usr/bin/systemctl', ss: '/usr/bin/ss' };
/** Проверяем цель REALITY из сети VPS до изменения рабочих конфигураций. */
export function probeRealityTarget(settings, timeoutMs = 8000) {
  const host = settings.realitySni, port = settings.realityTargetPort;
  return new Promise((resolve, reject) => {
    let socket, settled = false;
    const finish = error => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket?.destroy();
      if (error) reject(error); else resolve();
    };
    // Общий таймер ограничивает также DNS lookup, а не только простой TLS-сокета.
    const timer = setTimeout(() => finish(new Error(`Цель REALITY ${host}:${port} не ответила за ${timeoutMs / 1000} с. Проверьте DNS, исходящий TCP и доступность сайта из сети VPS`)), timeoutMs);
    try {
      socket = tls.connect({ host, port, servername: host, minVersion: 'TLSv1.3', ALPNProtocols: ['h2'], rejectUnauthorized: true });
      socket.once('error', () => finish(new Error(`Не удалось установить проверенное TLS 1.3 соединение с целью REALITY ${host}:${port}. Проверьте DNS, исходящий TCP, сертификат сайта и поддержку TLS 1.3`)));
      socket.once('secureConnect', () => {
        if (socket.getProtocol() !== 'TLSv1.3' || socket.alpnProtocol !== 'h2') {
          finish(new Error(`Цель REALITY ${host}:${port} не согласовала TLS 1.3 и HTTP/2 (h2). Выберите сайт с поддержкой обоих протоколов`));
        } else finish();
      });
    } catch {
      finish(new Error(`Не удалось проверить цель REALITY ${host}:${port}. Проверьте домен и порт целевого сайта`));
    }
  });
}
/** Одна read-транзакция даёт согласованный набор настроек и пользователей из SQLite. */
export function snapshot(store) {
  store.db.exec('BEGIN');
  try { const settings = store.settings(), users = store.users(), files = serverFiles(settings, users); store.db.exec('COMMIT');
    return { settings, files, revision: digest(files), hasUsers: users.some(u => effectiveStatus(u) === 'active') };
  } catch (e) { store.db.exec('ROLLBACK'); throw e; }
}
// rename в том же каталоге не даёт панели прочитать наполовину записанный JSON состояния.
function writeJson(path, data) { const tmp = path + '.tmp'; writeFileSync(tmp, JSON.stringify(data, null, 2) + '\n', { mode: 0o640 }); renameSync(tmp, path); }
/**
 * Применение: проверка окружения → подготовка → валидация → запуск → проверка → фиксация.
 * Общей транзакции у трёх процессов нет. После начала активации любую ошибку компенсируем откатом.
 * appliedRevision меняется только после успешной проверки всех ожидаемых сервисов.
 */
export async function reconcile(snap, adapter, previous = null) {
  const warnings = deploymentWarnings(snap.settings);
  if (warnings.length) return { status: 'blocked', message: warnings.join('. '), appliedRevision: previous?.appliedRevision || null };
  if (previous?.appliedRevision === snap.revision && previous.status === 'applied') {
    const healthy = await adapter.health(snap);
    if (healthy.every(x => x.ok)) return { ...previous, services: healthy };
  }
  let changed = false;
  try {
    await adapter.preflight(snap);
    await adapter.stage(snap);
    await adapter.validate(snap);
    // Даже частично завершившаяся activate могла заменить файлы или перезапустить один сервис.
    changed = true;
    await adapter.activate(snap);
    const health = await adapter.health(snap);
    if (!health.every(x => x.ok)) throw new Error(`Не запустились сервисы: ${health.filter(x => !x.ok).map(x => services[x.protocol] || x.protocol).join(', ')}. Проверьте journalctl -u ИМЯ_СЛУЖБЫ -n 50`);
    await adapter.commit(snap);
    return { status: 'applied', appliedRevision: snap.revision, services: health,
      message: 'Конфигурация применена. Процессы и TCP-порты проверены; внешнее подключение не проверялось.' };
  } catch (e) {
    let rollback = 'not-needed';
    if (changed) { try { await adapter.rollback(); rollback = 'restored'; } catch { rollback = 'failed'; } }
    return { status: 'error', appliedRevision: previous?.appliedRevision || null, rollback,
      message: `${e.message}. ${rollback === 'restored' ? 'Возвращена предыдущая конфигурация; изменения доступов ещё не действуют.' : rollback === 'failed' ? 'Откат не завершён. Требуется проверить сервисы вручную.' : 'Рабочая конфигурация не менялась.'}` };
  }
}
export class LinuxAdapter {
  constructor(runtime, gid) { this.runtime = runtime; this.gid = gid; this.candidate = join(runtime, 'candidate'); this.current = join(runtime, 'current'); this.backup = null; }
  async run(tool, args, name = tool) {
    // execFile передаёт аргументы без shell. Вывод ошибки команды не отдаём в панель:
    // диагностический вывод серверных бинарников может содержать секреты конфигурации.
    try { return (await exec(commands[tool], args, { timeout: 25000, maxBuffer: 1024 * 1024, encoding: 'utf8', env: { ...process.env, HOME: join(this.runtime, 'validation-home') } })).stdout; }
    catch (e) {
      const action = tool === 'systemctl' ? `${name} ${args.slice(0, 2).join(' ')}` : name;
      throw new Error(`Ошибка команды ${action} (код ${Number.isInteger(e.code) ? e.code : 'timeout/exec'}); проверьте журнал соответствующей службы на VPS`);
    }
  }
  writeFiles(dir, files) {
    // Каждый файл заменяется через rename отдельно. Весь набор файлов не атомарен;
    // согласованность между сервисами обеспечивают порядок активации и последующий откат.
    mkdirSync(dir, { recursive: true, mode: 0o750 }); chownSync(dir, 0, this.gid); chmodSync(dir, 0o750);
    for (const [name, content] of Object.entries(files)) { const p = join(dir, name); writeFileSync(p + '.tmp', content, { mode: 0o640 }); chownSync(p + '.tmp', 0, this.gid); renameSync(p + '.tmp', p); }
  }
  async preflight(snap) {
    if (snap.hasUsers) await probeRealityTarget(snap.settings);
    // Проверяем установленные версии и наличие специального модуля NaiveProxy в Caddy.
    const versions = await Promise.all([this.run('xray', ['version']), this.run('mita', ['version']), this.run('caddy', ['version'])]);
    if (!versions[0].includes('26.3.27') || !versions[1].includes('3.37.0') || !versions[2].includes('2.11.2')) throw new Error('Установленные версии отличаются от проверяемых: Xray 26.3.27, mita 3.37.0, Caddy 2.11.2');
    const modules = await this.run('caddy', ['list-modules']);
    if (!modules.includes('http.handlers.forward_proxy')) throw new Error('В Caddy отсутствует модуль forward_proxy');
    // Занятый порт разрешён лишь основному процессу соответствующего сервиса TRIDENT.
    // ss проверяет реальные TCP/UDP-сокеты; проверка настроек ранее исключила пересечения номеров.
    const pids = {};
    for (const [proto, name] of Object.entries(services)) pids[proto] = (await this.run('systemctl', ['show', '--property=MainPID', '--value', name])).trim();
    const socketTable = await this.run('ss', ['-H', '-ltnup']);
    const s = snap.settings;
    const wanted = [ ['naive', s.naivePort, s.naivePort, 'tcp'], ['naive', s.panelPort, s.panelPort, 'tcp'], ['naive', 80, 80, 'tcp'], ['naive', 2019, 2019, 'tcp'],
      ...(s.naiveQuic ? [['naive', s.naivePort, s.naivePort, 'udp'], ['naive', s.panelPort, s.panelPort, 'udp']] : []),
      ['vless', s.vlessPort, s.vlessPort, 'tcp'], ['mieru', s.mieruStart, s.mieruEnd, 'tcp'] ];
    for (const line of socketTable.split('\n')) {
      const cols = line.trim().split(/\s+/), transport = cols[0], local = cols[4];
      const port = Number(local?.match(/:(\d+)$/)?.[1]);
      for (const [owner, start, end, proto] of wanted) if (proto === transport && port >= start && port <= end) {
        const holders = [...line.matchAll(/pid=(\d+)/g)].map(m => m[1]);
        if (!holders.length || holders.some(pid => pid !== pids[owner])) throw new Error(`Порт ${port}/${proto} занят другим процессом`);
      }
    }
  }
  async stage(snap) {
    // Кандидат не используется работающими сервисами. Откатываемся к последнему набору,
    // для которого уже был сохранён manifest после успешной проверки.
    this.writeFiles(this.candidate, snap.files);
    this.backup = existsSync(join(this.current, 'manifest.json')) ? {
      manifest: JSON.parse(readFileSync(join(this.current, 'manifest.json'), 'utf8')),
      files: Object.fromEntries(['Caddyfile', 'xray.json', 'mita.json'].map(n => [n, readFileSync(join(this.current, n), 'utf8')]))
    } : null;
  }
  async validate() {
    await this.run('caddy', ['validate', '--config', join(this.candidate, 'Caddyfile'), '--adapter', 'caddyfile'], 'caddy validate');
    await this.run('xray', ['run', '-test', '-config', join(this.candidate, 'xray.json')], 'xray run -test');
    // У mita нет отдельной команды validate: JSON читает `mita run` при старте.
    // Ошибка его запуска обнаруживается после активации и приводит к откату.
  }
  async startServices(hasUsers) {
    // Первая версия использует restart, включая изменения пользователей: активные соединения
    // прерываются. Здесь пока нет горячего обновления через API каждого протокола.
    // При пустом списке VLESS и mieru останавливаются, а Caddy нужен для входа в панель.
    await this.run('systemctl', ['restart', services.naive]);
    for (const key of ['vless', 'mieru']) await this.run('systemctl', [hasUsers ? 'restart' : 'stop', services[key]]);
  }
  async activate(snap) { this.writeFiles(this.current, snap.files); await this.startServices(snap.hasUsers); }
  async health(snap) {
    // Проверяем состояние systemd и TCP connect на localhost с короткими повторами при запуске.
    // Это не проверка авторизации, TLS/REALITY, UDP/QUIC, внешнего firewall или передачи трафика.
    const s = snap.settings, result = [];
    for (const [key, name] of Object.entries(services)) {
      const shouldRun = key === 'naive' || snap.hasUsers;
      let ok = false;
      for (let attempt = 0; attempt < 8; attempt++) {
        const state = (await this.run('systemctl', ['show', '--property=ActiveState', '--value', name])).trim();
        const ports = key === 'naive' ? [s.naivePort, s.panelPort] : key === 'vless' ? [s.vlessPort] : Array.from({length:s.mieruEnd-s.mieruStart+1}, (_, i) => s.mieruStart+i);
        ok = shouldRun ? state === 'active' && (await Promise.all(ports.map(p => probe(p)))).every(Boolean) : state === 'inactive';
        if (ok || attempt === 7) break;
        await new Promise(r => setTimeout(r, 750));
      }
      result.push({ protocol: key, ok, state: shouldRun ? (ok ? 'listening' : 'failed') : (ok ? 'stopped-empty' : 'failed') });
    }
    return result;
  }
  async commit(snap) {
    // Manifest — отметка проверенного набора и данные для отката, включая секретные настройки.
    // На него распространяются те же файловые права, что и на серверные конфиги.
    this.writeFiles(this.current, { 'manifest.json': JSON.stringify({ revision: snap.revision, settings: snap.settings, hasUsers: snap.hasUsers }) });
  }
  async rollback() {
    // При первой неудачной активации предыдущего manifest нет: останавливаем сервисы,
    // но не сообщаем об успешном откате. Дальнейшая проверка нужна администратору.
    if (!this.backup) { for (const name of Object.values(services)) await this.run('systemctl', ['stop', name]); throw new Error('No previous working configuration'); }
    this.writeFiles(this.current, this.backup.files);
    await this.startServices(this.backup.manifest.hasUsers);
    if (!(await this.health(this.backup.manifest)).every(r => r.ok)) throw new Error('Rollback health check failed');
  }
}
function probe(port) { return new Promise(resolve => { const socket = net.connect({ host: '127.0.0.1', port }); const done = ok => { socket.destroy(); resolve(ok); }; socket.setTimeout(1000); socket.once('connect', () => done(true)); socket.once('error', () => done(false)); socket.once('timeout', () => done(false)); }); }
async function main() {
  if (process.platform !== 'linux' || process.getuid?.() !== 0) throw new Error('Linux-агент запускается через systemd от root. Локальная панель работает отдельно.');
  const runtime = process.env.RUNTIME_DIR || '/var/lib/trident-agent', data = process.env.DATA_DIR || '/var/lib/trident';
  const gid = Number((await exec('/usr/bin/id', ['-g', 'trident'])).stdout.trim());
  mkdirSync(runtime, { recursive: true, mode: 0o750 }); chownSync(runtime, 0, gid); chmodSync(runtime, 0o750);
  // PID-файл не допускает обычного повторного запуска агента; мёртвый PID можно убрать.
  const lock = join(runtime, 'agent.lock');
  if (existsSync(lock)) {
    const pid = Number(readFileSync(lock, 'utf8'));
    if (Number.isSafeInteger(pid) && pid > 0) { let alive = false; try { process.kill(pid, 0); alive = true; } catch {} if (alive) throw new Error('Агент уже запущен'); }
    rmSync(lock);
  }
  writeFileSync(lock, String(process.pid), { flag: 'wx', mode: 0o600 });
  // Агент читает базу в режиме readOnly и пишет только runtime-файлы. Источник желаемых
  // пользователей остаётся у панели, состояние применения публикуется в отдельном JSON.
  const store = new Store(data, { readOnly:true }), adapter = new LinuxAdapter(runtime, gid), statePath = join(runtime, 'state.json');
  let previous = null, stopping = false;
  try { previous = JSON.parse(readFileSync(statePath, 'utf8')); } catch {}
  for (const signal of ['SIGTERM', 'SIGINT']) process.on(signal, () => { stopping = true; });
  try {
    do {
      try { const snap = snapshot(store); previous = { ...(await reconcile(snap, adapter, previous)), desiredRevision: snap.revision, checkedAt: new Date().toISOString() }; }
      catch { previous = { status:'error', message:'Не удалось прочитать конфигурацию. Проверьте базу и ключ шифрования.', checkedAt:new Date().toISOString() }; }
      writeJson(statePath, previous); chownSync(statePath, 0, gid);
      if (process.argv.includes('--once')) break;
      // Новый снимок раз в 30 секунд также подхватывает истечение срока без записи в базу.
      for (let i = 0; i < 30 && !stopping; i++) await new Promise(r => setTimeout(r, 1000));
    } while (!stopping);
  } finally { store.close(); rmSync(lock, { force:true }); }
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main().catch(e => { console.error(e.message); process.exitCode = 1; });
