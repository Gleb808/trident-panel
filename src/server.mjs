import http from 'node:http';
import { readFileSync, existsSync } from 'node:fs';
import { resolve, join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { timingSafeEqual } from 'node:crypto';
import { Store } from './store.mjs';
import { publicUser, publicSettings, deploymentWarnings, effectiveStatus, fail, VERSIONS } from './domain.mjs';
import { clientBundle, serverFiles, revision, zip } from './configs.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
/** HTTP backend для локального запуска либо публикации через HTTPS reverse proxy Caddy. */
export function createApp({ dataDir = process.env.DATA_DIR || join(root, 'data'), statePath = process.env.AGENT_STATE || join(root, 'runtime', 'state.json') } = {}) {
  const store = new Store(dataDir), attempts = new Map();
  // Счётчики действуют в памяти процесса одну минуту. Не доверяем X-Forwarded-For:
  // за Caddy все посетители делят лимит по адресу соединения reverse proxy.
  function rate(req, kind, max = 10) {
    const now = Date.now(), key = `${kind}:${req.socket.remoteAddress}`;
    if (attempts.size > 5000) for (const [k, v] of attempts) if (v.until < now) attempts.delete(k);
    const entry = attempts.get(key);
    const next = !entry || entry.until < now ? { count: 1, until: now + 60_000 } : { ...entry, count: entry.count + 1 };
    attempts.set(key, next);
    if (next.count > max) fail('Слишком много запросов. Повторите через минуту.', 429);
  }
  // Готовность требует совпадения ревизии и свежего отчёта агента (не старше 90 секунд).
  // Сохранённый когда-то успех не должен выглядеть как работающий агент после его остановки.
  function status() {
    const s = store.settings(), desired = revision(s, store.users());
    let agent = null;
    try { agent = JSON.parse(readFileSync(statePath, 'utf8')); } catch {}
    const fresh = agent && Date.now() - Date.parse(agent.checkedAt) < 90_000;
    return { desired, connected: Boolean(fresh), synced: Boolean(fresh && agent.appliedRevision === desired && agent.status === 'applied'),
      agent: agent ? { ...agent, stale: !fresh } : null, warnings: deploymentWarnings(s), versions: VERSIONS };
  }
  const server = http.createServer(async (req, res) => {
    // Ответы API могут содержать секреты. Запрещаем кэширование и ограничиваем ресурсы интерфейса.
    const headers = { 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer',
      'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'", 'X-Frame-Options': 'DENY' };
    const send = (code, value, type = 'application/json; charset=utf-8', extra = {}) => {
      res.writeHead(code, { ...headers, 'Content-Type': type, ...extra }); res.end(Buffer.isBuffer(value) || typeof value === 'string' ? value : JSON.stringify(value));
    };
    try {
      const s = store.settings();
      // Host ограничен настроенным публичным адресом либо localhost с явным портом.
      // Это также препятствует обращениям к локальному backend через подменённый DNS/Host.
      const publicHost = `${s.host}:${s.panelPort}`;
      const host = req.headers.host || '';
      const local = /^(127\.0\.0\.1|localhost|\[::1\]):\d+$/.test(host);
      if (!local && host !== publicHost) fail('Недопустимый Host', 403);
      // Все изменяющие запросы, включая вход и выдачу по токену, требуют точного Origin.
      // Поэтому CLI-клиент API тоже должен передавать Origin, а не только cookie.
      const origin = `${local ? 'http' : 'https'}://${host}`;
      if (req.headers.origin && req.headers.origin !== origin) fail('Недопустимый Origin', 403);
      if (!['GET', 'HEAD'].includes(req.method) && req.headers.origin !== origin) fail('Требуется same-origin запрос', 403);
      const url = new URL(req.url, origin), path = url.pathname;
      const sid = (req.headers.cookie || '').split(';').map(v => v.trim()).find(v => v.startsWith('trident_sid='))?.slice(12);
      const session = store.session(sid);
      // Доступ администратора проверяем по сессии; для записи дополнительно требуем CSRF-токен.
      const auth = () => {
        if (!session) fail('Войдите в панель', 401);
        if (!['GET', 'HEAD'].includes(req.method) && req.headers['x-csrf-token'] !== session.csrf) fail('Сессия устарела. Обновите страницу.', 403);
      };
      // Небольшой JSON-объект — единственный входной формат; лимит действует при чтении потока.
      const body = async () => {
        if (!(req.headers['content-type'] || '').startsWith('application/json')) fail('Требуется JSON', 415);
        const chunks = []; let size = 0;
        for await (const chunk of req) { size += chunk.length; if (size > 32_768) fail('Слишком большой запрос', 413); chunks.push(chunk); }
        try { const b = JSON.parse(Buffer.concat(chunks).toString()); if (!b || typeof b !== 'object' || Array.isArray(b)) throw new Error(); return b; } catch { fail('Некорректный JSON'); }
      };
      const download = (files, name) => send(200, zip(files), 'application/zip', { 'Content-Disposition': `attachment; filename="${name}.zip"` });
      if (path === '/healthz') return send(200, { status: 'ok' });
      if (path === '/api/session' && req.method === 'GET') return send(200, { setupRequired: !store.getMeta('admin'), authenticated: Boolean(session), csrf: session?.csrf });
      if (path === '/api/setup' && req.method === 'POST') {
        rate(req, 'auth');
        // Первого администратора создают локально или через SSH-туннель.
        // Нужны одновременно локальный Host и loopback-адрес соединения.
        const loopback = ['127.0.0.1', '::1', '::ffff:127.0.0.1'].includes(req.socket.remoteAddress);
        if (!local || !loopback) fail('Первичная настройка доступна только через localhost / SSH-туннель', 403);
        store.setup((await body()).password);
        const session = store.newSession();
        return send(200, { csrf: session.csrf }, undefined, { 'Set-Cookie': cookie(session.id, local) });
      }
      if (path === '/api/login' && req.method === 'POST') {
        rate(req, 'auth');
        if (!store.authenticate((await body()).password)) fail('Неверный пароль', 401);
        const session = store.newSession();
        return send(200, { csrf: session.csrf }, undefined, { 'Set-Cookie': cookie(session.id, local) });
      }
      if (path === '/api/logout' && req.method === 'POST') {
        auth(); store.logout(sid); return send(200, {}, undefined, { 'Set-Cookie': cookie('', local, 0) });
      }
      if (path === '/api/access' && req.method === 'POST') {
        // Пользовательская выдача авторизуется секретом ссылки, без админской сессии.
        // Токен передаётся JSON-телом; в самой ссылке он находится после # и не уходит в URL запроса.
        rate(req, 'access', 30);
        const b = await body();
        if (typeof b.token !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(b.token)) fail('Ссылка недействительна', 404);
        const user = store.users().find(u => timingSafeEqual(Buffer.from(u.shareToken), Buffer.from(b.token)));
        if (!user || effectiveStatus(user) !== 'active') fail('Доступ отключён, истёк или ссылка отозвана', 404);
        // Само создание записи ещё не открывает доступ: комплект выдаём после подтверждения агента.
        if (!status().synced || deploymentWarnings(s).length) fail('Подключения ещё не применены на сервере. Обратитесь к администратору.', 409);
        const bundle = clientBundle(user, s);
        if (b.download) return download(bundle.files, 'trident-access');
        return send(200, { name: user.name, expiresAt: user.expiresAt, bundle });
      }
      if (path.startsWith('/api/')) {
        auth();
        if (path === '/api/overview' && req.method === 'GET') return send(200, { users: store.users().map(publicUser), settings: publicSettings(s), status: status(), events: store.events() });
        if (path === '/api/users' && req.method === 'POST') return send(201, publicUser(store.create(await body())));
        if (path === '/api/settings' && req.method === 'PUT') return send(200, publicSettings(store.updateSettings(await body())));
        if (path === '/api/server-bundle' && req.method === 'GET') {
          store.audit('server.exported', s.host); return download(serverFiles(s, store.users()), 'trident-server');
        }
        const match = path.match(/^\/api\/users\/([a-f0-9-]{36})(?:\/(bundle|share|rotate))?$/);
        if (match) {
          const [, id, action] = match;
          if (!action && req.method === 'PUT') return send(200, publicUser(store.update(id, await body())));
          if (!action && req.method === 'DELETE') { store.remove(id); return send(200, {}); }
          if (action === 'rotate' && req.method === 'POST') return send(200, publicUser(store.rotate(id, (await body()).protocol)));
          if (action === 'share' && req.method === 'GET') return send(200, { path: `/access#${store.user(id).shareToken}` });
          if (action === 'bundle' && req.method === 'GET') {
            // Админ может скачать конфиги заранее для проверки и ручного развёртывания.
            // Поэтому здесь нет требования synced, обязательного для персональной страницы выдачи.
            const u = store.user(id);
            if (effectiveStatus(u) !== 'active') fail('Сначала активируйте и продлите пользователя', 409);
            const bundle = clientBundle(u, s); store.audit('user.exported', u.name);
            return url.searchParams.has('download') ? download(bundle.files, `trident-${id.slice(0, 8)}`) : send(200, bundle);
          }
        }
        fail('Маршрут не найден', 404);
      }
      if (req.method !== 'GET') fail('Метод не разрешён', 405);
      // Явный список файлов не даёт превратить URL в произвольный путь на диске.
      const assets = { '/': ['index.html', 'text/html; charset=utf-8'], '/access': ['index.html', 'text/html; charset=utf-8'], '/app.js': ['app.js', 'text/javascript; charset=utf-8'], '/style.css': ['style.css', 'text/css; charset=utf-8'], '/favicon.svg': ['favicon.svg', 'image/svg+xml'] };
      if (!assets[path]) fail('Страница не найдена', 404);
      return send(200, readFileSync(join(root, 'public', assets[path][0])), assets[path][1]);
    } catch (error) {
      if (!error.status) console.error('Request failed:', error.code || error.name);
      if (!res.headersSent) send(error.status || 500, { error: error.status ? error.message : 'Внутренняя ошибка сервера' });
      else res.end();
    }
  });
  server.requestTimeout = 15_000; server.headersTimeout = 10_000;
  return { server, store };
}
// HttpOnly скрывает cookie от JavaScript; Secure обязателен для публичного HTTPS-входа.
function cookie(value, local, age = 43200) { return `trident_sid=${value}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${age}${local ? '' : '; Secure'}`; }
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const { server, store } = createApp();
  const port = Number(process.env.PORT || 8787);
  // Backend не слушает публичный интерфейс: TLS и внешний порт принадлежат Caddy.
  server.listen(port, '127.0.0.1', () => console.log(`TRIDENT: http://127.0.0.1:${port} · данные сохраняются локально`));
  const stop = () => server.close(() => { store.close(); process.exit(0); });
  process.on('SIGTERM', stop); process.on('SIGINT', stop);
}
