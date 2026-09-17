import { randomBytes, randomUUID, generateKeyPairSync, createHash } from 'node:crypto';
import { isIP } from 'node:net';

// Версии, на которые рассчитаны генераторы конфигов и проверки агента.
export const VERSIONS = { xray: '26.3.27', mieru: '3.37.0', caddyNaive: '2.11.2-naive' };
export const token = () => randomBytes(32).toString('base64url');
export const digest = value => createHash('sha256').update(typeof value === 'string' ? value : JSON.stringify(value)).digest('hex');
export function fail(message, status = 400) { throw Object.assign(new Error(message), { status }); }
/** REALITY: приватный ключ остаётся на сервере, публичный входит в клиентский конфиг. */
export function keys() {
  const { privateKey, publicKey } = generateKeyPairSync('x25519');
  return { privateKey: privateKey.export({ format: 'jwk' }).d, publicKey: publicKey.export({ format: 'jwk' }).x, shortId: randomBytes(8).toString('hex') };
}
// Начальные значения позволяют открыть панель, но example.com блокирует применение на VPS.
export function defaults() {
  return { host: 'proxy.example.com', naivePort: 443, naiveQuic: false, vlessPort: 8443,
    mieruStart: 20000, mieruEnd: 20009, panelPort: 9443, realitySni: 'www.microsoft.com',
    realityTargetPort: 443, xhttpPath: '/trident', acmeEmail: '', ...keys() };
}
// Разрешаем только доменное имя: URL, IP, порт и вставки в текстовый Caddyfile сюда не проходят.
export function validDomain(value) {
  return typeof value === 'string' && value.length <= 253 && !isIP(value) &&
    value.includes('.') && value.split('.').every(label => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(label));
}
export function validateSettings(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) fail('Некорректные настройки');
  const s = { xhttpPath: '/trident', ...input };
  if (typeof s.xhttpPath !== 'string' || !/^\/[A-Za-z0-9/_-]{0,127}$/.test(s.xhttpPath)) fail('XHTTP path: путь от /, до 128 символов, латиница, цифры, /, _ и -');
  for (const field of ['host', 'realitySni']) {
    if (!validDomain(s[field])) fail(field === 'host' ? 'Укажите домен сервера без https:// и порта' : 'Укажите корректный домен REALITY');
    s[field] = s[field].toLowerCase();
  }
  for (const field of ['naivePort', 'vlessPort', 'mieruStart', 'mieruEnd', 'panelPort', 'realityTargetPort']) {
    if (!Number.isInteger(s[field]) || s[field] < 1 || s[field] > 65535) fail('Порт должен быть целым числом от 1 до 65535');
  }
  if (s.mieruStart < 1025 || s.mieruEnd < s.mieruStart || s.mieruEnd - s.mieruStart > 99) fail('mieru: диапазон 1025–65535, не более 100 портов');
  if (typeof s.naiveQuic !== 'boolean') fail('Некорректная настройка QUIC');
  if (typeof s.acmeEmail !== 'string' || s.acmeEmail.length > 254 || (s.acmeEmail && !/^[a-zA-Z0-9._+%-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(s.acmeEmail))) fail('Некорректный email для сертификата');
  // Резервируем сами номера портов независимо от TCP/UDP и адреса привязки.
  // Это строже правил ОС: разные протоколы панели не смогут случайно получить один номер.
  // Проверку реально занятых сокетов выполняет агент на VPS; здесь проверяется наша схема.
  // realityTargetPort — исходящее соединение к цели REALITY, поэтому резервировать его не нужно.
  const ranges = [ ['NaiveProxy', s.naivePort, s.naivePort], ['VLESS', s.vlessPort, s.vlessPort],
    ['mieru', s.mieruStart, s.mieruEnd], ['Панель HTTPS', s.panelPort, s.panelPort],
    ['ACME', 80, 80], ['Caddy API', 2019, 2019], ['Панель backend', 8787, 8787], ['SSH', 22, 22] ];
  for (let i = 0; i < ranges.length; i++) for (let j = i + 1; j < ranges.length; j++) {
    if (ranges[i][1] <= ranges[j][2] && ranges[j][1] <= ranges[i][2]) fail(`Конфликт портов: ${ranges[i][0]} и ${ranges[j][0]}`);
  }
  return s;
}
export function validateUser(input, existing) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) fail('Некорректный пользователь');
  const name = typeof input.name === 'string' ? input.name.trim() : '';
  if (!name || name.length > 80 || /[\x00-\x1f]/.test(name)) fail('Имя: от 1 до 80 символов');
  const note = typeof input.note === 'string' ? input.note.trim() : '';
  if (note.length > 500) fail('Заметка: не более 500 символов');
  if (!['active', 'disabled'].includes(input.status)) fail('Неизвестный статус');
  let expiresAt = null;
  if (input.expiresAt) {
    const ms = Date.parse(input.expiresAt);
    if (!Number.isFinite(ms)) fail('Некорректная дата окончания');
    expiresAt = new Date(ms).toISOString();
  }
  return { name, note, status: input.status, expiresAt, ...(existing ? {} : { id: randomUUID(), createdAt: new Date().toISOString() }) };
}
/** У одного человека общий ID в базе, но отдельные секреты каждого протокола. */
export function credentials() {
  const suffix = randomBytes(8).toString('hex');
  return { naive: { username: `n_${suffix}`, password: token() }, mieru: { username: `m_${suffix}`, password: token() }, vless: { uuid: randomUUID() } };
}
/**
 * Истечение вычисляется по текущему времени без изменения записи пользователя.
 * Генератор исключает такой доступ, а агент применяет новую ревизию при следующем опросе.
 * Ручное отключение имеет приоритет над датой; null означает отсутствие срока.
 */
export function effectiveStatus(u, now = Date.now()) {
  return u.status === 'disabled' ? 'disabled' : u.expiresAt && Date.parse(u.expiresAt) <= now ? 'expired' : 'active';
}
// Для обычного списка пользователей убираем и протокольные секреты, и токен выдачи.
export function publicUser(u) {
  const { secrets, shareToken, ...rest } = u;
  return { ...rest, effectiveStatus: effectiveStatus(u) };
}
export function publicSettings(s) { const { privateKey, ...rest } = s; return rest; }
export function deploymentWarnings(s) {
  const warnings = [];
  if (s.host === 'proxy.example.com' || s.host.endsWith('.example.com')) warnings.push('Укажите свой домен сервера в настройках');
  if (s.realitySni === s.host) warnings.push('Домен REALITY должен отличаться от домена этого сервера');
  return warnings;
}
