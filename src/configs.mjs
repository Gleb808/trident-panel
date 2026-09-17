import { effectiveStatus, validateSettings, digest } from './domain.mjs';

export const pretty = value => JSON.stringify(value, null, 2) + '\n';
/**
 * Собирает три клиентских конфигурации из одной записи пользователя.
 * Локальные SOCKS-порты 1080/1081/1082 различаются, чтобы клиенты можно было запустить вместе.
 * Результат содержит открытые секреты: выдавать его можно только через защищённый API.
 */
export function clientBundle(u, s) {
  s = validateSettings(s);
  const n = u.secrets.naive, m = u.secrets.mieru;
  const naive = { listen: 'socks://127.0.0.1:1080', proxy: `https://${encodeURIComponent(n.username)}:${encodeURIComponent(n.password)}@${s.host}:${s.naivePort}` };
  const mieru = { profiles: [{ profileName: 'trident', user: { name: m.username, password: m.password },
    servers: [{ domainName: s.host, portBindings: [{ portRange: `${s.mieruStart}-${s.mieruEnd}`, protocol: 'TCP' }] }],
    multiplexing: { level: 'MULTIPLEXING_LOW' }, mtu: 1400 }], activeProfile: 'trident', socks5Port: 1081, rpcPort: 8964, loggingLevel: 'INFO', socks5ListenLAN: false };
  const vless = { log: { loglevel: 'warning' }, inbounds: [{ listen: '127.0.0.1', port: 1082, protocol: 'socks', settings: { udp: true } }],
    outbounds: [{ tag: 'proxy', protocol: 'vless', settings: { vnext: [{ address: s.host, port: s.vlessPort,
      users: [{ id: u.secrets.vless.uuid, encryption: 'none' }] }] },
      streamSettings: { network: 'xhttp', xhttpSettings: { path: s.xhttpPath, mode: 'auto' }, security: 'reality', realitySettings: { serverName: s.realitySni, fingerprint: 'chrome', publicKey: s.publicKey, shortId: s.shortId, spiderX: '/' } } }] };
  // Vision flow относится к RAW/XTLS; с XHTTP оставляем обычный VLESS без flow.
  const q = new URLSearchParams({ encryption: 'none', security: 'reality', type: 'xhttp', path: s.xhttpPath, mode: 'auto', sni: s.realitySni, fp: 'chrome', pbk: s.publicKey, sid: s.shortId, spx: '/' });
  const vlessUri = `vless://${u.secrets.vless.uuid}@${s.host}:${s.vlessPort}?${q}#${encodeURIComponent(u.name + ' · VLESS')}`;
  const naiveUri = `naive+${naive.proxy}#${encodeURIComponent(u.name + ' · NaiveProxy')}`;
  // mierus — официальный текстовый формат mieru, без самодельной protobuf-кодировки.
  const mq = new URLSearchParams({ profile: 'trident', port: `${s.mieruStart}-${s.mieruEnd}`, protocol: 'TCP', mtu: '1400', multiplexing: 'MULTIPLEXING_LOW' });
  const mieruUri = `mierus://${encodeURIComponent(m.username)}:${encodeURIComponent(m.password)}@${s.host}?${mq}`;
  const readme = `TRIDENT · ${u.name}\n\nСсылки для импорта: naive.txt (naive+https), mieru.txt (mierus), vless.txt (VLESS + XHTTP + REALITY). Клиент должен поддерживать выбранный протокол; обычный HTTPS proxy не заменяет NaiveProxy.\n\nНативные JSON предназначены для отдельных CLI, это не универсальный конфиг любого приложения:\nNaiveProxy: naive naive.json; SOCKS5 127.0.0.1:1080.\nmieru: mieru apply config mieru.json; mieru start. SOCKS5 127.0.0.1:1081.\nXray 26.3.27+: xray run -config vless.json. SOCKS5 127.0.0.1:1082. В клиенте нужны XHTTP и REALITY, flow пустой.\n\nСрок: ${u.expiresAt || 'без срока'}.\nКонфиги содержат секреты. Не публикуйте комплект.\nПосле обновления с RAW/Vision скачайте новый VLESS-конфиг. Создание файлов само по себе не запускает сервер. Статус применения виден администратору.\n`;
  return { files: { 'naive.txt': naiveUri + '\n', 'mieru.txt': mieruUri + '\n', 'vless.txt': vlessUri + '\n', 'naive.json': pretty(naive), 'mieru.json': pretty(mieru), 'vless.json': pretty(vless), 'README.txt': readme }, naiveUri, mieruUri, vlessUri };
}
/** Полный желаемый набор серверных файлов. Отключённые и истёкшие доступы исключаются. */
export function serverFiles(s, users) {
  s = validateSettings(s);
  const active = users.filter(u => effectiveStatus(u) === 'active');
  // Пустой список basic_auth мог бы превратить forward_proxy в открытый прокси.
  // Поэтому при отсутствии активных пользователей целиком убираем этот обработчик;
  // Caddy продолжает обслуживать HTTPS панели и обычный ответ сайта.
  const auth = active.length ? active.map(u => `    basic_auth ${u.secrets.naive.username} ${u.secrets.naive.password}`).join('\n') : '';
  const proxy = active.length ? `  forward_proxy {\n${auth}\n    hide_ip\n    hide_via\n    probe_resistance\n    acl {\n      deny 0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.168.0.0/16 ::1/128 fc00::/7 fe80::/10\n      allow all\n    }\n  }\n` : '';
  const caddy = `{\n  admin 127.0.0.1:2019\n  order forward_proxy first\n  ${s.acmeEmail ? `email ${s.acmeEmail}` : ''}\n  servers {\n    protocols h1 h2${s.naiveQuic ? ' h3' : ''}\n  }\n  log {\n    exclude http.log.error\n  }\n}\n\n:${s.naivePort}, ${s.host}:${s.naivePort} {\n${proxy}  respond "Service available" 200\n}\n\nhttps://${s.host}:${s.panelPort} {\n  reverse_proxy 127.0.0.1:8787\n}\n`;
  // IPv6 wildcard в Linux/Go принимает также IPv4: A и AAAA работают на одном порту.
  const xray = { log: { loglevel: 'warning' }, inbounds: [{ tag: 'vless', listen: '::', port: s.vlessPort, protocol: 'vless',
    settings: { clients: active.map(u => ({ id: u.secrets.vless.uuid, email: u.id, level: 0 })), decryption: 'none' },
    streamSettings: { network: 'xhttp', xhttpSettings: { path: s.xhttpPath, mode: 'auto' }, security: 'reality', realitySettings: { show: false, target: `${s.realitySni}:${s.realityTargetPort}`, xver: 0,
      serverNames: [s.realitySni], privateKey: s.privateKey, shortIds: [s.shortId] } } }],
    outbounds: [{ tag: 'direct', protocol: 'freedom' }, { tag: 'block', protocol: 'blackhole' }],
    routing: { domainStrategy: 'IPIfNonMatch', rules: [{ type: 'field', ip: ['0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16', '172.16.0.0/12', '192.168.0.0/16', '::1/128', 'fc00::/7', 'fe80::/10'], outboundTag: 'block' }] } };
  const mita = { portBindings: [{ portRange: `${s.mieruStart}-${s.mieruEnd}`, protocol: 'TCP' }],
    users: active.map(u => ({ name: u.secrets.mieru.username, password: u.secrets.mieru.password })), loggingLevel: 'INFO', mtu: 1400 };
  return { 'Caddyfile': caddy, 'xray.json': pretty(xray), 'mita.json': pretty(mita) };
}
// Хешируем именно сгенерированные файлы. Имя/заметка не требуют перезапуска сервисов,
// а смена ключей, портов или исключение истёкшего пользователя меняют ревизию.
// Совпадение ревизий означает совпадение конфигов, но само по себе не доказывает доступность VPS.
export function revision(s, users) { return digest(serverFiles(s, users)); }

/**
 * Минимальный ZIP без зависимостей и сжатия: локальные заголовки, каталог, завершающая запись.
 * Предназначен для небольших комплектов конфигураций; ZIP64 и шифрование здесь не реализованы.
 * CRC32 проверяет целостность записи архива, но не защищает секреты и не заменяет HTTPS.
 */
export function zip(files) {
  const local = [], central = []; let offset = 0;
  for (const [name, content] of Object.entries(files)) {
    // Принимаем только плоские имена, которые задаёт генератор: без путей и каталогов.
    if (!/^[a-zA-Z0-9._-]+$/.test(name)) throw new Error('Invalid archive filename');
    const filename = Buffer.from(name), data = Buffer.from(content), crc = crc32(data);
    const h = Buffer.alloc(30); h.writeUInt32LE(0x04034b50); h.writeUInt16LE(20, 4); h.writeUInt16LE(0x800, 6);
    h.writeUInt16LE(33, 12); h.writeUInt32LE(crc, 14); h.writeUInt32LE(data.length, 18); h.writeUInt32LE(data.length, 22); h.writeUInt16LE(filename.length, 26);
    local.push(h, filename, data);
    const c = Buffer.alloc(46); c.writeUInt32LE(0x02014b50); c.writeUInt16LE(20, 4); c.writeUInt16LE(20, 6); c.writeUInt16LE(0x800, 8);
    c.writeUInt16LE(33, 14); c.writeUInt32LE(crc, 16); c.writeUInt32LE(data.length, 20); c.writeUInt32LE(data.length, 24); c.writeUInt16LE(filename.length, 28); c.writeUInt32LE(offset, 42);
    central.push(c, filename); offset += h.length + filename.length + data.length;
  }
  const cd = Buffer.concat(central), end = Buffer.alloc(22); end.writeUInt32LE(0x06054b50); end.writeUInt16LE(central.length / 2, 8); end.writeUInt16LE(central.length / 2, 10); end.writeUInt32LE(cd.length, 12); end.writeUInt32LE(offset, 16);
  return Buffer.concat([...local, cd, end]);
}
function crc32(data) { let c = 0xffffffff; for (const b of data) { c ^= b; for (let i = 0; i < 8; i++) c = (c >>> 1) ^ (0xedb88320 & -(c & 1)); } return (c ^ 0xffffffff) >>> 0; }
