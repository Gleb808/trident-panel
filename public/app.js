// Интерфейс не требует сборки и внешних библиотек. Источник данных — HTTP API;
// пароли, конфиги и токены не сохраняются в localStorage/sessionStorage.
const app = document.querySelector('#app'), dialog = document.querySelector('#dialog');
let csrf = '', model = null, page = 'users', query = '', filter = 'all', toastTimer;
const labels = { active: 'Активен', disabled: 'Отключён', expired: 'Истёк' };
// Все пользовательские строки, попадающие в HTML-шаблоны, экранируются.
// Содержимое самих конфигов показывается через textContent, а не как HTML.
const esc = v => String(v ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const date = v => v ? new Intl.DateTimeFormat('ru', { day: 'numeric', month: 'short', year: 'numeric', timeZone: 'UTC' }).format(new Date(v)) : 'Без срока';
const brand = `<div class="brand"><img src="/favicon.svg" alt=""><div>TRIDENT<small>ACCESS CONTROL</small></div></div>`;
const daysLeft = u => !u.expiresAt ? '' : Math.max(0, Math.ceil((Date.parse(u.expiresAt) - Date.now()) / 86400000));
function toast(text, bad = false) { const el = document.querySelector('#toast'); el.textContent = text; el.className = `show${bad ? ' bad' : ''}`; clearTimeout(toastTimer); toastTimer = setTimeout(() => el.className = '', 4500); }
// Браузер сам отправляет session cookie; JavaScript хранит только CSRF-токен.
// Сетевые ошибки показываем вызывающему экрану, потерю сессии переводим на вход.
async function api(path, { method = 'GET', body } = {}) {
  const r = await fetch('/api' + path, { method, headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf }, body: body === undefined ? undefined : JSON.stringify(body) });
  const result = await r.json();
  if (!r.ok) { if (r.status === 401 && path !== '/login') { dialog.close(); await boot(); } throw new Error(result.error || 'Ошибка запроса'); }
  return result;
}
async function refresh() { model = await api('/overview'); render(); }
function modal(title, content) {
  dialog.innerHTML = `<div class="modal-head"><h2>${esc(title)}</h2><button type="button" data-close aria-label="Закрыть">×</button></div>${content}`;
  dialog.querySelector('[data-close]').onclick = () => dialog.close();
  if (!dialog.open) dialog.showModal();
}
dialog.addEventListener('click', e => { if (e.target === dialog) { const r = dialog.getBoundingClientRect(); if (e.clientX < r.left || e.clientX > r.right || e.clientY < r.top || e.clientY > r.bottom) dialog.close(); } });
async function boot() {
  if (location.pathname === '/access') return accessPage();
  try {
    const session = await api('/session'); csrf = session.csrf || '';
    if (session.authenticated) return refresh();
    authPage(session.setupRequired);
  } catch (e) { app.innerHTML = `<main class="auth-shell"><div class="auth-card">${brand}<h1>Не удалось открыть панель</h1><p>${esc(e.message)}</p><button>Повторить</button></div></main>`; app.querySelector('button').onclick = () => location.reload(); }
}
function authPage(setup) {
  app.innerHTML = `<main class="auth-shell"><section class="auth-card">${brand}<div class="eyebrow">${setup ? 'Первый запуск' : 'С возвращением'}</div><h1>${setup ? 'Настроим ваш доступ' : 'Вход в панель'}</h1><p>${setup ? 'Создайте пароль администратора. Пользователями всех трёх протоколов вы будете управлять здесь.' : 'Один кабинет для NaiveProxy, mieru и VLESS.'}</p><form id="auth-form"><label>Пароль администратора<input name="password" type="password" autocomplete="${setup ? 'new-password' : 'current-password'}" minlength="${setup ? 12 : 1}" maxlength="256" required autofocus placeholder="${setup ? 'Не менее 12 символов' : 'Введите пароль'}"></label>${setup ? '<label class="confirm-password">Повторите пароль<input name="confirm" type="password" autocomplete="new-password" required></label>' : ''}<div class="error" role="alert"></div><button class="primary">${setup ? 'Создать панель →' : 'Войти →'}</button></form><div class="form-help">${setup ? 'Первичная настройка доступна через localhost или SSH-туннель.' : 'Секреты пользователей хранятся в зашифрованной базе.'}</div></section></main>`;
  const form = app.querySelector('form');
  form.onsubmit = async e => { e.preventDefault(); const b = new FormData(form), btn = form.querySelector('button');
    if (setup && b.get('password') !== b.get('confirm')) { form.querySelector('.error').textContent = 'Пароли не совпадают'; return; }
    btn.disabled = true;
    try { const r = await api(setup ? '/setup' : '/login', { method: 'POST', body: { password: b.get('password') } }); csrf = r.csrf; await refresh(); }
    catch (e) { form.querySelector('.error').textContent = e.message; } finally { btn.disabled = false; }
  };
}
function render() {
  const { users, settings: s, status } = model;
  const title = { users: 'Пользователи', server: 'Сервер и протоколы', audit: 'Журнал действий' }[page];
  app.innerHTML = `<div class="layout"><aside class="sidebar">${brand}<div class="nav-label">Рабочее пространство</div><nav class="nav" aria-label="Главное меню">${[['users','◫','Пользователи'],['server','⌘','Сервер'],['audit','≡','Журнал']].map(([id, icon, text]) => `<button data-page="${id}" class="${page === id ? 'active' : ''}" ${page === id ? 'aria-current="page"' : ''}><span>${icon}</span>${text}</button>`).join('')}</nav><div class="side-bottom"><small><i class="dot ${status.connected ? '' : 'off'}"></i>${status.connected ? 'Агент подключён' : 'Локальная панель'}<br>Один сервер · три протокола</small><button id="logout" class="ghost">↗ Выйти</button></div></aside><main class="main"><div class="topline"><div class="breadcrumb">Рабочее пространство <span>/</span> <span>${title}</span></div><span class="top-badge">${esc(s.host)}</span></div>${page === 'users' ? usersView() : page === 'server' ? serverView() : auditView()}</main></div>`;
  app.querySelectorAll('[data-page]').forEach(b => b.onclick = () => { page = b.dataset.page; render(); });
  app.querySelector('#logout').onclick = async () => { await api('/logout', { method: 'POST', body: {} }); await boot(); };
  app.querySelectorAll('[data-create]').forEach(b => b.onclick = () => userForm());
  app.querySelectorAll('[data-settings]').forEach(b => b.onclick = () => { page = 'server'; render(); });
  if (page === 'users') {
    app.querySelector('#search').oninput = e => { query = e.target.value; renderRows(); };
    app.querySelector('#filter').onchange = e => { filter = e.target.value; renderRows(); };
    renderRows();
  }
  if (page === 'server') bindSettings();
}
function notice() {
  const st = model.status;
  if (st.warnings.length) return `<div class="notice"><span>↗</span><div><strong>Нужна настройка VPS.</strong> ${esc(st.warnings.join('. '))}. <a href="#" data-settings>Настроить →</a></div></div>`;
  if (!st.connected) return `<div class="notice"><span>◷</span><div><strong>Агент сервера не подключён</strong><br>Конфиги сохраняются в панели. Применение и автоматическое отключение по сроку начнут работать после запуска агента на VPS: <code>sudo systemctl enable --now trident-agent</code>.</div></div>`;
  if (!st.synced) return `<div class="notice"><span>◷</span><div><strong>${st.agent?.status === 'error' ? 'Ошибка применения на VPS' : 'Ожидается применение изменений'}</strong><br>${esc(st.agent?.message || 'Агент обновит три сервиса.')} Старые подключения могут оставаться активными до успешного применения.</div></div>`;
  return `<div class="notice good"><span>✓</span><div>Три сервиса применили текущую конфигурацию. Проверка внешнего подключения выполняется отдельно.</div></div>`;
}
function protocols() {
  const s = model.settings;
  return `<div class="protocols">${[['naive','NaiveProxy','N',s.naivePort, s.naiveQuic ? 'TCP + UDP' : 'TCP','HTTPS · Caddy'],['mieru','mieru','M',`${s.mieruStart}–${s.mieruEnd}`,'TCP','Шифрованный транспорт · mita'],['vless','VLESS','V',s.vlessPort,'TCP','XHTTP · REALITY']].map(([id,name,letter,port,network,note]) => `<article class="protocol ${id}"><div class="proto-top"><h3>${name}</h3><span class="proto-letter">${letter}</span></div><div class="proto-port mono">:${port}<small>${network}</small></div><div class="muted">${note}</div></article>`).join('')}</div>`;
}
function usersView() {
  const users = model.users, active = users.filter(u => u.effectiveStatus === 'active').length;
  const soon = users.filter(u => u.effectiveStatus === 'active' && u.expiresAt && daysLeft(u) <= 7).length;
  return `<header class="page-head"><div><div class="eyebrow">Три протокола. Один доступ.</div><h1>Пользователи</h1><p>Создавайте, выдавайте и продлевайте подключения.</p></div><button class="primary" data-create>＋ Добавить пользователя</button></header><div class="stats"><div class="stat"><span class="label">Всего пользователей</span><strong>${users.length.toString().padStart(2,'0')}</strong><small>В едином реестре</small></div><div class="stat"><span class="label">Активных доступов</span><strong class="lime">${active.toString().padStart(2,'0')}</strong><small>По настройкам панели</small></div><div class="stat"><span class="label">Истекают за 7 дней</span><strong>${soon.toString().padStart(2,'0')}</strong><small>Можно продлить заранее</small></div><div class="stat"><span class="label">Протоколов в комплекте</span><strong>03</strong><small>С независимыми ключами</small></div></div>${protocols()}${notice()}<section class="section"><div class="section-head"><h2>Все пользователи <small>${users.length}</small></h2><div class="filters"><input class="search" id="search" aria-label="Поиск пользователей" placeholder="⌕  Найти по имени или заметке" value="${esc(query)}"><select id="filter" aria-label="Фильтр по статусу">${[['all','Все статусы'],['active','Активные'],['disabled','Отключённые'],['expired','Истёкшие']].map(([value,text]) => `<option value="${value}" ${filter === value ? 'selected' : ''}>${text}</option>`).join('')}</select></div></div><div id="rows"></div></section>`;
}
// Поиск меняет только таблицу: поле ввода не пересоздаётся на каждую букву
// и сохраняет фокус. На телефоне те же строки отображаются как карточки.
function renderRows() {
  const users = model.users.filter(u => `${u.name} ${u.note}`.toLowerCase().includes(query.toLowerCase()) && (filter === 'all' || u.effectiveStatus === filter));
  const el = app.querySelector('#rows');
  if (!users.length) {
    el.innerHTML = `<div class="empty"><div class="empty-symbol">⌘</div><h2>${model.users.length ? 'Ничего не найдено' : 'Первый доступ — за один шаг'}</h2><p>${model.users.length ? 'Попробуйте другое имя или измените фильтр.' : 'Добавьте человека. Панель подготовит персональный комплект NaiveProxy, mieru и VLESS.'}</p>${model.users.length ? '' : '<button class="primary" data-create>＋ Создать первый доступ</button>'}</div>`;
    el.querySelector('[data-create]')?.addEventListener('click', () => userForm()); return;
  }
  el.innerHTML = `<div class="table-wrap"><table><thead><tr><th>Пользователь</th><th>Статус</th><th>Подключения</th><th>Действует до</th><th>Действия</th></tr></thead><tbody>${users.map(u => `<tr><td><div class="person"><span class="avatar">${esc(u.name.slice(0,2).toUpperCase())}</span><div><strong>${esc(u.name)}</strong><small>${esc(u.note || u.id.slice(0,8))}</small></div></div></td><td><span class="badge ${u.effectiveStatus}">${labels[u.effectiveStatus]}</span></td><td><div class="chips"><span class="chip">Naive</span><span class="chip m">mieru</span><span class="chip v">VLESS</span></div></td><td>${date(u.expiresAt)}${u.expiresAt && u.effectiveStatus === 'active' ? `<br><small>${daysLeft(u)} дн. осталось</small>` : ''}</td><td><div class="row-actions"><button data-bundle="${u.id}" ${u.effectiveStatus !== 'active' ? 'disabled' : ''}>↓ Конфиги</button><button data-edit="${u.id}" aria-label="Изменить ${esc(u.name)}">Настроить</button></div></td></tr>`).join('')}</tbody></table></div><div class="table-foot"><span>Показано ${users.length} из ${model.users.length}</span><span>Один человек → три подключения</span></div>`;
  el.querySelectorAll('[data-edit]').forEach(b => b.onclick = () => userForm(model.users.find(u => u.id === b.dataset.edit)));
  el.querySelectorAll('[data-bundle]').forEach(b => b.onclick = () => showBundle(b.dataset.bundle).catch(e => toast(e.message, true)));
}
// Срок задаётся календарной датой включительно по UTC. Для «без срока»
// отправляется null; отключение хранится отдельно и не сбрасывает дату.
function userForm(u) {
  const defaultExpiry = new Date(Date.now() + 30 * 86400000).toISOString().slice(0,10);
  modal(u ? `Доступ · ${u.name}` : 'Новый пользователь', `<form id="user-form"><div class="form-grid"><label class="wide">Имя<input name="name" required maxlength="80" value="${esc(u?.name || '')}" placeholder="Например, Алексей"></label><label>Действует до<input name="expiresAt" type="date" value="${u ? u.expiresAt?.slice(0,10) || '' : defaultExpiry}"><small>Включительно, по UTC. Пусто — без срока.</small></label><label>Статус<select name="status"><option value="active">Активен</option><option value="disabled" ${u?.status === 'disabled' ? 'selected' : ''}>Отключён</option></select></label><label class="wide">Заметка<textarea name="note" maxlength="500" rows="2" placeholder="Команда, устройство или контакт">${esc(u?.note || '')}</textarea></label></div><p class="form-help">${u ? 'Изменения будут переданы агенту. В первой версии применение перезапускает прокси-сервисы.' : 'Будут созданы два независимых пароля и UUID. Все три доступа принадлежат одному человеку.'}</p><div class="error" role="alert"></div><div class="form-actions">${u ? '<button type="button" id="extend">＋ 30 дней</button>' : ''}<button type="submit" class="primary">${u ? 'Сохранить' : 'Создать три доступа'}</button></div></form>${u ? '<div class="tabs"><button id="rotate" class="ghost">Перевыпустить ключи</button><button id="revoke-share" class="ghost">Отозвать ссылку</button><button id="delete" class="danger ghost">Удалить пользователя</button></div>' : ''}`);
  const form = dialog.querySelector('form');
  form.onsubmit = async e => { e.preventDefault(); const data = Object.fromEntries(new FormData(form)), btn = form.querySelector('[type=submit]');
    data.expiresAt = data.expiresAt ? `${data.expiresAt}T23:59:59.999Z` : null; btn.disabled = true;
    try { const result = await api(u ? `/users/${u.id}` : '/users', { method: u ? 'PUT' : 'POST', body: data }); dialog.close(); await refresh(); toast(u ? 'Изменения сохранены' : 'Три доступа созданы'); if (!u) await showBundle(result.id); }
    catch(e) { form.querySelector('.error').textContent = e.message; } finally { btn.disabled = false; }
  };
  if (u) {
    dialog.querySelector('#extend').onclick = () => { const field = form.elements.expiresAt; field.value = new Date(Math.max(Date.now(), Date.parse(field.value) || 0) + 30 * 86400000).toISOString().slice(0,10); form.elements.status.value = 'active'; };
    dialog.querySelector('#rotate').onclick = () => confirmAction('Перевыпустить все ключи?', 'Старые конфиги и ссылка выдачи перестанут работать после применения на сервере. Потребуется выдать новый комплект.', async () => { await api(`/users/${u.id}/rotate`, { method:'POST', body:{ protocol:'all' } }); await refresh(); await showBundle(u.id); });
    dialog.querySelector('#revoke-share').onclick = () => confirmAction('Отозвать ссылку выдачи?', 'Старая ссылка перестанет открываться. Уже скачанные конфиги продолжат работать.', async () => { await api(`/users/${u.id}/rotate`, { method:'POST', body:{ protocol:'share' } }); dialog.close(); await refresh(); toast('Ссылка отозвана'); });
    dialog.querySelector('#delete').onclick = () => confirmAction(`Удалить ${u.name}?`, 'Запись и ключи будут удалены. Агент уберёт доступы из трёх сервисов при следующем успешном применении.', async () => { await api(`/users/${u.id}`, { method:'DELETE', body:{} }); dialog.close(); await refresh(); toast('Пользователь удалён'); });
  }
}
function confirmAction(title, text, action) { modal(title, `<p class="form-help">${esc(text)}</p><div class="error" role="alert"></div><div class="form-actions"><button id="cancel">Отмена</button><button class="primary" id="confirm">Подтвердить</button></div>`); dialog.querySelector('#cancel').onclick = () => dialog.close(); dialog.querySelector('#confirm').onclick = async e => { e.target.disabled = true; try { await action(); } catch(e) { dialog.querySelector('.error').textContent = e.message; } finally { const b = dialog.querySelector('#confirm'); if (b) b.disabled = false; } }; }
// Администратор может просмотреть черновые конфиги до подключения VPS.
// Это отличается от персональной выдачи: там сервер обязательно требует synced.
async function showBundle(id) {
  const u = model.users.find(u => u.id === id), bundle = await api(`/users/${id}/bundle`);
  modal(`Подключения · ${u.name}`, `${model.status.synced && !model.status.warnings.length ? '<div class="notice good">✓ Конфигурация применена на сервере.</div>' : '<div class="notice">Комплект подготовлен. Сервер ещё не подтвердил применение; файлы могут содержать тестовый домен.</div>'}<div class="bundle-actions"><a class="button-link" href="/api/users/${id}/bundle?download=1" download>↓ Скачать комплект ZIP</a><button id="share">Копировать ссылку выдачи</button></div><div class="tabs" id="bundle-tabs"><button data-file="naive.txt" class="active">NaiveProxy ↗</button><button data-file="mieru.txt">mieru ↗</button><button data-file="vless.txt">VLESS ↗</button><button data-file="naive.json">Naive CLI JSON</button><button data-file="mieru.json">mieru CLI JSON</button><button data-file="vless.json">Xray JSON</button><button data-file="README.txt">Инструкция</button></div><pre id="config-preview"></pre><button id="copy-config" class="ghost">Копировать конфиг</button><p class="form-help">Ссылки требуют поддержки протокола в приложении. JSON предназначены для нативных CLI; инструкция находится в комплекте. После обновления скачайте новый VLESS XHTTP-конфиг.</p>`);
  let file = 'naive.txt'; dialog.querySelector('#config-preview').textContent = bundle.files[file];
  dialog.querySelectorAll('[data-file]').forEach(b => b.onclick = () => { file = b.dataset.file; dialog.querySelectorAll('[data-file]').forEach(x => x.classList.toggle('active', x === b)); dialog.querySelector('#config-preview').textContent = bundle.files[file]; });
  dialog.querySelector('#copy-config').onclick = () => copy(bundle.files[file]);
  dialog.querySelector('#share').onclick = async () => { try { const r = await api(`/users/${id}/share`); await copy(location.origin + r.path); } catch(e) { toast(e.message, true); } };
}
async function copy(text) { try { await navigator.clipboard.writeText(text); toast('Скопировано'); } catch { toast('Не удалось скопировать. Выделите текст вручную.', true); } }
function serverView() {
  const s = model.settings;
  return `<header class="page-head"><div><div class="eyebrow">Инфраструктура</div><h1>Сервер и протоколы</h1><p>Отдельные порты, единое управление.</p></div><a href="/api/server-bundle" download>↓ Серверные конфиги</a></header>${notice()}${protocols()}<div class="settings-grid"><section class="section card-pad"><h2>Настройки подключений</h2><form id="settings"><div class="form-grid">${[['host','Домен сервера','text'],['acmeEmail','Email для TLS-сертификата','email'],['naivePort','Порт NaiveProxy','number'],['vlessPort','Порт VLESS','number'],['mieruStart','mieru: начало диапазона','number'],['mieruEnd','mieru: конец диапазона','number'],['panelPort','Порт панели HTTPS','number'],['realitySni','Домен REALITY / SNI','text'],['realityTargetPort','Порт целевого сайта REALITY','number'],['xhttpPath','Путь XHTTP','text']].map(([key,label,type]) => `<label>${label}<input name="${key}" type="${type}" value="${esc(s[key])}" ${type === 'number' ? 'min="1" max="65535" step="1"' : ''} ${key !== 'acmeEmail' ? 'required' : ''}></label>`).join('')}<label class="check"><input type="checkbox" name="naiveQuic" ${s.naiveQuic ? 'checked' : ''}>Разрешить NaiveProxy QUIC / UDP</label></div><div class="error" role="alert"></div><div class="form-actions"><button class="primary">Сохранить настройки</button></div></form></section><div><section class="section card-pad"><h2>Карта портов</h2><p class="settings-note">Порты закреплены за протоколами. Новый человек получает ключи, а не новые порты. Пересечения блокируются при сохранении.</p><div class="mini-list"><div class="mini-row"><span>Панель backend</span><code>127.0.0.1:8787</code></div><div class="mini-row"><span>Caddy API</span><code>127.0.0.1:2019</code></div><div class="mini-row"><span>ACME HTTP</span><code>:80 / TCP</code></div><div class="mini-row"><span>SSH · резерв</span><code>:22 / TCP</code></div></div></section><section class="section card-pad support-card"><h2>Применение</h2><p class="form-help">${model.status.connected ? esc(model.status.agent?.message || 'Агент доступен') : 'Агент ещё не запускался или давно не отвечает. Сохранение настроек не означает, что VPS уже настроен.'}</p><div class="mini-list version-list">${Object.entries(model.status.versions).map(([k,v]) => `<div class="mini-row"><span>${esc(k)}</span><code>${esc(v)}</code></div>`).join('')}</div><p class="form-help">Целевые версии для этой сборки. REALITY SNI нужно проверить из сети VPS перед запуском.</p></section></div></div>`;
}
function bindSettings() {
  const form = app.querySelector('#settings');
  form.onsubmit = async e => { e.preventDefault(); const data = Object.fromEntries(new FormData(form)); data.naiveQuic = form.elements.naiveQuic.checked;
    for (const k of ['naivePort','vlessPort','mieruStart','mieruEnd','panelPort','realityTargetPort']) data[k] = Number(data[k]);
    const b = form.querySelector('button'); b.disabled = true;
    try { await api('/settings', { method:'PUT', body:data }); await refresh(); toast('Настройки сохранены'); }
    catch(e) { form.querySelector('.error').textContent = e.message; } finally { b.disabled = false; }
  };
}
function auditView() {
  const names = { 'user.created':'Создан пользователь', 'user.updated':'Обновлён доступ', 'user.deleted':'Удалён пользователь', 'user.exported':'Открыт комплект конфигов', 'settings.updated':'Обновлены настройки сервера', 'server.exported':'Выгружены серверные конфиги', 'admin.created':'Создан администратор', 'user.rotated.all':'Перевыпущены все ключи', 'user.rotated.share':'Отозвана ссылка выдачи' };
  return `<header class="page-head"><div><div class="eyebrow">История изменений</div><h1>Журнал действий</h1><p>Последние 80 событий. Секреты в журнал не записываются.</p></div></header><section class="section">${model.events.map(e => `<div class="event"><div><p>${esc(names[e.action] || e.action)}</p><small>${esc(e.subject)}</small></div><time>${esc(new Date(e.at).toLocaleString('ru'))}</time></div>`).join('') || '<div class="empty">Событий пока нет</div>'}</section>`;
}
// Секрет персональной ссылки берётся из fragment (#), который браузер
// не отправляет в HTTP URL. Для проверки он передаётся телом POST-запроса.
async function accessPage() {
  const token = location.hash.slice(1);
  app.innerHTML = `<main class="access-main">${brand}<h1>Ваши подключения</h1><p class="muted">Проверяем доступ…</p></main>`;
  try {
    const r = await api('/access', { method:'POST', body:{ token } });
    app.innerHTML = `<main class="access-main">${brand}<div class="eyebrow">Персональный комплект</div><h1>${esc(r.name)}</h1><p class="muted">Действует до: ${date(r.expiresAt)}</p><section class="section access-bundle"><h2>Три подключения готовы</h2><p class="form-help">NaiveProxy · mieru · VLESS + XHTTP + REALITY</p><button class="primary" id="download-access">↓ Скачать комплект ZIP</button><div class="tabs"><button data-access-file="naive.txt" class="active">NaiveProxy</button><button data-access-file="mieru.txt">mieru</button><button data-access-file="vless.txt">VLESS</button></div><pre id="access-preview"></pre><button id="access-copy">Копировать</button><p class="form-help">Скопируйте ссылку в приложение с поддержкой выбранного протокола. VLESS требует XHTTP + REALITY, flow пустой. JSON в ZIP предназначены для нативных CLI; откройте README.txt. Не передавайте персональную ссылку другим людям.</p></section></main>`;
    let file = 'naive.txt'; app.querySelector('#access-preview').textContent = r.bundle.files[file];
    app.querySelectorAll('[data-access-file]').forEach(b => b.onclick = () => { file = b.dataset.accessFile; app.querySelectorAll('[data-access-file]').forEach(x => x.classList.toggle('active', x === b)); app.querySelector('#access-preview').textContent = r.bundle.files[file]; });
    app.querySelector('#access-copy').onclick = () => copy(r.bundle.files[file]);
    app.querySelector('#download-access').onclick = async () => {
      try { const response = await fetch('/api/access', { method:'POST', headers:{ 'Content-Type':'application/json' }, body:JSON.stringify({token, download:true}) });
        if (!response.ok) throw new Error((await response.json()).error);
        const url = URL.createObjectURL(await response.blob()), a = document.createElement('a'); a.href = url; a.download = 'trident-access.zip'; a.click(); setTimeout(() => URL.revokeObjectURL(url), 2000);
      } catch(e) { toast(e.message,true); }
    };
  } catch(e) { app.innerHTML = `<main class="auth-shell"><section class="auth-card">${brand}<h1>Доступ пока недоступен</h1><p>${esc(e.message)}</p><small>Обратитесь к администратору панели.</small></section></main>`; }
}
// Фоновое обновление не должно уничтожать незавершённую форму или поисковый ввод.
setInterval(async () => { if (model && !dialog.open && !app.querySelector('form') && !['INPUT','SELECT'].includes(document.activeElement?.tagName)) { try { await refresh(); } catch {} } }, 15000);
boot();
