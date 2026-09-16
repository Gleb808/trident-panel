import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createPrivateKey, createPublicKey } from 'node:crypto';
import http from 'node:http';
import { Store } from '../src/store.mjs';
import { defaults, validateSettings, effectiveStatus, publicUser, publicSettings } from '../src/domain.mjs';
import { clientBundle, serverFiles, revision, zip } from '../src/configs.mjs';
import { createApp } from '../src/server.mjs';
import { reconcile } from '../src/agent.mjs';

function fixture(t) { const dir = mkdtempSync(join(tmpdir(),'trident-test-')); const store = new Store(dir); t.after(() => {store.close();rmSync(dir,{recursive:true,force:true});}); return {dir,store}; }
const userInput = {name:'Алексей',note:'Команда',status:'active',expiresAt:null};
test('port allocator rejects overlapping ranges, reserved numbers, floats and reversed ranges', () => {
  const s = defaults(); assert.doesNotThrow(()=>validateSettings(s));
  for (const patch of [{vlessPort:443},{panelPort:20001},{mieruStart:8440,mieruEnd:8450},{naivePort:2019},{vlessPort:80},{panelPort:8787},{mieruStart:20010,mieruEnd:20000},{vlessPort:2.5},{naivePort:22},{host:'host.com\nmalicious'}]) assert.throws(()=>validateSettings({...s,...patch}));
});
test('three independent credentials persist encrypted, rotate selectively and redact in API models', t => {
  const {store,dir}=fixture(t),u=store.create(userInput);
  assert.notEqual(u.secrets.naive.password,u.secrets.mieru.password);
  assert.equal(u.secrets.vless.uuid.length,36);
  const m=store.rotate(u.id,'mieru'); assert.equal(m.secrets.naive.password,u.secrets.naive.password); assert.notEqual(m.secrets.mieru.password,u.secrets.mieru.password);
  assert.equal(store.user(u.id).secrets.mieru.password,m.secrets.mieru.password);
  assert.equal(publicUser(u).secrets,undefined);assert.equal(publicUser(u).shareToken,undefined);assert.equal(publicSettings(store.settings()).privateKey,undefined);
  store.db.exec('PRAGMA wal_checkpoint(TRUNCATE)'); const file=readFileSync(join(dir,'panel.sqlite'));
  assert.ok(!file.includes(Buffer.from(u.secrets.naive.password))); assert.ok(!file.includes(Buffer.from(store.settings().privateKey)));
  const old=store.user(u.id).shareToken;assert.notEqual(store.rotate(u.id,'all').shareToken,old);
});
test('expiration removes the same user from every server and changes desired revision without any DB write', t => {
  const {store}=fixture(t),u=store.create(userInput),s=store.settings(),files=serverFiles(s,[u]);
  assert.ok(files.Caddyfile.includes(u.secrets.naive.username));assert.equal(JSON.parse(files['mita.json']).users.length,1);
  assert.equal(JSON.parse(files['xray.json']).inbounds[0].settings.clients[0].id,u.secrets.vless.uuid);
  const expired={...u,expiresAt:'2000-01-01T00:00:00.000Z'};
  assert.equal(effectiveStatus(expired),'expired'); const empty=serverFiles(s,[expired]);
  assert.ok(!empty.Caddyfile.includes('  forward_proxy {'));assert.equal(JSON.parse(empty['mita.json']).users.length,0);assert.equal(JSON.parse(empty['xray.json']).inbounds[0].settings.clients.length,0);
  assert.notEqual(revision(s,[u]),revision(s,[expired]));
});
test('client/server pairs agree on ports, authentication and REALITY public key; local ports differ', t => {
  const {store}=fixture(t),u=store.create(userInput),s=store.settings(),b=clientBundle(u,s),server=serverFiles(s,[u]);
  const n=JSON.parse(b.files['naive.json']),m=JSON.parse(b.files['mieru.json']),v=JSON.parse(b.files['vless.json']);
  assert.equal(new URL(n.proxy).password,u.secrets.naive.password);
  assert.equal(m.profiles[0].user.password,JSON.parse(server['mita.json']).users[0].password);
  assert.equal(v.outbounds[0].settings.vnext[0].users[0].id,JSON.parse(server['xray.json']).inbounds[0].settings.clients[0].id);
  assert.deepEqual([new URL(n.listen).port,m.socks5Port,v.inbounds[0].port],['1080',1081,1082]);
  const privateKey=createPrivateKey({key:{kty:'OKP',crv:'X25519',d:s.privateKey,x:s.publicKey},format:'jwk'});
  assert.equal(createPublicKey(privateKey).export({format:'jwk'}).x,v.outbounds[0].streamSettings.realitySettings.publicKey);
  assert.ok(b.vlessUri.startsWith('vless://'));assert.ok(!JSON.stringify(b).includes(s.privateKey));
});
test('ZIP exports all filenames and valid stored-entry CRC values', t => {
  const {store}=fixture(t),b=clientBundle(store.create(userInput),store.settings()),z=zip(b.files);
  assert.equal(z.readUInt32LE(0),0x04034b50);assert.equal(z.readUInt32LE(z.length-22),0x06054b50);assert.equal(z.readUInt16LE(z.length-12),5);
  for(const name of Object.keys(b.files))assert.ok(z.includes(Buffer.from(name)));
  assert.throws(()=>zip({'../bad':'x'}));
});
test('reconcile is idempotent, prevents activation on validation failure, and rolls back partial activation', async()=>{
  const snap={settings:{...defaults(),host:'proxy.test.net'},revision:'new',hasUsers:true};let calls=[];
  const adapter={preflight:async()=>calls.push('preflight'),stage:async()=>calls.push('stage'),validate:async()=>calls.push('validate'),activate:async()=>calls.push('activate'),health:async()=>[{protocol:'naive',ok:true}],commit:async()=>calls.push('commit'),rollback:async()=>calls.push('rollback')};
  const ok=await reconcile(snap,adapter);assert.equal(ok.status,'applied');assert.deepEqual(calls,['preflight','stage','validate','activate','commit']);
  calls=[];await reconcile(snap,adapter,ok);assert.deepEqual(calls,[]);
  const badValidate=await reconcile(snap,{...adapter,validate:async()=>{throw Error('invalid');}});assert.equal(badValidate.status,'error');assert.ok(!calls.includes('activate'));
  calls=[];const bad=await reconcile(snap,{...adapter,activate:async()=>{throw Error('failed');}},{appliedRevision:'old'});assert.equal(bad.rollback,'restored');assert.equal(bad.appliedRevision,'old');assert.ok(calls.includes('rollback'));
  const blocked=await reconcile({...snap,settings:defaults()},adapter);assert.equal(blocked.status,'blocked');
});
test('HTTP lifecycle: auth, CSRF, CRUD, ZIP, access gating, token revocation, expiration, host rejection and persistence', async t=>{
  const dir=mkdtempSync(join(tmpdir(),'trident-http-')),statePath=join(dir,'state.json');
  const {server,store}=createApp({dataDir:dir,statePath});await new Promise(r=>server.listen(0,'127.0.0.1',r));
  t.after(async()=>{await new Promise(r=>server.close(r));store.close();rmSync(dir,{recursive:true,force:true});});
  const base=`http://127.0.0.1:${server.address().port}`;let cookie='',csrf='';
  const request=async(path,method='GET',body,extra={})=>fetch(base+'/api'+path,{method,headers:{Origin:base,'Content-Type':'application/json',Cookie:cookie,'X-CSRF-Token':csrf,...extra},body:body===undefined?undefined:JSON.stringify(body)});
  assert.equal((await request('/overview')).status,401);
  assert.equal((await request('/setup','POST',{password:'short'})).status,400);
  const setup=await request('/setup','POST',{password:'correct-horse-battery'});assert.equal(setup.status,200);cookie=setup.headers.get('set-cookie').split(';')[0];csrf=(await setup.json()).csrf;
  assert.equal((await request('/setup','POST',{password:'correct-horse-battery'})).status,409);
  assert.equal((await request('/users','POST',userInput,{'X-CSRF-Token':''})).status,403);
  assert.equal((await request('/users','POST',userInput,{Origin:'https://evil.test'})).status,403);
  const created=await request('/users','POST',userInput);assert.equal(created.status,201);const u=await created.json();assert.equal(u.secrets,undefined);
  let response=await request(`/users/${u.id}/bundle?download=1`);assert.equal(response.status,200);assert.equal(response.headers.get('content-type'),'application/zip');
  const token=(await(await request(`/users/${u.id}/share`)).json()).path.split('#')[1];
  assert.equal((await request('/access','POST',{token:'я'.repeat(43)})).status,404);
  assert.equal((await request('/access','POST',{token})).status,409);
  assert.equal((await request('/settings','PUT',{vlessPort:443})).status,400);
  assert.equal((await request('/settings','PUT',{host:'proxy.test.net'})).status,200);
  const rev=revision(store.settings(),store.users());writeFileSync(statePath,JSON.stringify({checkedAt:new Date().toISOString(),status:'applied',appliedRevision:rev}));
  assert.equal((await request('/access','POST',{token})).status,200);
  await request(`/users/${u.id}/rotate`,'POST',{protocol:'share'});assert.equal((await request('/access','POST',{token})).status,404);
  await request(`/users/${u.id}`,'PUT',{expiresAt:'2000-01-01T00:00:00Z'});assert.equal((await request(`/users/${u.id}/bundle`)).status,409);
  const rejectedHost = await new Promise((resolve,reject)=>{ const req=http.request(base+'/api/overview',{headers:{Host:'evil.test'}},res=>{res.resume();res.on('end',()=>resolve(res.statusCode));}); req.on('error',reject);req.end(); });
  assert.equal(rejectedHost,403);
  const overview=await(await request('/overview')).json();assert.equal(overview.status.synced,false);assert.equal(overview.users[0].effectiveStatus,'expired');assert.ok(!JSON.stringify(overview).includes(store.user(u.id).secrets.naive.password));
  await request('/logout','POST',{});assert.equal((await request('/overview')).status,401);
  const login=await request('/login','POST',{password:'correct-horse-battery'});assert.equal(login.status,200);
  const again=new Store(dir,{readOnly:true});assert.equal(again.users().length,1);again.close();
});
