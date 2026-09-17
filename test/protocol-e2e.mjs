// Реальные systemd units, LinuxAdapter и официальные клиенты. Только CI runner.
import assert from 'node:assert/strict';
import { execFile, spawn } from 'node:child_process';
import { promisify } from 'node:util';
import { readFileSync, writeFileSync, openSync, closeSync } from 'node:fs';
import { join } from 'node:path';
import http from 'node:http';
import http2 from 'node:http2';
import { defaults, credentials, digest } from '../src/domain.mjs';
import { serverFiles, clientBundle } from '../src/configs.mjs';
import { LinuxAdapter, reconcile } from '../src/agent.mjs';
const exec=promisify(execFile),dir=process.env.TRIDENT_E2E_DIR;
assert.equal(process.env.GITHUB_ACTIONS,'true'); assert.equal(process.getuid(),0); assert.ok(dir?.startsWith('/tmp/trident-e2e.'));
const certDir='/var/lib/trident-caddy/test-tls';
const origin=http.createServer((req,res)=>res.end('trident-e2e-ok'));
const target=http2.createSecureServer({key:readFileSync(join(certDir,'key.pem')),cert:readFileSync(join(certDir,'cert.pem')),minVersion:'TLSv1.3',allowHTTP1:true},(req,res)=>res.end('reality target'));
await new Promise(r=>origin.listen(18080,'203.0.113.10',r));
await new Promise(r=>target.listen(2443,'127.0.0.1',r));
const settings={...defaults(),host:'proxy.test',realitySni:'reality.test',realityTargetPort:2443};
const user={id:'ci-user',name:'CI user',status:'active',expiresAt:null,secrets:credentials()};
const gid=Number((await exec('/usr/bin/id',['-g','trident'])).stdout.trim());
const adapter=new LinuxAdapter('/var/lib/trident-agent',gid);
function snap(users) {
  const files=serverFiles(settings,users);
  // Единственная замена production-конфига: тестовый TLS сертификат вместо ACME.
  files.Caddyfile=files.Caddyfile.replace('  admin ', '  auto_https disable_certs\n  admin ');
  files.Caddyfile=files.Caddyfile.replaceAll(/(proxy\.test:\d+ \{\n)/g,`$1  tls ${certDir}/cert.pem ${certDir}/key.pem\n`);
  return {settings,files,revision:digest(files),hasUsers:users.length>0};
}
const clients=[];
function start(name,bin,args,env={}) {
  const fd=openSync(join(dir,name+'.log'),'w');
  const child=spawn(bin,args,{env:{...process.env,...env},stdio:['ignore',fd,fd]}); closeSync(fd);
  child.on('error',e=>console.error(name+': '+e.message)); clients.push(child); return child;
}
async function stopClients() {
  await Promise.all(clients.splice(0).map(child=>new Promise(r=>{
    if(child.exitCode!==null || child.signalCode!==null) return r();
    child.once('exit',r); child.kill('SIGTERM');
    const timer=setTimeout(()=>child.kill('SIGKILL'),2000); timer.unref();
  })));
}
function runClients(u) {
  const bundle=clientBundle(u,settings);
  for(const file of ['naive.json','mieru.json','vless.json']) writeFileSync(join(dir,file),bundle.files[file],{mode:0o600});
  start('naive',join(dir,'naive/naive'),[join(dir,'naive.json')],{SSL_CERT_FILE:join(certDir,'cert.pem')});
  start('mieru',join(dir,'mieru/mieru'),['run'],{MIERU_CONFIG_JSON_FILE:join(dir,'mieru.json')});
  start('vless','/usr/local/bin/xray',['run','-config',join(dir,'vless.json')]);
  return bundle;
}
async function traffic(port,expected=true) {
  for(let attempt=0;attempt<(expected?12:1);attempt++) {
    try {
      const {stdout}=await exec('/usr/bin/curl',['--silent','--show-error','--fail','--max-time','5','--noproxy','','--socks5-hostname',`127.0.0.1:${port}`,'http://203.0.113.10:18080'],{timeout:7000});
      assert.equal(stdout,'trident-e2e-ok');
      if(!expected) throw new Error(`Revoked credentials still work on ${port}`);
      return;
    } catch(e) {
      if(!expected) { if(e.message.startsWith('Revoked')) throw e; return; }
      if(attempt===11) throw new Error(`Native proxy traffic failed on ${port}: ${e.message}`);
      await new Promise(r=>setTimeout(r,500));
    }
  }
}
try {
  const applied=await reconcile(snap([user]),adapter); assert.equal(applied.status,'applied',applied.message);
  console.log('PASS: generated configs activated through LinuxAdapter and real systemd units');
  const bundle=runClients(user);
  // Импорт mierus проверяет официальный parser, а не нашу обратную реализацию URL.
  // mierus содержит профиль, а локальные порты и activeProfile задаются отдельно.
  const importEnv={env:{...process.env,MIERU_CONFIG_FILE:join(dir,'import.pb')}};
  await exec(join(dir,'mieru/mieru'),['apply','config',join(dir,'mieru.json')],importEnv);
  await exec(join(dir,'mieru/mieru'),['import','config',bundle.mieruUri],importEnv);
  for(const port of [1082,1080,1081]) { await traffic(port); console.log(`PASS: authenticated native proxy traffic on SOCKS ${port}`); }
  await stopClients();
  const rotated={...user,secrets:credentials()};
  const changed=await reconcile(snap([rotated]),adapter,applied); assert.equal(changed.status,'applied',changed.message);
  runClients(user); await new Promise(r=>setTimeout(r,1500));
  for(const port of [1080,1081,1082]) await traffic(port,false);
  console.log('PASS: revoked credentials rejected by all three servers');
  await stopClients(); runClients(rotated);
  for(const port of [1080,1081,1082]) await traffic(port);
  console.log('PASS: replacement credentials work for all three protocols');
  await stopClients();
  const empty=await reconcile(snap([]),adapter,changed); assert.equal(empty.status,'applied',empty.message);
  assert.ok(empty.services.filter(x=>x.protocol!=='naive').every(x=>x.state==='stopped-empty'));
  runClients(rotated); await new Promise(r=>setTimeout(r,1000)); await traffic(1080,false);
  console.log('PASS: empty user list stops Xray/mita and removes NaiveProxy access');
} catch(e) {
  // Логи содержат лишь одноразовые CI реквизиты; никогда не запускайте этот тест на VPS.
  for(const name of ['naive','mieru','vless']) { try { console.error(name+':\n'+readFileSync(join(dir,name+'.log'),'utf8').slice(-6000)); } catch {} }
  throw e;
} finally { await stopClients(); origin.close(); target.close(); }
