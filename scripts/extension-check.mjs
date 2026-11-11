import { chromium } from 'playwright';
import { createServer } from 'node:http';
import { mkdtemp,rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve,dirname,join } from 'node:path';
import { fileURLToPath } from 'node:url';
import assert from 'node:assert/strict';
const root=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const profile=await mkdtemp(join(tmpdir(),'tracehawk-extension-test-'));
const headers={'Content-Type':'application/json','X-TraceHawk-Control':'1'};
async function api(path,body){const r=await fetch('http://127.0.0.1:4000/api'+path,{method:body?'POST':'GET',headers,...(body?{body:JSON.stringify(body)}:{})});assert.ok(r.ok,`API ${path}: ${r.status}`);return r.json();}
const target=createServer((req,res)=>{if(req.url.startsWith('/api/')){res.setHeader('Content-Type','application/json');res.end(JSON.stringify({ok:true,token:'secret-response-value'}));}else{res.setHeader('Content-Type','text/html');res.end('<title>Owned extension test</title><p>Signed-in application</p>');}});
await new Promise(r=>target.listen(0,'127.0.0.1',r));
let context,projectId,sessionId;
try{
  const origin=`http://127.0.0.1:${target.address().port}`;
  const project=await api('/projects',{name:'Temporary Chrome extension validation',targetUrl:origin,allowedOrigins:[origin]});projectId=project.project.id;
  
  const extension=resolve(root,'extensions/tracehawk');
  context=await chromium.launchPersistentContext(profile,{channel:'chromium',headless:true,args:[`--disable-extensions-except=${extension}`,`--load-extension=${extension}`]});
  const worker=context.serviceWorkers()[0]||await context.waitForEvent('serviceworker');
  const page=await context.newPage();await page.goto(origin);
  const other=await context.newPage();await other.goto(origin+'/unrelated');
  const tabId=await worker.evaluate(async url=>(await chrome.debugger.getTargets()).find(t=>t.url===url+'/').tabId,origin);
  const popup=await context.newPage();await popup.goto('chrome-extension://'+new URL(worker.url()).host+'/popup.html');
  const started=await popup.evaluate(async({projectId,tabId,url})=>chrome.runtime.sendMessage({action:'start_current_tab',projectId,tabId,url}),{projectId,tabId,url:origin});
  // Messages sent from the worker itself are not delivered to itself; use its extension popup instead.
  if(!started?.success)throw Error(started?.error||'Extension did not start');
  sessionId=started.sessionId;
  await api(`/sessions/${sessionId}/focus`,{});
  await new Promise(r=>setTimeout(r,2200));
  assert.equal(await worker.evaluate(async tabId=>(await chrome.tabs.get(tabId)).active,tabId),true,'Show connected browser selects the recorded tab');
  await page.evaluate(()=>fetch('/api/selected',{headers:{Authorization:'Bearer secret-request-value'}}));
  await other.evaluate(()=>fetch('/api/unrelated'));
  let traffic;
  for(let i=0;i<50;i++){traffic=await api(`/sessions/${sessionId}/traffic`);if(traffic.exchanges?.some(e=>e.url.includes('/api/selected')))break;await new Promise(r=>setTimeout(r,200));}
  assert.ok(traffic.exchanges.some(e=>e.url.includes('/api/selected')),'Selected tab captured');
  assert.ok(!traffic.exchanges.some(e=>e.url.includes('/api/unrelated')),'Other tab excluded');
  assert.ok(!JSON.stringify(traffic).includes('secret-request-value'),'Request token redacted');
  assert.ok(!JSON.stringify(traffic).includes('secret-response-value'),'Response token redacted');
  const denied=await fetch('http://127.0.0.1:4000/api/extension/bridge/claim',{method:'POST',headers:{'Content-Type':'application/json',Authorization:'Bearer invalid'},body:JSON.stringify({url:origin})});assert.equal(denied.status,401);
  await api(`/sessions/${sessionId}/pause`,{});await new Promise(r=>setTimeout(r,2200));await page.evaluate(()=>fetch('/api/paused'));await new Promise(r=>setTimeout(r,500));
  traffic=await api(`/sessions/${sessionId}/traffic`);assert.ok(!traffic.exchanges.some(e=>e.url.includes('/api/paused')));
  await api(`/sessions/${sessionId}/resume`,{});await new Promise(r=>setTimeout(r,2200));
  await api(`/sessions/${sessionId}/stop`,{});await new Promise(r=>setTimeout(r,2500));assert.equal(page.isClosed(),false,'User tab stays open');
  assert.equal((await api(`/sessions/${sessionId}`)).session.status,'STOPPED');
  const opened=await popup.evaluate(async({projectId,url})=>chrome.runtime.sendMessage({action:'open_and_record',projectId,url}),{projectId,url:origin+'/new-recording'});
  assert.ok(opened.success,opened.error);sessionId=opened.sessionId;
  for(let i=0;i<50;i++){traffic=await api(`/sessions/${sessionId}/traffic`);if(traffic.exchanges?.some(e=>e.url.includes('/new-recording')))break;await new Promise(r=>setTimeout(r,200));}
  assert.ok(traffic.exchanges.some(e=>e.url.includes('/new-recording')),'New tab initial navigation captured');
  await api(`/sessions/${sessionId}/stop`,{});
  console.log('Extension passed: real selected-tab capture, unrelated-tab isolation, secret redaction, invalid pairing rejection, pause/resume and stop without closing the tab.');
}finally{
  await context?.close();
  if(sessionId)await api(`/sessions/${sessionId}/stop`,{}).catch(()=>{});
  if(projectId)await fetch(`http://127.0.0.1:4000/api/projects/${projectId}`,{method:'DELETE',headers});
  await new Promise(r=>target.close(r));
  if(dirname(profile)===resolve(tmpdir())&&profile.startsWith(join(tmpdir(),'tracehawk-extension-test-')))await rm(profile,{recursive:true,force:true});
}

