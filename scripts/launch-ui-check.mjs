import { chromium } from 'playwright';
import { createServer } from 'node:http';
import assert from 'node:assert/strict';
const target=createServer((_req,res)=>{res.setHeader('Content-Type','text/html');res.end('<title>TraceHawk launch verification</title><p>Local recording test</p>');});
await new Promise(r=>target.listen(0,'127.0.0.1',r));
const origin=`http://127.0.0.1:${target.address().port}`;
const headers={'Content-Type':'application/json','X-TraceHawk-Control':'1'};
let browser,sessionId,projectId;
try{
  browser=await chromium.launch({headless:true});
  const page=await browser.newPage();
  await page.goto('http://localhost:3001');
  assert.equal(await page.getByRole('combobox',{name:'Recording browser'}).inputValue(),'auto');
  await page.getByLabel('Website URL',{exact:true}).fill(origin);
  const create=page.waitForResponse(r=>new URL(r.url()).pathname==='/api/projects'&&r.request().method()==='POST');
  const launch=page.waitForResponse(r=>new URL(r.url()).pathname==='/api/sessions'&&r.request().method()==='POST');
  await page.getByRole('button',{name:'Open Browser & Record',exact:true}).click();
  projectId=(await (await create).json()).project.id;
  const response=await launch;const data=await response.json();assert.ok(response.ok(),JSON.stringify(data));sessionId=data.sessionId;
  await page.waitForURL(`**/sessions/${sessionId}`);
  let traffic;
  for(let i=0;i<40;i++){traffic=await (await fetch(`http://127.0.0.1:4000/api/sessions/${sessionId}/traffic`)).json();if(traffic.exchanges?.some(e=>e.url.startsWith(origin)))break;await new Promise(r=>setTimeout(r,250));}
  assert.ok(traffic.exchanges.some(e=>e.url.startsWith(origin)),'Visible browser navigates and records target');
  console.log('Homepage launch passed without extension: real button -> visible browser -> target request recorded -> session dashboard.');
}finally{
  if(sessionId)await fetch(`http://127.0.0.1:4000/api/sessions/${sessionId}/stop`,{method:'POST',headers,body:'{}'});
  if(projectId)await fetch(`http://127.0.0.1:4000/api/projects/${projectId}`,{method:'DELETE',headers});
  await browser?.close();await new Promise(r=>target.close(r));
}

