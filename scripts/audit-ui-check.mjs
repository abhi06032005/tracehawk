import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdir } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { resolve, dirname } from 'node:path';
import assert from 'node:assert/strict';
import { chromium } from 'playwright';
const root=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const child=spawn(process.execPath,[resolve(root,'node_modules/next/dist/bin/next'),'start','-p','3101'],{cwd:resolve(root,'apps/web'),windowsHide:true,stdio:'ignore'});
const browser=await chromium.launch({headless:true});
try{
  let ready=false;for(let i=0;i<100;i++){try{if((await fetch('http://127.0.0.1:3101/audit')).ok){ready=true;break}}catch{}await new Promise(r=>setTimeout(r,200))}assert.ok(ready,'Web server starts');
  const page=await browser.newPage({viewport:{width:1440,height:1000}});
  let run=null,startPayload=null,approved=null;
  const source='11111111-1111-4111-8111-111111111111';
  const evidence={id:'evidence-1',kind:'security_headers',endpoint:'http://127.0.0.1:3000/[endpoint-abc123]',sourceIds:[source],observations:{cspPresent:false},supports:['missing_csp'],refutes:[]};
  await page.route('**/api/**',async route=>{
    const request=route.request(),path=new URL(request.url()).pathname;
    let value={};
    if(path==='/api/projects')value={projects:[{id:'p',name:'Authorized Juice Shop',targetUrl:'http://127.0.0.1:3000',allowedOrigins:['http://127.0.0.1:3000'],sessions:[{id:'completed-session',status:'STOPPED',startedAt:new Date().toISOString()},{id:'recording-session',status:'RECORDING',startedAt:new Date().toISOString()}]}]};
    else if(path==='/api/ai/config')value={enabled:true,model:'fixture-model',scenarios:[],zapConfigured:true};
    else if(path.endsWith('/investigations'))value={investigations:run?[run]:[]};
    else if(path.endsWith('/investigate')){
      startPayload=request.postDataJSON();assert.equal(request.headers()['x-tracehawk-control'],'1');
      run={id:'audit-fixture',sessionId:'completed-session',status:'AWAITING_APPROVAL',currentStep:4,maxSteps:10,requestsUsed:0,requestBudget:10,startedAt:new Date().toISOString(),steps:[{id:'step1',stepNumber:1,phase:'OBSERVE',thought:'Recorded evidence',toolResult:{evidence:[evidence]}},{id:'pending',stepNumber:4,phase:'VERIFY',thought:'Waiting for approval',toolName:'check_rate_limit_with_budget',approvalId:'approval1',approvalStatus:'PENDING',toolResult:{approvalRequest:{method:'DELETE',requests:1,exchangeId:source}}}],hypotheses:[]};
      value={investigationId:run.id,status:run.status};
    }else if(path.includes('/approvals/')){
      approved=request.postDataJSON().approved;run.status='COMPLETED';run.steps[1].approvalStatus=approved?'APPROVED':'DENIED';run.hypotheses=[{id:'hyp1',title:'Missing CSP',affectedEndpoint:evidence.endpoint,verificationStatus:'VERIFIED',risk:'LOW',confidence:'HIGH',attackMechanism:'Defense in depth missing',prerequisites:'Separate injection flaw required',potentialImpact:'Conditional',suggestedRemediation:'Set CSP',verificationNotes:'Verified configuration only',supportingEvidenceIds:['evidence-1']}];value={message:'Action denied'};
    }else if(path.endsWith('/chat')){
      assert.equal(request.headers()['x-tracehawk-control'],'1');
      const input=request.postDataJSON();assert.equal(input.findingId,'hyp1');
      run.steps.push({id:'question',stepNumber:5,phase:'CHAT_USER',thought:input.question,toolArgs:{status:'done'}},{id:'answer',stepNumber:6,phase:'CHAT_ASSISTANT',thought:'The recorded missing CSP requires a separate injection flaw. Verify that prerequisite before claiming exploitation.'});value={questionId:'question'};
    }else if(path.endsWith('/stream')){await route.fulfill({status:200,contentType:'text/event-stream',body:'data: {"type":"status"}\n\n'});return;}
    else if(path==='/api/investigations/audit-fixture')value={investigation:run};
    await route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(value)});
  });
  const errors=[];page.on('pageerror',e=>errors.push(e.message));
  await page.goto('http://127.0.0.1:3101/audit');
  const start=page.getByRole('button',{name:'Start AI Audit',exact:true});await start.waitFor();await page.waitForFunction(()=>Array.from(document.querySelectorAll("button")).some(b=>b.textContent==="Start AI Audit"&&!b.disabled));
  assert.equal(await page.locator('option[value="recording-session"]').count(),0);
  assert.equal(await page.getByRole('checkbox').count(),0);await start.click();
  await page.getByRole('button',{name:'Deny',exact:true}).waitFor();assert.equal(startPayload.authorized,true);assert.equal(startPayload.activeTests,false);assert.equal(startPayload.maxTimeSeconds,0);assert.equal(startPayload.maxSteps,20);assert.equal(startPayload.requestBudget,0);
  await page.getByRole('button',{name:'Deny',exact:true}).click();
  await page.getByRole('button',{name:/Missing CSP/}).click();
  await page.getByText('Supporting evidence (1)',{exact:true}).click(); await page.getByRole('link',{name:'evidence-1',exact:true}).click();
  assert.equal(approved,false);assert.equal(await page.getByText('Separate injection flaw required',{exact:false}).count(),1);
  const downloadEvent=page.waitForEvent('download');await page.getByRole('button',{name:'Download saved report'}).click();assert.ok((await downloadEvent).suggestedFilename().includes('audit-fixture'));
  await page.getByRole('textbox',{name:'Ask about this report'}).fill('What is the exploit prerequisite?');await page.getByRole('button',{name:'Send',exact:true}).click();
  await page.getByText('The recorded missing CSP requires a separate injection flaw.',{exact:false}).waitFor();
  await page.reload();await page.getByText('What is the exploit prerequisite?',{exact:true}).waitFor();
  assert.equal(errors.length,0,errors.join('\n'));
  await mkdir(resolve(root,'artifacts'),{recursive:true});await page.screenshot({path:resolve(root,'artifacts/phase2-audit-dashboard.png'),fullPage:true});
  await page.setViewportSize({width:390,height:844});assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth),'No mobile horizontal overflow');
  console.log('Audit UI passed: completed-session filter, one-click passive defaults, saved report download, control header, approval denial, evidence links, prerequisites, no browser runtime errors.');
}finally{await browser.close();child.kill();}

