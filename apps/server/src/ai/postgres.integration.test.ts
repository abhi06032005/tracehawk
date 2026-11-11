import { afterAll, expect, it, vi } from 'vitest';
import { createServer } from 'node:http';
import { chromium } from 'playwright';
import { prisma } from '../db.js';
import { SessionRecorder } from '../browser/recorder.js';
import { captureAndPersistStorage } from '../browser/storage.js';
import { analyzeSession } from '../security/analyzer.js';
import { InvestigationManager } from './agent.js';
import { ToolRegistry } from './tools.js';
import { runZap } from './zap.js';
import { startReportChat } from './chat.js';
let projectId:string,sessionId:string;
afterAll(async()=>{vi.unstubAllEnvs();if(projectId)await prisma.project.delete({where:{id:projectId}});await prisma.$disconnect()});
it('records real Juice Shop traffic, then runs the model protocol and persists decisions, evidence and gated results in PostgreSQL',async()=>{
  const target='http://127.0.0.1:3000';
  expect((await fetch(target)).ok).toBe(true);
  const project=await prisma.project.create({data:{name:'Phase 2 integration test (temporary)',targetUrl:target,allowedOrigins:[target]}});projectId=project.id;
  const session=await prisma.session.create({data:{projectId,status:'RECORDING'}});sessionId=session.id;
  const recorder=new SessionRecorder(sessionId,target,[target]);
  const browser=await chromium.launch({headless:true});
  try{
    const context=await browser.newContext();const page=await context.newPage();recorder.attachToPage(page,context);
    await page.goto(target,{waitUntil:'networkidle'});
    await captureAndPersistStorage(sessionId,context);
  }finally{await recorder.stop();await browser.close()}
  await prisma.session.update({where:{id:sessionId},data:{status:'STOPPED',endedAt:new Date(),totalRequests:recorder.totalRequests}});
  const exchanges=await prisma.httpExchange.findMany({where:{sessionId}});expect(exchanges.length).toBeGreaterThan(0);
  const document=exchanges.find(e=>e.resourceType==='document'&&e.statusCode===200)!;expect(document).toBeDefined();
  await analyzeSession(sessionId);
  const contexts:any[]=[];
  const fixture=createServer(async(req,res)=>{
    try{
      let raw='';for await(const chunk of req)raw+=chunk;
      const body=JSON.parse(raw),context=JSON.parse(body.messages[1].content);contexts.push(context);
      expect(req.headers.authorization).toBe('Bearer integration-fixture-key');
      if(context.question){res.setHeader('Content-Type','application/json');res.end(JSON.stringify({choices:[{message:{content:JSON.stringify({answer:'This saved report requires more evidence before claiming exploitation.'})}}]}));return;}
      const result=context.history.find((h:any)=>h.phase==='VERIFY')?.result;
      const decision=result?{phase:'EVALUATE',thought:'Evaluated returned evidence; unrelated claims lack proof',hypotheses:[{
        title:'Unsupported SQL injection claim',affectedEndpoint:result.evidence[0].endpoint,claimType:'other',attackMechanism:'Unproven',prerequisites:'Missing proof',potentialImpact:'Unknown',suggestedRemediation:'Obtain reproducible evidence',risk:'HIGH',confidence:'HIGH',verificationStatus:'VERIFIED',supportingEvidenceIds:[result.evidence[0].id],verificationNotes:'Fixture intentionally requests an unsupported status',
      }],toolCall:null,isFinished:true,riskSummary:'Evidence reviewed; unsupported claim must remain unverified'}:
      {phase:'ANALYZE',thought:'Inspect recorded document security headers',hypotheses:[],toolCall:{name:'analyze_security_headers',args:{exchangeId:document.id}},isFinished:false,riskSummary:''};
      res.setHeader('Content-Type','application/json');res.end(JSON.stringify({choices:[{message:{content:JSON.stringify(decision)}}]}));
    }catch{res.writeHead(500);res.end('{}')}
  });
  await new Promise<void>(r=>fixture.listen(0,'127.0.0.1',r));
  vi.stubEnv('AI_TOKENIZER_URL','');vi.stubEnv('AI_PROVIDER','custom');vi.stubEnv('HF_TOKEN','');vi.stubEnv('AI_ENABLED','true');vi.stubEnv('AI_BASE_URL',`http://127.0.0.1:${(fixture.address()as any).port}/v1`);vi.stubEnv('AI_API_KEY','integration-fixture-key');vi.stubEnv('AI_MODEL','fixture-only');
  const manager=new InvestigationManager();
  let investigationId='';
  try{
    ({investigationId}=await manager.startInvestigation(sessionId,{authorized:true,activeTests:false,maxSteps:4,maxTimeSeconds:0,requestBudget:0}));
    let finished:any;
    for(let i=0;i<100;i++){
      finished=await prisma.investigation.findUnique({where:{id:investigationId},include:{steps:{orderBy:{stepNumber:'asc'}},hypotheses:true}});
      if(!['RUNNING','AWAITING_APPROVAL'].includes(finished!.status))break;
      await new Promise(r=>setTimeout(r,100));
    }
    expect(finished.status).toBe('COMPLETED');expect(finished.deadline).toBeNull();expect(finished.maxTimeSeconds).toBe(0);expect(finished.riskSummary).toBeTruthy();expect(contexts).toHaveLength(2);
    expect(contexts[0].history[0].result.data.passiveFindings.length).toBeGreaterThan(0);
    expect(finished.steps.map((s:any)=>s.phase)).toEqual(['OBSERVE','ANALYZE','PLAN','VERIFY','EVALUATE']);
    expect(finished.hypotheses[0].verificationStatus).toBe('NEEDS_VERIFICATION');
    expect(finished.steps.at(-1).decision.hypotheses[0].verificationStatus).toBe('VERIFIED');
    expect(finished.steps.at(-1).evaluation[0].verificationStatus).toBe('NEEDS_VERIFICATION');
    expect(finished.requestsUsed).toBe(0);
    await startReportChat(investigationId,{question:'Explain the remaining evidence gap.'});
    for(let i=0;i<100;i++){
      const answer=await prisma.investigationStep.findFirst({where:{investigationId,phase:'CHAT_ASSISTANT'}});
      if(answer){expect(answer.thought).toContain('more evidence');break;}
      if(i===99)throw Error('Chat reply was not saved');
      await new Promise(r=>setTimeout(r,50));
    }
    const savedQuestion=await prisma.investigationStep.findFirst({where:{investigationId,phase:'CHAT_USER'}});
    expect((savedQuestion?.toolArgs as any).status).toBe('done');
    console.info(`PostgreSQL/recorder integration: ${exchanges.length} real Juice Shop exchanges, ${finished.steps.length} persisted phase events, unsupported claim gated.`);
  }finally{if(investigationId)await manager.stopInvestigation(investigationId);fixture.closeAllConnections();await new Promise<void>(r=>fixture.close(()=>r()))}
},60000);
it.runIf(process.env.TEST_ZAP==='true')('imports recorded HAR into real ZAP and returns only session-linked passive evidence',async()=>{
  vi.stubEnv('ZAP_BASE_URL','http://127.0.0.1:8080');vi.stubEnv('ZAP_API_KEY',process.env.ZAP_API_KEY||'tracehawk-local-test-key');vi.stubEnv('ZAP_IMPORT_DIR','../../zap-import');vi.stubEnv('ZAP_CONTAINER_IMPORT_DIR','/zap/import');
  let ready=false;
  for(let i=0;i<60;i++){
    try { if((await fetch('http://127.0.0.1:8080/JSON/core/view/version/',{headers:{'X-ZAP-API-Key':process.env.ZAP_API_KEY!},signal:AbortSignal.timeout(1000)})).ok){ready=true;break} }catch{}
    await new Promise(r=>setTimeout(r,500));
  }
  expect(ready).toBe(true);
  const exchanges=await prisma.httpExchange.findMany({where:{sessionId}});
  const result=await runZap(exchanges,new AbortController().signal);
  expect(result.status).toBe('ok');expect(result.summary).toContain('ZAP passive analysis completed');
  expect(result.evidence.length).toBeGreaterThan(0);
  for(const evidence of result.evidence){expect(exchanges.some(e=>e.id===evidence.sourceIds[0])).toBe(true);expect(evidence.supports).toEqual([])}
},90000);
