import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { createServer, Server } from 'node:http';
import { randomUUID } from 'node:crypto';
const store=vi.hoisted(()=>({ sessions: [] as any[], exchanges: [] as any[], investigations: [] as any[], steps: [] as any[], hypotheses: [] as any[] }));
vi.mock('../db.js',()=>{
  const match=(row:any,where:any={}):boolean=>Object.entries(where).every(([k,v]:any)=>v&&typeof v==='object' ? ('in' in v?v.in.includes(row[k]):'lt' in v?row[k]<v.lt:match(row[k],v)) : row[k]===v);
  const model=(rows:any[],defaults:any={})=>({
    findUnique:vi.fn(async({where}:any)=>rows.find(r=>match(r,where))||null),
    findFirst:vi.fn(async({where}:any)=>rows.find(r=>match(r,where))||null),
    findMany:vi.fn(async({where}:any={})=>rows.filter(r=>match(r,where))),
    create:vi.fn(async({data}:any)=>{const r={id:crypto.randomUUID(),...defaults,...data};rows.push(r);return r}),
    update:vi.fn(async({where,data}:any)=>{const r=rows.find(r=>match(r,where));if(!r)throw Error('not found');Object.assign(r,data);return r}),
    updateMany:vi.fn(async({where,data}:any)=>{const found=rows.filter(r=>match(r,where));for(const r of found)for(const [k,v] of Object.entries(data))r[k]=v&&typeof v==='object'&&'increment'in v?r[k]+(v as any).increment:v;return {count:found.length}}),
  });
  return {prisma:{session:model(store.sessions),httpExchange:model(store.exchanges),storageObservation:model([]),browserEvent:model([]),finding:model([]),investigation:model(store.investigations,{requestsUsed:0,currentStep:0}),investigationStep:model(store.steps),aiHypothesis:model(store.hypotheses)}};
});
import { InvestigationManager } from './agent.js';
import { ToolRegistry, ToolContext } from './tools.js';
import { endpointRef } from './privacy.js';
import { aiProvider } from './provider.js';
import { AgentDecisionSchema } from './contracts.js';
let server:Server,base:string, targetCalls:any[]=[], modelCalls:any[]=[], handler:(context:any)=>any;
const exchangeId='11111111-1111-4111-8111-111111111111';
const decision=(phase='ANALYZE',extra:any={})=>({phase,thought:'Assessing actual supplied evidence',hypotheses:[],toolCall:null,isFinished:true,riskSummary:'Test completed',...extra});
const options={authorized:true,activeTests:false,maxSteps:4,maxTimeSeconds:20,requestBudget:5};
const poll=async(fn:()=>boolean)=>{for(let i=0;i<200;i++){if(fn())return;await new Promise(r=>setTimeout(r,10))}throw Error('Timed out waiting for test condition')};
beforeAll(async()=>{
  server=createServer(async(req,res)=>{
    if(req.url==='/v1/chat/completions'){
      let text='';for await(const chunk of req)text+=chunk;
      const body=JSON.parse(text);const context=JSON.parse(body.messages[1].content);modelCalls.push({headers:req.headers,body,context});
      if(context.constraints?.remainingRequests===-999)return; // cancellation fixture
      const answer=handler(context);
      res.setHeader('Content-Type','application/json');res.end(JSON.stringify({choices:[{message:{content:typeof answer==='string'?answer:JSON.stringify(answer)}}]}));return;
    }
    targetCalls.push({url:req.url,method:req.method,authorization:req.headers.authorization});
    if(req.url==='/hang')return;
    if(req.url==='/redirect'){res.writeHead(302,{Location:'/outside'});res.end();return}
    if(req.url==='/resource'&&req.headers.authorization==='Bearer second-denied'){res.writeHead(403);res.end('{}');return}
    res.setHeader('Content-Type','application/json');res.end(JSON.stringify({id:'owned-resource',private:'private-person-value'}));
  });
  await new Promise<void>(r=>server.listen(0,'127.0.0.1',r));base=`http://127.0.0.1:${(server.address()as any).port}`;
});
afterAll(async()=>{server.closeAllConnections();await new Promise<void>(r=>server.close(()=>r()))});
beforeEach(()=>{
  for(const rows of Object.values(store))rows.length=0;
  targetCalls=[];modelCalls=[];handler=()=>decision();
  vi.stubEnv('AI_TOKENIZER_URL','');vi.stubEnv('AI_PROVIDER','custom');vi.stubEnv('HF_TOKEN','');vi.stubEnv('AI_ENABLED','true');vi.stubEnv('AI_BASE_URL',base+'/v1');vi.stubEnv('AI_API_KEY','fixture-api-key');vi.stubEnv('AI_MODEL','fixture-model');vi.stubEnv('AI_TEST_ACCOUNTS','[]');vi.stubEnv('AI_ACCESS_SCENARIOS','[]');
  store.sessions.push({id:'session',status:'STOPPED',project:{allowedOrigins:[base],targetUrl:base}});
  store.exchanges.push({id:exchangeId,sessionId:'session',url:base+'/resource',method:'GET',statusCode:200,resourceType:'document',timestamp:new Date(),requestHeaders:{authorization:'Bearer private-credential'},responseHeaders:{},sanitizedRequestBody:null,sanitizedResponseBody:'{"password":"private-password","email":"private@example.invalid"}'});
});
afterEach(()=>vi.unstubAllEnvs());
function context(extra:Partial<ToolContext>={}):ToolContext{return {sessionId:'session',investigationId:'inv',allowedOrigins:[base],authorized:true,activeTests:true,signal:new AbortController().signal,remainingRequests:5,reserveRequest:async()=>{},approve:async()=>false,...extra}}
describe('real HTTP model protocol and agent loop (fixture model, in-memory persistence)',()=>{
  it('starts a saved passive report with defaults, no deadline and no approval prompt',async()=>{
    const {investigationId}=await new InvestigationManager().startInvestigation('session',{});
    await poll(()=>store.investigations[0].status==='COMPLETED');
    expect(store.investigations[0]).toMatchObject({id:investigationId,maxSteps:20,maxTimeSeconds:0,deadline:null,activeTests:false,requestBudget:0,riskSummary:'Test completed'});
    expect(store.steps.some(s=>s.approvalStatus==='PENDING')).toBe(false);
    expect(targetCalls).toHaveLength(0);
  });
  it('sends API key and actual initial context, model chooses tool, receives result and evaluates exact proof',async()=>{
    handler=c=>{
      if(c.constraints.phase==='ANALYZE')return decision('ANALYZE',{isFinished:false,toolCall:{name:'analyze_security_headers',args:{exchangeId}}});
      const proof=c.history.find((s:any)=>s.phase==='VERIFY').result.evidence[0];
      return decision('EVALUATE',{hypotheses:[{title:'Missing CSP',affectedEndpoint:proof.endpoint,claimType:'missing_csp',attackMechanism:'A missing browser policy weakens defense in depth',prerequisites:'A separate injection flaw is needed for exploitation',potentialImpact:'Conditional script injection impact',suggestedRemediation:'Set a restrictive CSP',risk:'LOW',confidence:'HIGH',verificationStatus:'VERIFIED',supportingEvidenceIds:[proof.id],verificationNotes:'Observed missing header'}]});
    };
    const manager=new InvestigationManager();const {investigationId}=await manager.startInvestigation('session',options);
    await poll(()=>store.investigations[0].status==='COMPLETED');
    expect(modelCalls).toHaveLength(2);expect(modelCalls[0].headers.authorization).toBe('Bearer fixture-api-key');
    expect(modelCalls[0].context.history[0].result.data.endpointInventory[0].exchangeIds).toContain(exchangeId);
    expect(modelCalls[1].context.history.some((s:any)=>s.result?.evidence?.some((e:any)=>e.kind==='security_headers'))).toBe(true);
    expect(store.hypotheses[0].verificationStatus).toBe('VERIFIED');expect(store.steps.map(s=>s.phase)).toEqual(['OBSERVE','ANALYZE','PLAN','VERIFY','EVALUATE']);
    const persisted=JSON.stringify(store.steps);const sent=JSON.stringify(modelCalls.map(c=>c.body));
    for(const secret of ['private-password','private@example.invalid','private-credential']){expect(persisted).not.toContain(secret);expect(sent).not.toContain(secret)}
    expect(store.steps.find(s=>s.phase==='EVALUATE').evaluation).toHaveLength(1);expect(investigationId).toBeTruthy();expect(targetCalls).toHaveLength(0);
  });
  it('disabled AI rejects start without scripted findings',async()=>{
    vi.stubEnv('AI_ENABLED','false');await expect(new InvestigationManager().startInvestigation('session',options)).rejects.toThrow('Configure');expect(store.investigations).toHaveLength(0);
  });
  it('recording sessions cannot start',async()=>{store.sessions[0].status='RECORDING';await expect(new InvestigationManager().startInvestigation('session',options)).rejects.toThrow('completed')});
  it('invalid model JSON fails explicitly with durable error',async()=>{
    handler=()=>'{invalid';await new InvestigationManager().startInvestigation('session',options);await poll(()=>store.investigations[0].status==='FAILED');expect(store.hypotheses).toHaveLength(0);expect(store.steps.at(-1).phase).toBe('ERROR');
  });
  it('tool argument errors are recorded and returned to model',async()=>{
    handler=c=>c.constraints.phase==='ANALYZE'?decision('ANALYZE',{isFinished:false,toolCall:{name:'get_session_evidence',args:{sessionId:'another-session'}}}):decision('EVALUATE');
    await new InvestigationManager().startInvestigation('session',options);await poll(()=>store.investigations[0].status==='COMPLETED');
    expect(modelCalls[1].context.history.find((h:any)=>h.phase==='VERIFY').result.status).toBe('error');
  });
  it('final model turn cannot schedule an unevaluated tool',async()=>{
    handler=c=>decision(c.constraints.phase,{isFinished:false,toolCall:{name:'analyze_security_headers',args:{exchangeId}}});
    await new InvestigationManager().startInvestigation('session',{...options,maxSteps:2});await poll(()=>store.investigations[0].status==='FAILED');
    expect(store.steps.filter(s=>s.phase==='VERIFY')).toHaveLength(1);
  });
  it('state-changing action waits for exact one-time approval',async()=>{
    handler=c=>c.constraints.phase==='ANALYZE'?decision('ANALYZE',{isFinished:false,toolCall:{name:'check_rate_limit_with_budget',args:{exchangeId,method:'DELETE',budget:1}}}):decision('EVALUATE');
    const manager=new InvestigationManager();const {investigationId}=await manager.startInvestigation('session',{...options,activeTests:true});
    await poll(()=>store.investigations[0].status==='AWAITING_APPROVAL');expect(targetCalls).toHaveLength(0);
    const pending=store.steps.find(s=>s.approvalStatus==='PENDING');
    await expect(manager.resolveApproval('wrong',pending.approvalId,true)).rejects.toThrow();
    await manager.resolveApproval(investigationId,pending.approvalId,true);
    await expect(manager.resolveApproval(investigationId,pending.approvalId,true)).rejects.toThrow();
    await poll(()=>store.investigations[0].status==='COMPLETED');expect(targetCalls[0].method).toBe('DELETE');expect(store.investigations[0].requestsUsed).toBe(1);
  });
  it('emergency stop expires pending approval without executing it',async()=>{
    handler=()=>decision('ANALYZE',{isFinished:false,toolCall:{name:'check_rate_limit_with_budget',args:{exchangeId,method:'POST',budget:1}}});
    const manager=new InvestigationManager();const {investigationId}=await manager.startInvestigation('session',{...options,activeTests:true});await poll(()=>store.investigations[0].status==='AWAITING_APPROVAL');
    const pending=store.steps.find(s=>s.approvalStatus==='PENDING');await manager.stopInvestigation(investigationId);await poll(()=>pending.approvalStatus==='EXPIRED');
    await expect(manager.resolveApproval(investigationId,pending.approvalId,true)).rejects.toThrow();expect(targetCalls).toHaveLength(0);expect(store.investigations[0].status).toBe('CANCELLED');
  });
});
describe('backend active tools',()=>{
  it('DELETE denied without approval',async()=>{const result=await ToolRegistry.execute('check_rate_limit_with_budget',{exchangeId,method:'DELETE',budget:1},context());expect(result.status).toBe('denied');expect(targetCalls).toHaveLength(0)});
  it('passive authorization never authorizes active requests',async()=>{expect((await ToolRegistry.execute('check_rate_limit_with_budget',{exchangeId},context({activeTests:false}))).status).toBe('denied');expect(targetCalls).toHaveLength(0)});
  it('budget is shared across tool calls',async()=>{const ctx=context({remainingRequests:1});await ToolRegistry.execute('check_rate_limit_with_budget',{exchangeId,budget:1},ctx);expect((await ToolRegistry.execute('check_rate_limit_with_budget',{exchangeId,budget:1},ctx)).status).toBe('denied');expect(targetCalls).toHaveLength(1)});
  it('redirect destinations are never followed',async()=>{store.exchanges[0].url=base+'/redirect';await ToolRegistry.execute('check_rate_limit_with_budget',{exchangeId,budget:3},context());expect(targetCalls.map(c=>c.url)).toEqual(['/redirect'])});
  it('cancellation aborts an in-flight target fetch',async()=>{store.exchanges[0].url=base+'/hang';const controller=new AbortController();const work=ToolRegistry.execute('check_rate_limit_with_budget',{exchangeId,budget:1},context({signal:controller.signal}));await poll(()=>targetCalls.length===1);controller.abort();await expect(work).rejects.toThrow();});
  it('deadline aborts an in-flight model call',async()=>{const controller=new AbortController();const work=aiProvider.complete('test',{constraints:{remainingRequests:-999}},AgentDecisionSchema,controller.signal);await poll(()=>modelCalls.length===1);controller.abort();await expect(work).rejects.toThrow();});
  it.each([false,true])('compares two real test account responses; other denied=%s',async(denied)=>{
    vi.stubEnv('AI_TEST_ACCOUNTS',JSON.stringify([{id:'owner',origin:base,headers:{Authorization:'Bearer owner-secret'}},{id:'other',origin:base,headers:{Authorization:denied?'Bearer second-denied':'Bearer other-secret'}}]));
    vi.stubEnv('AI_ACCESS_SCENARIOS',JSON.stringify([{id:'owned',endpoint:base+'/resource',ownerAccountId:'owner',otherAccountId:'other',resourcePointer:'/id',expectedResourceValue:'owned-resource',otherMustBeDenied:true}]));
    const r=await ToolRegistry.execute('compare_test_account_access',{scenarioId:'owned'},context());expect(r.status).toBe('ok');expect(targetCalls).toHaveLength(2);
    expect(r.evidence[0][denied?'refutes':'supports']).toContain('cross_account_access');
    for(const secret of ['owner-secret','other-secret','private-person-value','owned-resource'])expect(JSON.stringify(r)).not.toContain(secret);
  });
});
