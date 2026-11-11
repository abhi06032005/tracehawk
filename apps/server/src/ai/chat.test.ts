import { beforeEach, expect, it, vi } from 'vitest';
const state=vi.hoisted(()=>({steps:[] as any[],report:{id:'report',status:'COMPLETED',currentStep:0,hypotheses:[{id:'finding'}],steps:[] as any[],riskSummary:'Recorded evidence'},complete:vi.fn()}));
vi.mock('../db.js',()=>{
  const db:any={investigation:{findUniqueOrThrow:async()=>state.report,update:async()=>({...state.report,currentStep:++state.report.currentStep})},investigationStep:{create:async({data}:any)=>{const row={id:String(state.steps.length),...data};state.steps.push(row);return row;},update:async({where,data}:any)=>Object.assign(state.steps.find(s=>s.id===where.id),data),findMany:async()=>state.steps.filter(s=>s.toolArgs?.status==='pending')}};
  db.$transaction=(fn:any)=>fn(db);return {prisma:db};
});
vi.mock('./provider.js',()=>({aiProvider:{complete:state.complete},modelFailureMessage:()=> 'Model unavailable'}));
import { startReportChat,stopReportChat,recoverReportChats } from './chat.js';
beforeEach(()=>{state.steps.length=0;state.report.currentStep=0;state.report.status='COMPLETED';state.complete.mockReset();});
it('saves both the question and grounded reply in report steps',async()=>{
  state.complete.mockResolvedValue({answer:'Verify the evidence first.'});
  await startReportChat('report',{question:'Explain the attack',findingId:'finding'});
  await vi.waitFor(()=>expect(state.steps).toHaveLength(2));
  expect(state.steps[0].toolArgs.status).toBe('done');expect(state.steps[1].phase).toBe('CHAT_ASSISTANT');
  expect(state.complete.mock.calls[0][1].selectedFindingId).toBe('finding');
});
it('rejects unrelated findings and running reports without model requests',async()=>{
  await expect(startReportChat('report',{question:'Explain',findingId:'other'})).rejects.toThrow('does not belong');
  state.report.status='RUNNING';await expect(startReportChat('report',{question:'Explain'})).rejects.toThrow('finish');
  expect(state.complete).not.toHaveBeenCalled();
});
it('stops a pending response and prevents duplicate concurrent requests',async()=>{
  state.complete.mockImplementation((_s,_c,_z,signal)=>new Promise((_resolve,reject)=>signal.addEventListener('abort',()=>reject(Error('aborted')))));
  await startReportChat('report',{question:'Explain'});
  await expect(startReportChat('report',{question:'Again'})).rejects.toThrow('Wait');
  stopReportChat('report');await vi.waitFor(()=>expect(state.steps).toHaveLength(2));
  expect(state.steps[1].thought).toContain('Response stopped');expect(state.steps[0].toolArgs.status).toBe('done');
});
it('marks unfinished replies interrupted after restart',async()=>{
  state.steps.push({id:'old',phase:'CHAT_USER',toolArgs:{status:'pending'}});await recoverReportChats();expect(state.steps[0].toolArgs.status).toBe('interrupted');
});
