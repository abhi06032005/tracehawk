"use client";
import { useEffect, useState } from 'react';
import { api } from '@/lib/api';
import AuditWorkspace from '@/components/AuditWorkspace';
import { Session, Investigation, AiHypothesis } from '@/types';

export default function AiAuditPage() {
  const [sessions,setSessions]=useState<Session[]>([]);
  const [sessionId,setSessionId]=useState('');
  const [runs,setRuns]=useState<Investigation[]>([]);
  const [run,setRun]=useState<Investigation|null>(null);
  const [config,setConfig]=useState<Awaited<ReturnType<typeof api.getAiConfig>>|null>(null);


  const [error,setError]=useState(''), [busy,setBusy]=useState(false);
  const [selectedId,setSelectedId]=useState('');
  const active=run?.status==='RUNNING'||run?.status==='AWAITING_APPROVAL';
  const chatPending=run?.steps?.some(s=>s.phase==='CHAT_USER'&&s.toolArgs?.status==='pending');
  const selected=run?.hypotheses?.find(h=>h.id===selectedId);
  const steps=run?.steps||[];
  const evidence=steps.flatMap(s=>s.toolResult?.evidence||[]);
  const approval=steps.find(s=>s.approvalStatus==='PENDING');
  useEffect(()=>{
    Promise.all([api.getProjects(),api.getAiConfig()]).then(([p,c])=>{
      const completed=p.projects.flatMap(project=>(project.sessions||[]).filter(s=>['STOPPED','ANALYZED'].includes(s.status)).map(s=>({...s,project})));
      const requested = new URLSearchParams(window.location.search).get('session');
      setSessions(completed);setSessionId(completed.find(s=>s.id===requested)?.id||completed[0]?.id||'');setConfig(c);
    }).catch(e=>setError(e.message));
  },[]);
  useEffect(()=>{
    setSelectedId('');setRun(null);
    if (!sessionId) return;
    let cancelled=false;
    api.getInvestigations(sessionId).then(async r=>{
      if(cancelled)return;setRuns(r.investigations);
      if(r.investigations[0]) {const d=await api.getInvestigation(r.investigations[0].id);if(!cancelled)setRun(d.investigation);}
    }).catch(e=>{if(!cancelled)setError(e.message)});
    return()=>{cancelled=true};
  },[sessionId]);
  useEffect(()=>{
    if(!run||(!active&&!chatPending))return;
    let cancelled=false;
    const id=run.id;
    const refresh=()=>api.getInvestigation(id).then(r=>{if(!cancelled)setRun(r.investigation)}).catch(e=>{if(!cancelled)setError(e.message)});
    const events=new EventSource(`/api/investigations/${id}/stream`);
    events.onmessage=()=>{void refresh()};
    const timer=setInterval(refresh,2000);
    return()=>{cancelled=true;events.close();clearInterval(timer)};
  },[run?.id,active,chatPending]);
  const action=async(fn:()=>Promise<void>)=>{setBusy(true);setError('');try{await fn()}catch(e:any){setError(e.message)}finally{setBusy(false)}};
  const start=()=>action(async()=>{
    const result=await api.startInvestigation(sessionId,{authorized:true,activeTests:false,maxSteps:20,maxTimeSeconds:0,requestBudget:0});
    const detail=await api.getInvestigation(result.investigationId);setRun(detail.investigation);setRuns(r=>[detail.investigation,...r]);
  });
  const download=()=>action(async()=>{if(!run)return;const saved=await api.getInvestigation(run.id);const url=URL.createObjectURL(new Blob([JSON.stringify(saved.investigation,null,2)],{type:"application/json"}));const link=document.createElement("a");link.href=url;link.download=`tracehawk-ai-report-${run.id}.json`;link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);});
  const stop=()=>action(async()=>{if(run){await api.stopInvestigation(run.id);setRun((await api.getInvestigation(run.id)).investigation)}});
  const approve=(approved:boolean)=>action(async()=>{if(run&&approval?.approvalId){await api.approveAction(run.id,approval.approvalId,approved);setRun((await api.getInvestigation(run.id)).investigation)}});
  const target=sessions.find(s=>s.id===sessionId)?.project;
  return <AuditWorkspace sessions={sessions} sessionId={sessionId} onSession={setSessionId} runs={runs} run={run} onRun={id=>action(async()=>{setRun((await api.getInvestigation(id)).investigation)})} config={config} busy={busy} error={error} start={start} stop={stop} download={download} approve={approve} refresh={async()=>{if(run)setRun((await api.getInvestigation(run.id)).investigation)}}/>;
}