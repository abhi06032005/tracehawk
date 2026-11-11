"use client";
import { useEffect, useRef, useState } from 'react';
import Markdown from 'react-markdown';
import Link from 'next/link';
import { api } from '@/lib/api';
import { Investigation, Session } from '@/types';

export default function AuditWorkspace({sessions,sessionId,onSession,runs,run,onRun,config,busy,error,start,stop,download,approve,refresh}:{sessions:Session[];sessionId:string;onSession:(id:string)=>void;runs:Investigation[];run:Investigation|null;onRun:(id:string)=>void;config:any;busy:boolean;error:string;start:()=>void;stop:()=>void;download:()=>void;approve:(yes:boolean)=>void;refresh:()=>Promise<void>}){
  const [selectedId,setSelected]=useState(''),[question,setQuestion]=useState(''),[sending,setSending]=useState(false),[chatError,setChatError]=useState('');
  const active=run?.status==='RUNNING'||run?.status==='AWAITING_APPROVAL';
  const steps=run?.steps||[],findings=run?.hypotheses||[];
  const selected=findings.find(h=>h.id===selectedId)||findings[0];
  const pending=steps.some(s=>s.phase==='CHAT_USER'&&s.toolArgs?.status==='pending');
  const approval=steps.find(s=>s.approvalStatus==='PENDING');
  const conversation=steps.filter(s=>s.phase.startsWith('CHAT_'));
  const scroll=useRef<HTMLDivElement>(null);
  useEffect(()=>{setSelected('');setQuestion('');setChatError('');},[run?.id]);
  useEffect(()=>{if(scroll.current)scroll.current.scrollTop=scroll.current.scrollHeight;},[conversation.length,pending]);
  const ask=async(text=question)=>{if(!run||!text.trim()||active||pending)return;setSending(true);setChatError('');try{await api.askReport(run.id,text.trim(),selected?.id);setQuestion('');await refresh();}catch(e:any){setChatError(e.message);}finally{setSending(false);}};
  const md=(text:string)=><div className="chat-prose"><Markdown>{text}</Markdown></div>;
  const button='rounded-lg border border-stone-300 bg-white px-3 py-2 text-xs font-medium hover:bg-stone-100 disabled:opacity-40';
  return <div className="flex h-full min-h-0 flex-col bg-[#faf9f6] text-stone-800">
    <header className="flex flex-wrap items-center justify-between gap-3 border-b border-stone-200 px-5 py-4">
      <div><h1 className="text-base font-semibold">Security review</h1><p className="mt-1 text-xs text-stone-500">{config?.model||'DeepHat'} · {run?'Saved to your database':'Your recorded application, reviewed with evidence'}</p></div>
      <div className="flex items-center gap-2">{run&&<button className={button} onClick={download} disabled={busy}>Download saved report</button>}{active&&<button className={button} onClick={stop}>Stop audit</button>}</div>
    </header>
    <div className="flex flex-wrap items-end gap-3 border-b border-stone-200 bg-white/50 px-5 py-3">
      <label className="min-w-0 flex-1 text-xs text-stone-500">Recorded session<select aria-label="Completed browser session" className="mt-1 block w-full max-w-md rounded-lg border border-stone-200 bg-white p-2 text-sm text-stone-800" value={sessionId} disabled={active||pending} onChange={e=>onSession(e.target.value)}><option value="">Choose a completed session</option>{sessions.map(s=><option value={s.id} key={s.id}>{s.project?.name} · {new Date(s.startedAt).toLocaleString()}</option>)}</select></label>
      {runs.length>0&&<label className="text-xs text-stone-500">Saved AI reports<select aria-label="Saved AI reports" className="mt-1 block rounded-lg border border-stone-200 bg-white p-2 text-sm text-stone-800" value={run?.id||''} disabled={active||pending} onChange={e=>onRun(e.target.value)}>{runs.map(r=><option key={r.id} value={r.id}>{new Date(r.startedAt).toLocaleString()}</option>)}</select></label>}
      <button onClick={start} disabled={busy||active||pending||!sessionId||!config?.enabled} className="rounded-lg bg-stone-900 px-4 py-2 text-sm text-white disabled:opacity-40">Start AI Audit</button>
    </div>
    {(error||chatError)&&<p role="alert" className="border-b border-red-100 bg-red-50 px-5 py-3 text-sm text-red-800">{error||chatError}</p>}
    <div className="grid min-h-0 flex-1 grid-cols-1 overflow-auto xl:grid-cols-[minmax(0,1fr)_310px] xl:overflow-hidden">
      <section className="flex min-h-[500px] min-w-0 flex-col xl:min-h-0" aria-label="Audit conversation">
        <div ref={scroll} className="min-h-0 flex-1 overflow-auto px-5 py-8 md:px-10">
          <div className="mx-auto max-w-3xl space-y-8">
            {!run&&<div className="py-14"><p className="mb-4 text-xs uppercase tracking-widest text-stone-400">Recorded evidence. Clear explanations.</p><h2 className="text-3xl font-medium tracking-tight">Understand how your app could be attacked.</h2><p className="mt-4 max-w-xl text-sm leading-7 text-stone-500">Choose a completed recording and start a review. Findings appear on the right. Select one to explore its attack path, prerequisites, evidence and remediation.</p><Link href="/" className="mt-6 inline-block text-sm underline underline-offset-4">Record a browser session</Link></div>}
            {run&&<>
              <div className="ml-auto max-w-lg rounded-2xl bg-stone-200/60 px-5 py-4 text-sm">Review this application recording. Prioritize serious vulnerabilities and explain how an attacker could exploit them.</div>
              <article><div className="mb-3 text-xs font-semibold uppercase tracking-wide text-stone-500">TraceHawk</div>
                <p role="status" className="mb-3 text-xs text-stone-500">{run.status} · {findings.length} findings · {active?'Review in progress':'Report saved'}</p>
                {active?<><p className="text-sm leading-7">Reviewing recorded requests and checking the evidence.</p><p className="mt-2 text-xs text-stone-500">{steps.at(-1)?.thought||'Preparing the session…'}</p></>:run.riskSummary?md(run.riskSummary):<p className="text-sm leading-7">{run.errorMessage||'No final summary is available. Any completed decisions and findings are saved below.'}</p>}
                {run.errorMessage&&run.riskSummary&&<p className="mt-3 text-sm text-red-700">{run.errorMessage}</p>}
              </article>
              {approval&&active&&<div className="rounded-lg border border-stone-300 p-4"><h3 className="font-medium">Approval required for one state-changing test</h3><pre className="my-3 overflow-auto text-xs">{JSON.stringify(approval.toolResult?.approvalRequest,null,2)}</pre><button onClick={()=>approve(true)} className={button}>Approve this action</button><button onClick={()=>approve(false)} className={`${button} ml-2`}>Deny</button></div>}
              {selected&&<article className="border-t border-stone-200 pt-6"><p className="mb-2 text-xs text-stone-500">Selected finding · {selected.verificationStatus.replaceAll('_',' ')}</p><h2 className="text-xl font-semibold">{selected.title}</h2><p className="mt-2 break-all font-mono text-xs text-stone-500">{selected.affectedEndpoint}</p>
                {([['Attack path',selected.attackMechanism],['What an attacker needs',selected.prerequisites],['Potential impact',selected.potentialImpact],['Verification and next steps',selected.verificationNotes],['How to fix it',selected.suggestedRemediation]]as const).map(([label,text])=><div className="mt-6" key={label}><h3 className="mb-2 text-sm font-semibold">{label}</h3>{md(text||'Not established by the recorded evidence.')}</div>)}
                <details className="mt-6 border-t border-stone-200 pt-3"><summary className="cursor-pointer text-xs text-stone-500">Supporting evidence ({selected.supportingEvidenceIds.length})</summary>{selected.supportingEvidenceIds.length?selected.supportingEvidenceIds.map(id=>{const e=steps.flatMap(s=>s.toolResult?.evidence||[]).find((e:any)=>e.id===id);return <div id={`evidence-${id}`} key={id} className="mt-3"><a href={`#evidence-${id}`} className="text-xs underline">{id}</a><pre className="mt-2 max-h-56 overflow-auto whitespace-pre-wrap rounded bg-white p-3 text-xs">{JSON.stringify(e||{id},null,2)}</pre></div>}):<p className="mt-2 text-xs">Further evidence is needed to confirm exploitation.</p>}</details>
              </article>}
              {conversation.map(s=><article key={s.id} className={s.phase==='CHAT_USER'?'ml-auto max-w-lg rounded-2xl bg-stone-200/60 px-5 py-4':'py-1'}><p className="mb-2 text-xs font-semibold text-stone-500">{s.phase==='CHAT_USER'?'You':'TraceHawk'}</p>{md(s.thought)}{s.phase==='CHAT_USER'&&['interrupted','failed'].includes(s.toolArgs?.status)&&<p className="mt-2 text-xs text-red-700">Response interrupted. Please ask again.</p>}</article>)}
              {pending&&<p role="status" className="text-sm text-stone-500">Preparing an evidence-based response…</p>}
              <details className="border-t border-stone-200 pt-4"><summary className="cursor-pointer text-xs text-stone-500">Review activity and tool results</summary>{steps.filter(s=>!s.phase.startsWith('CHAT_')).map(s=><div key={s.id} className="mt-4 text-xs"><strong>{s.phase}</strong><p className="mt-1 leading-6">{s.thought}</p>{s.toolResult&&<pre className="mt-2 max-h-52 overflow-auto whitespace-pre-wrap rounded bg-white p-3">{JSON.stringify(s.toolResult,null,2)}</pre>}</div>)}</details>
            </>}
          </div>
        </div>
        <div className="border-t border-stone-200 px-5 py-4 md:px-10"><div className="mx-auto max-w-3xl">
          {run&&!active&&!pending&&<div className="mb-3 flex flex-wrap gap-2">{['Explain the attack path','What should I verify next?','How do I fix the highest-risk issue?'].map(q=><button key={q} onClick={()=>ask(q)} disabled={sending} className="rounded-full border border-stone-200 px-3 py-1.5 text-xs text-stone-600 hover:bg-white">{q}</button>)}</div>}
          <form onSubmit={e=>{e.preventDefault();void ask();}} className="rounded-2xl border border-stone-300 bg-white p-3"><textarea aria-label="Ask about this report" value={question} onChange={e=>setQuestion(e.target.value)} maxLength={2000} rows={2} disabled={!run||active||pending||sending} placeholder={active?'The audit is running. You can ask questions when it finishes.':'Ask about an exploit path, evidence, or remediation…'} className="w-full resize-none bg-transparent p-1 text-sm outline-none disabled:opacity-50"/><div className="flex items-center justify-between"><span className="text-[11px] text-stone-400">Answers use this saved report. No attacks are executed in chat.</span>{pending?<button type="button" onClick={()=>run&&api.stopReportReply(run.id).catch(e=>setChatError(e.message))} className={button}>Stop response</button>:<button disabled={!run||active||sending||!question.trim()} className="rounded-lg bg-stone-900 px-4 py-2 text-xs text-white disabled:opacity-30">Send</button>}</div></form>
        </div></div>
      </section>
      <aside className="border-t border-stone-200 bg-[#f3f2ef] xl:overflow-auto xl:border-l xl:border-t-0" aria-label="Vulnerabilities">
        <div className="border-b border-stone-200 px-5 py-5"><h2 className="text-sm font-semibold">Vulnerabilities <span className="ml-2 text-stone-400">{findings.length}</span></h2><p className="mt-2 text-xs leading-5 text-stone-500">Potential issues remain unverified until the evidence proves them.</p></div>
        {!findings.length&&<p className="px-5 py-7 text-sm leading-6 text-stone-500">{active?'Findings will appear as the review progresses.':'Start a review to see its findings here.'}</p>}
        {findings.map(h=><button key={h.id} onClick={()=>setSelected(h.id)} aria-pressed={selected?.id===h.id} className={`block w-full border-b border-stone-200 px-5 py-5 text-left transition-colors ${selected?.id===h.id?'bg-white':'hover:bg-white/60'}`}><span className={`text-[10px] font-semibold uppercase tracking-wider ${['CRITICAL','HIGH'].includes(h.risk)?'text-red-700':'text-stone-500'}`}>{h.risk}</span><strong className="mt-2 block text-sm leading-6 font-medium">{h.title}</strong><span className="mt-2 block text-[11px] text-stone-500">{h.verificationStatus.replaceAll('_',' ')}</span></button>)}
      </aside>
    </div>
  </div>;
}
