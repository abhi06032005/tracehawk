"use client";
import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { Globe, Play, ArrowRight } from 'lucide-react';
import { api } from '@/lib/api';
import { Project, Session } from '@/types';

function webUrl(value: string) {
  const text = value.trim();
  const url = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(text) ? text : `${/^(localhost|127\.0\.0\.1)(:|\/|$)/i.test(text) ? 'http' : 'https'}://${text}`);
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) {
    throw new Error('Enter an HTTP or HTTPS website URL without credentials.');
  }
  return url;
}

export default function OverviewPage() {
  const router = useRouter();
  const [projects, setProjects] = useState<Project[]>([]);
  const [selected, setSelected] = useState('');
  const [target, setTarget] = useState('http://localhost:3000');
  const [extraOrigins, setExtraOrigins] = useState('');
  const [launching, setLaunching] = useState(false);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);
  const [message, setMessage] = useState('');
  const [connected, setConnected] = useState(false);
  const [mode,setMode]=useState('auto');
  const [extensionReady,setExtensionReady]=useState(false);
  useEffect(()=>{
    const listener=(event:MessageEvent)=>{if(event.source===window&&event.data?.type==='TRACEHAWK_EXTENSION_READY')setExtensionReady(true);};
    window.addEventListener('message',listener);
    window.postMessage({type:'TRACEHAWK_CHECK_EXTENSION'},window.location.origin);
    return()=>window.removeEventListener('message',listener);
  },[]);

  const load = async () => {
    try {
      const [p, h] = await Promise.all([
        api.getProjects(),
        api.getHealth()
      ]);
      setProjects(p.projects);
      setConnected(h.services.database === 'connected');
      setError(h.services.database === 'connected' ? '' : 'Database is unavailable. Open Settings to check the local services.');
    } catch (e: any) {
      setConnected(false);
      setError(e.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void load();
    const timer = setInterval(load, 5000);
    return () => clearInterval(timer);
  }, []);

  const sessions = projects
    .flatMap(p => (p.sessions || []).map(s => ({ ...s, project: p })))
    .sort((a, b) => new Date(b.startedAt).getTime() - new Date(a.startedAt).getTime());
  const active = sessions.filter(s => ['RECORDING', 'PAUSED'].includes(s.status));

  const launch = async (event: React.FormEvent) => {
    event.preventDefault();
    if (launching) return;
    setError('');
    setLaunching(true);

    try {
      const url = webUrl(target);
      if(mode==='chrome'&&!extensionReady)throw new Error('Load or reload the TraceHawk extension in your everyday Chrome, then refresh this dashboard.');
      const origins = [url.origin, ...extraOrigins.split(',').map(s => s.trim()).filter(Boolean).map(s => webUrl(s).origin)];
      setMessage('Preparing your project…');

      let project = projects.find(p => p.id === selected);
      if (!project) {
        project = (await api.createProject({
          name: url.hostname,
          targetUrl: url.href,
          allowedOrigins: [...new Set(origins)]
        })).project;
      }

      setSelected(project.id);
      setProjects(p => p.some(x => x.id === project!.id) ? p : [project!, ...p]);

      if(mode==='chrome'||(mode==='auto'&&extensionReady)){
        setMessage('Opening your Chrome tab…');
        const sessionId=await new Promise<string>((resolve,reject)=>{
          const timer=setTimeout(()=>{window.removeEventListener('message',listener);reject(new Error('Chrome did not respond. Reload the extension and try again.'));},30000);
          const listener=(event:MessageEvent)=>{if(event.source!==window||event.data?.type!=='TRACEHAWK_RECORD_STARTED')return;clearTimeout(timer);window.removeEventListener('message',listener);event.data.success?resolve(event.data.sessionId):reject(new Error(event.data.error||'Chrome recording failed'));};
          window.addEventListener('message',listener);
          window.postMessage({type:'TRACEHAWK_START_RECORD',url:url.href,projectId:project.id},window.location.origin);
        });
        router.push('/sessions/'+sessionId);return;
      }
      setMessage('Opening Google Chrome window…');
      const result = await api.launchSession({
        projectId: project.id,
        targetUrl: url.href
      });

      router.push(`/sessions/${result.sessionId}`);
    } catch (e: any) {
      setError(e.message);
      setLaunching(false);
      setMessage('');
    }
  };

  return (
    <div className="mx-auto w-full max-w-6xl space-y-7 p-5 md:p-8">
      <header>
        <p className="mb-2 text-xs font-semibold uppercase tracking-widest text-stone-600">Browser Security Workspace</p>
        <h1 className="text-3xl font-bold tracking-tight">Use your app. See every recorded request.</h1>
        <p className="mt-3 max-w-2xl text-sm leading-6 text-slate-600">
          Record your existing Chrome tab or open a separate browser. Browse your application, stop recording, then review the saved evidence with AI.
        </p>
      </header>

      {error && (
        <div role="alert" className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-red-200 bg-red-50 p-4 text-sm text-red-800">
          <span>{error}</span>
          <button onClick={load} className="font-semibold underline">Retry connection</button>
        </div>
      )}

      <section id="record" className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm md:p-7">
        <div className="mb-5 flex items-center justify-between gap-3">
          <h2 className="text-lg font-semibold">Start a browser recording</h2>
          <span role="status" className={`rounded-full px-3 py-1 text-xs font-medium ${connected ? 'bg-emerald-50 text-emerald-700' : 'bg-slate-100 text-slate-600'}`}>
            {loading ? 'Checking connection…' : connected ? 'Recorder ready' : 'Recorder offline'}
          </span>
        </div>

        <form onSubmit={launch} className="space-y-4">
          <label className="block text-sm font-medium">Browser<select aria-label="Recording browser" value={mode} onChange={e=>{setMode(e.target.value);setError('');}} disabled={launching} className="mt-2 block w-full rounded-lg border border-stone-300 bg-white p-3"><option value="auto">Automatic — open an available recording browser</option><option value="chrome">My everyday Chrome — requires extension</option><option value="dedicated">Separate browser window — no extension needed</option></select></label>
          {mode==='auto'&&<p className="text-sm text-stone-600">{extensionReady?'Your Chrome extension is connected. The website will open in your everyday Chrome.':'A separate Chrome window will open and record. Google may block sign-in in this automated browser. For Google login, sign in in your everyday Chrome first, then record that application tab with the extension.'}</p>}
          {mode==='chrome'&&!extensionReady&&<button type="button" onClick={()=>{setMode('dedicated');setError('');}} className="rounded-lg border border-stone-300 px-4 py-2 text-sm">Use separate browser without extension</button>}
          {mode==='chrome'&&<div className="rounded-lg border border-stone-200 p-3 text-sm leading-6">{extensionReady?'Chrome extension connected. Only the selected tab will be recorded.':<>Open this dashboard in your everyday Chrome. In chrome://extensions, enable Developer mode, choose Load unpacked and select <code>D:\tracehawk\extensions\tracehawk</code>. If already installed, click Reload. Refresh this page afterwards.</>}<p className="mt-2 text-xs text-stone-500">For an already open signed-in page, use the extension popup on that tab and choose Record Current Tab.</p></div>}

          {projects.length > 0 && (
            <label className="block text-sm font-medium">
              Saved website
              <select
                value={selected}
                disabled={launching}
                onChange={e => {
                  setSelected(e.target.value);
                  const p = projects.find(x => x.id === e.target.value);
                  if (p) {
                    setTarget(p.targetUrl);
                    setExtraOrigins(p.allowedOrigins.filter(o => o !== new URL(p.targetUrl).origin).join(', '));
                  }
                }}
                className="mt-2 block w-full rounded-lg border border-slate-300 bg-white p-3"
              >
                <option value="">Record a new website</option>
                {projects.map(p => (
                  <option key={p.id} value={p.id}>
                    {p.name} — {p.targetUrl}
                  </option>
                ))}
              </select>
            </label>
          )}

          <label className="block text-sm font-medium" htmlFor="record-url">Website URL</label>
          <div className="flex flex-col gap-3 sm:flex-row">
            <div className="relative min-w-0 flex-1">
              <Globe className="absolute left-3 top-3.5 h-5 w-5 text-slate-400" />
              <input
                id="record-url"
                required
                value={target}
                disabled={launching}
                onChange={e => {
                  setTarget(e.target.value);
                  setSelected('');
                }}
                placeholder="https://your-app.com"
                className="w-full rounded-lg border border-slate-300 py-3 pl-11 pr-3 text-sm focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-100"
              />
            </div>
            <button
              type="submit"
              disabled={launching || !connected}
              className="flex items-center justify-center gap-2 rounded-lg bg-stone-900 px-6 py-3 text-sm font-semibold text-white hover:bg-stone-800 disabled:opacity-40"
            >
              <Play className="h-4 w-4" />
              {launching ? 'Opening Browser…' : 'Open Browser & Record'}
            </button>
          </div>

          <details className="rounded-lg bg-slate-50 p-3 text-sm">
            <summary className="cursor-pointer font-medium">My app uses a separate API domain</summary>
            <label className="mt-3 block text-xs text-slate-600">
              Additional authorized API origins, separated by commas
              <input
                value={extraOrigins}
                disabled={launching}
                onChange={e => {
                  setExtraOrigins(e.target.value);
                  setSelected('');
                }}
                placeholder="https://api.your-app.com"
                className="mt-2 block w-full rounded border bg-white p-2 text-sm"
              />
            </label>
            <p className="mt-2 text-xs text-slate-500">
              Request and response bodies are captured only for these authorized origins. Other traffic is shown as metadata.
            </p>
          </details>

          {message && <p role="status" className="text-sm text-indigo-700">{message}</p>}
          <p className="text-xs leading-5 text-slate-500">
            Sensitive values are redacted before storage. Use the extension to keep your existing sign-ins.
          </p>
        </form>
      </section>

      <section className="grid gap-4 sm:grid-cols-3">
        {[
          ['1. Open Browser', 'Enter your URL and click Open Browser & Record.'],
          ['2. Use Your App', 'For Google login, sign in in everyday Chrome before starting extension recording.'],
          ['3. Inspect & Audit', 'Inspect saved traffic, tokens, storage, and start DeepHat AI security audit.']
        ].map(([title, text]) => (
          <div key={title} className="rounded-xl border border-slate-200 bg-white p-4">
            <h3 className="text-sm font-semibold">{title}</h3>
            <p className="mt-2 text-sm text-slate-500">{text}</p>
          </div>
        ))}
      </section>

      {active.length > 0 && (
        <section>
          <h2 className="mb-3 text-lg font-semibold">Active recordings</h2>
          <div className="space-y-3">
            {active.map(s => (
              <Link
                key={s.id}
                href={`/sessions/${s.id}`}
                className="flex items-center justify-between gap-3 rounded-xl border border-emerald-200 bg-emerald-50 p-4"
              >
                <span>
                  <strong className="text-sm">{s.project.name}</strong>
                  <span className="mt-1 block text-xs text-emerald-800">
                    {s.status === 'PAUSED' ? 'Paused' : 'Recording'} · Open live traffic and browser controls
                  </span>
                </span>
                <ArrowRight className="h-5 w-5 text-emerald-700" />
              </Link>
            ))}
          </div>
        </section>
      )}

      <section>
        <div className="mb-3 flex items-center justify-between">
          <h2 className="text-lg font-semibold">Recent sessions</h2>
          <Link href="/sessions" className="text-sm text-indigo-700">View all sessions</Link>
        </div>
        {sessions.length === 0 ? (
          <div className="rounded-xl border border-dashed border-slate-300 p-8 text-center text-sm text-slate-500">
            Your first recording will appear here.
          </div>
        ) : (
          <div className="divide-y rounded-xl border bg-white">
            {sessions.slice(0, 6).map(s => (
              <Link
                key={s.id}
                href={`/sessions/${s.id}`}
                className="flex flex-wrap items-center justify-between gap-3 p-4 hover:bg-slate-50"
              >
                <div>
                  <strong className="text-sm">{s.project.name}</strong>
                  <p className="mt-1 text-xs text-slate-500">
                    {new Date(s.startedAt).toLocaleString()} · {s.totalRequests} requests · {s.status}
                  </p>
                </div>
                <span className="text-sm text-indigo-700">Inspect session →</span>
              </Link>
            ))}
          </div>
        )}
      </section>
    </div>
  );
}


