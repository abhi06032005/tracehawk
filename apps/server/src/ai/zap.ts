import { mkdir, writeFile, unlink } from 'node:fs/promises';
import { resolve, posix } from 'node:path';
import { randomUUID } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { boundedText } from './provider.js';
import { endpointRef, headerFacts } from './privacy.js';
import { ToolResult } from './contracts.js';

let busy = false;
// Dedicated ZAP instance only. Importing HAR records responses; no scanner/spider
// or replay API is called. Synthetic hosts prevent cross-session alert mixing.
export async function runZap(exchanges: any[], parentSignal: AbortSignal): Promise<ToolResult> {
  if (!process.env.ZAP_BASE_URL || !process.env.ZAP_IMPORT_DIR || !process.env.ZAP_CONTAINER_IMPORT_DIR || !process.env.ZAP_API_KEY)
    return { status: 'unavailable', evidence: [], summary: 'Configure dedicated ZAP, API key and shared HAR import directories.' };
  if (busy) return { status: 'unavailable', evidence: [], summary: 'Dedicated ZAP is busy; retry later.' };
  busy = true;
  const signal = AbortSignal.any([parentSignal, AbortSignal.timeout(45000)]);
  const id = randomUUID(), name = `${id}.har`, host = `http://evidence-${id}.invalid`;
  const syntheticUrl = (e: any) => `${new URL(e.url).protocol === 'https:' ? host.replace('http:', 'https:') : host}/${e.id}`;
  const directory = resolve(process.env.ZAP_IMPORT_DIR), file = resolve(directory,name);
  const call = async (path: string, params: Record<string,string> = {}) => {
    const url = new URL(path,process.env.ZAP_BASE_URL);
    const res = await fetch(url,{ method: 'POST', redirect: 'error', signal, headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'X-ZAP-API-Key': process.env.ZAP_API_KEY! }, body: new URLSearchParams(params) });
    if (!res.ok) throw new Error('ZAP API request failed');
    const data = JSON.parse(await boundedText(res));
    if (data.code) throw new Error('ZAP API rejected operation');
    return data;
  };
  try {
    signal.throwIfAborted();
    const entries = exchanges.filter(e => e.statusCode).map(e => {
      const h = headerFacts(e.responseHeaders);
      // Preserve only safe security-header semantics. Content and cookies omitted.
      const mime = ['text/html','application/json','text/plain','application/javascript','text/css'].find(t => String(e.contentType || '').startsWith(t)) || 'application/octet-stream';
      const headers = [{ name: 'Content-Type', value: mime }];
      if (h.cspPresent) headers.push({ name: 'Content-Security-Policy', value: "default-src 'self'" });
      if (h.hstsPresent) headers.push({ name: 'Strict-Transport-Security', value: 'max-age=31536000' });
      if (h.nosniff) headers.push({ name: 'X-Content-Type-Options', value: 'nosniff' });
      if (h.frameProtectionPresent) headers.push({ name: 'X-Frame-Options', value: 'DENY' });
      return { startedDateTime: new Date(e.timestamp).toISOString(), time: e.duration || 0,
        request: { method: e.method, url: syntheticUrl(e), httpVersion: 'HTTP/1.1', cookies: [], headers: [], queryString: [], headersSize: -1, bodySize: 0 },
        response: { status: e.statusCode, statusText: '', httpVersion: 'HTTP/1.1', cookies: [], headers, content: { size: 0, mimeType: mime, text: '' }, redirectURL: '', headersSize: -1, bodySize: 0 }, cache: {}, timings: { send: 0, wait: 0, receive: 0 } };
    });
    await mkdir(directory,{ recursive: true });
    await writeFile(file,JSON.stringify({ log: { version: '1.2', creator: { name: 'TraceHawk', version: '2.0' }, entries } }),'utf8');
    await call('/JSON/exim/action/importHar/',{ filePath: posix.join(process.env.ZAP_CONTAINER_IMPORT_DIR,name) });
    while (Number((await call('/JSON/pscan/view/recordsToScan/')).recordsToScan) > 0) await delay(250,undefined,{ signal });
    const evidence: ToolResult['evidence'] = [];
    for (const origin of [host,host.replace('http:', 'https:')]) for (let start=0;start<10000;start+=100) {
      const { alerts } = await call('/JSON/core/view/alerts/',{ baseurl: origin, start: String(start), count: '100' });
      if (!Array.isArray(alerts)) throw new Error('Invalid ZAP alert response');
      for (const alert of alerts) {
        const e = exchanges.find(e => syntheticUrl(e) === alert.url);
        if (!e) continue;
        evidence.push({ id: randomUUID(), kind: 'zap_passive', endpoint: endpointRef(e.url), sourceIds: [e.id],
          observations: { scannerId: String(alert.pluginId).replace(/\D/g,''), risk: Number(alert.riskcode), confidence: Number(alert.confidence), limitation: 'ZAP analyzed privacy-projected headers and empty bodies. Review as a hypothesis; not proof of exploitability.' }, supports: [], refutes: [] });
      }
      if (alerts.length < 100) break;
    }
    return { status: 'ok', evidence, summary: `ZAP passive analysis completed for ${entries.length} privacy-projected recorded responses; no target traffic sent.` };
  } finally { busy = false; await unlink(file).catch(() => {}); }
}
