import { afterEach, expect, it, vi } from 'vitest';
import { mkdtemp, readFile, readdir, unlink, rmdir } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { runZap } from './zap.js';
let directory='';
afterEach(async()=>{vi.unstubAllGlobals();vi.unstubAllEnvs();if(directory){for(const name of await readdir(directory))await unlink(join(directory,name));await rmdir(directory);directory=''}});
it('ZAP imports private-data-free recorded HAR, waits for scanning, correlates alerts and never replays requests',async()=>{
  directory=await mkdtemp(join(tmpdir(),'tracehawk-zap-test-'));
  vi.stubEnv('ZAP_BASE_URL','http://zap.invalid');vi.stubEnv('ZAP_API_KEY','fixture-key');vi.stubEnv('ZAP_IMPORT_DIR',directory);vi.stubEnv('ZAP_CONTAINER_IMPORT_DIR','/zap/import');
  let imported:any,queuePolls=0;const paths:string[]=[];
  vi.stubGlobal('fetch',vi.fn(async(input:any,init:any)=>{
    const url=new URL(input);paths.push(url.pathname);expect(init.headers['X-ZAP-API-Key']).toBe('fixture-key');expect(init.signal).toBeDefined();expect(init.redirect).toBe('error');
    let data:any;
    if(url.pathname.includes('importHar')){
      const name=String(init.body.get('filePath')).split('/').at(-1)!;
      imported=JSON.parse(await readFile(join(directory,name),'utf8'));data={Result:'OK'};
    }else if(url.pathname.includes('recordsToScan'))data={recordsToScan:++queuePolls<2?'1':'0'};
    else if(url.pathname.includes('/alerts/'))data={alerts:String(init.body.get('baseurl')).startsWith('https:')?[{url:imported.log.entries[0].request.url,pluginId:'10038',riskcode:'2',confidence:'2',evidence:'PRIVATE_SCANNER_EVIDENCE'},{url:'http://unrelated.invalid',pluginId:'9'}]:[]};
    else throw Error('Unexpected ZAP operation');
    return new Response(JSON.stringify(data),{status:200});
  }));
  const result=await runZap([{id:'exchange-id',url:'https://example.invalid/private-person?token=secret',method:'GET',statusCode:200,contentType:'text/html',timestamp:new Date(),responseHeaders:{'set-cookie':'sid=secret-cookie','content-security-policy':"script-src 'nonce-private-nonce'"},sanitizedResponseBody:'private-person'}],new AbortController().signal);
  expect(result.status).toBe('ok');expect(result.evidence).toHaveLength(1);expect(result.evidence[0].sourceIds).toEqual(['exchange-id']);expect(result.evidence[0].supports).toEqual([]);
  expect(imported.log.entries[0].request.url).toMatch(/^https:\/\/evidence-/);
  for(const value of ['private-person','secret-cookie','private-nonce','PRIVATE_SCANNER_EVIDENCE']){expect(JSON.stringify(imported)).not.toContain(value);expect(JSON.stringify(result)).not.toContain(value)}
  expect(queuePolls).toBe(2);expect(paths.every(p=>!p.includes('send')&&!p.includes('spider')&&!p.includes('ascan'))).toBe(true);
  expect(await readdir(directory)).toEqual([]);
});
it('unconfigured scanner reports unavailable rather than local fake ZAP findings',async()=>{
  vi.stubEnv('ZAP_BASE_URL','');expect((await runZap([],new AbortController().signal)).status).toBe('unavailable');
});
