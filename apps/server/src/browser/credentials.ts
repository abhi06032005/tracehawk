import { createHash, randomUUID } from 'node:crypto';
import type { BrowserContext, Request, Response } from 'playwright';
import { prisma } from '../db.js';

type Entry = { id: string; value: string; expires: number; metadata: Record<string, unknown> };
const vault = new Map<string, Map<string, Entry>>();
const ttl = 30 * 60 * 1000;
export function tokenMetadata(value: string): Record<string, unknown> {
  const base: Record<string, unknown> = { fingerprint: createHash('sha256').update(value).digest('hex').slice(0, 16), length: value.length, format: 'opaque' };
  try {
    const parts=value.split('.'); if(parts.length!==3)return base;
    const header=JSON.parse(Buffer.from(parts[0],'base64url').toString()), claims=JSON.parse(Buffer.from(parts[1],'base64url').toString());
    const algorithms=['none','HS256','HS384','HS512','RS256','RS384','RS512','ES256','ES384','ES512','PS256','PS384','PS512','EdDSA'];
    return { ...base, format:'JWT', algorithm:algorithms.includes(header.alg)?header.alg:'unrecognized',
      expiresAt:typeof claims.exp==='number'&&Number.isFinite(claims.exp)?claims.exp:null,
      issuedAt:typeof claims.iat==='number'&&Number.isFinite(claims.iat)?claims.iat:null,
      notBefore:typeof claims.nbf==='number'&&Number.isFinite(claims.nbf)?claims.nbf:null,
      hasIssuer:typeof claims.iss==='string',hasAudience:Boolean(claims.aud),hasSubject:typeof claims.sub==='string',
      signaturePresent:parts[2].length>0, limitation:'Decoded metadata only. Signature validity and exploitability have not been verified.' };
  }catch{return base}
}
export async function captureToken(sessionId:string, value:string, location:string, origin:string, flags:Record<string,unknown>={}) {
  if(!value||value.includes('[REDACTED')||value.length>16384)return;
  const metadata: Record<string, unknown>={...tokenMetadata(value),location,origin,...flags};
  const entries=vault.get(sessionId)||new Map<string,Entry>();vault.set(sessionId,entries);
  for(const [key,entry] of entries)if(entry.expires<Date.now())entries.delete(key);
  const key=`${metadata.fingerprint}:${location}:${origin}:${JSON.stringify(flags)}`;
  if(entries.has(key))return;
  if(entries.size>=100)entries.delete(entries.keys().next().value!);
  const id=randomUUID();entries.set(key,{id,value,expires:Date.now()+ttl,metadata});
  await prisma.browserEvent.create({data:{sessionId,type:'TOKEN_OBSERVATION',message:'Authentication material observed; raw value is held temporarily in local memory only.',metadata:{...metadata,tokenId:id}}});
}
export function revealToken(sessionId:string,id:string):string|null {
  const entries=vault.get(sessionId);if(!entries)return null;
  for(const [key,e]of entries){if(e.expires<Date.now()){entries.delete(key);continue}if(e.id===id)return e.value}
  return null;
}
export function forgetTokens(sessionId:string){vault.delete(sessionId)}
const timer=setInterval(()=>{for(const [session,entries]of vault){for(const [key,e]of entries)if(e.expires<Date.now())entries.delete(key);if(!entries.size)vault.delete(session)}},60000);timer.unref();
async function jsonTokens(session:string,value:unknown,location:string,origin:string,depth=0):Promise<void>{
  if(depth>5||!value||typeof value!=='object')return;
  for(const [key,item]of Object.entries(value).slice(0,100)){
    if(/^(access_?token|refresh_?token|auth_?token|id_?token|jwt|token)$/i.test(key)&&typeof item==='string')await captureToken(session,item,location,origin);
    else if(typeof item==='object')await jsonTokens(session,item,location,origin,depth+1);
  }
}
export function attachCredentialCapture(sessionId:string,context:BrowserContext,origins:string[],recording:()=>boolean) {
  let closed=false;
  const pending=new Set<Promise<void>>();
  const eligible=(url:string)=>{try{return !closed&&recording()&&origins.includes(new URL(url).origin)}catch{return false}};
  const track=(task:Promise<void>)=>{pending.add(task);void task.catch(()=>{}).finally(()=>pending.delete(task))};
  const request=(req:Request)=>{if(!eligible(req.url()))return;const origin=new URL(req.url()).origin;const headers=req.headers();
    if(headers.authorization?.startsWith('Bearer '))track(captureToken(sessionId,headers.authorization.slice(7),'Authorization header',origin));
    if(headers.cookie)for(const pair of headers.cookie.split(';')){const i=pair.indexOf('=');if(i>=0)track(captureToken(sessionId,pair.slice(i+1).trim(),'Cookie request',origin));}
  };
  const response=(res:Response)=>{if(!eligible(res.url()))return;track((async()=>{
    const origin=new URL(res.url()).origin;
    const responseHeaders=await res.headersArray();if(closed||!recording())return;
    for(const header of responseHeaders)if(header.name.toLowerCase()==='set-cookie'){
      const first=header.value.split(';')[0],i=first.indexOf('=');if(i>=0)await captureToken(sessionId,first.slice(i+1),'Set-Cookie response',origin,{httpOnly:/;\s*httponly(?:;|$)/i.test(header.value),secure:/;\s*secure(?:;|$)/i.test(header.value),sameSite:header.value.match(/;\s*samesite=(Strict|Lax|None)/i)?.[1]?.toLowerCase()||'unspecified'});
    }
    const headers=res.headers();
    if(headers['content-type']?.includes('application/json')&&Number(headers['content-length']||0)<65536){const body=await res.body();if(!closed&&recording()&&body.length<=65536)try{await jsonTokens(sessionId,JSON.parse(body.toString()),'JSON response',origin)}catch{}}
  })())};
  context.on('request',request);context.on('response',response);
  let snapshotRunning=false;
  const storage=async()=>{if(snapshotRunning||closed||!recording())return;snapshotRunning=true;try{
    for(const page of context.pages())if(eligible(page.url())){
      const origin=new URL(page.url()).origin;
      const values=await page.evaluate(()=>{
        const entries:{location:string;value:string}[]=[];
        for(const [location,store]of [['localStorage',localStorage],['sessionStorage',sessionStorage]] as const)for(let i=0;i<Math.min(store.length,100);i++){
          const key=store.key(i)!;if(/token|jwt|auth/i.test(key)){const value=store.getItem(key)||'';if(value.length<=16384)entries.push({location,value})}
        }return entries;
      }).catch(()=>[]);
      if(!closed&&recording())for(const entry of values){try{await jsonTokens(sessionId,JSON.parse(entry.value),entry.location,origin)}catch{}if(/^[\w-]+\.[\w-]+\.[\w-]*$/.test(entry.value)||!entry.value.startsWith('{'))await captureToken(sessionId,entry.value,entry.location,origin)}
    }
  }finally{snapshotRunning=false}};
  const interval=setInterval(()=>track(storage()),3000);interval.unref();
  return async()=>{await Promise.race([storage().catch(()=>{}),new Promise(r=>setTimeout(r,2000))]);closed=true;clearInterval(interval);context.off('request',request);context.off('response',response);await Promise.race([Promise.allSettled([...pending]),new Promise(r=>setTimeout(r,2000))]);};
}
