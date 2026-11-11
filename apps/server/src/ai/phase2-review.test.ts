import { describe, expect, it } from 'vitest';
import { gateHypothesis, HypothesisSchema, StartAuditSchema, Evidence } from './contracts.js';
import { isAllowed, toolSchemas } from './tools.js';
import { bodyShape, endpointRef, headerFacts, scrubText } from './privacy.js';
import { completionUrl, parseModelJson, AiSecurityProvider } from './provider.js';
import { sanitizeBody, sanitizeHeaders } from '../utils/redact.js';
const hyp = HypothesisSchema.parse({title:'Claim',affectedEndpoint:'endpoint-1',claimType:'missing_authentication',attackMechanism:'test',prerequisites:'test',potentialImpact:'test',suggestedRemediation:'test',risk:'HIGH',confidence:'HIGH',verificationStatus:'VERIFIED',supportingEvidenceIds:['proof']});
const evidence: Evidence = {id:'proof',endpoint:'endpoint-1',kind:'test',sourceIds:[],observations:{status:200},supports:[],refutes:[]};
describe('Phase 2 strict regression checks',()=>{
  it.each(['missing_authentication','missing_rate_limiting','sensitive_storage','other'] as const)('unsupported %s is never verified',claimType=>{
    expect(gateHypothesis({...hyp,claimType},[evidence]).verificationStatus).toBe('NEEDS_VERIFICATION');
  });
  it('denied or failed tools cannot verify a vulnerability',()=>expect(gateHypothesis(hyp,[]).verificationStatus).toBe('NEEDS_VERIFICATION'));
  it('forged evidence IDs cannot verify a vulnerability',()=>expect(gateHypothesis({...hyp,supportingEvidenceIds:['invented']},[{...evidence,supports:['missing_authentication']}]).verificationStatus).toBe('NEEDS_VERIFICATION'));
  it('proof must match endpoint and claim',()=>{
    expect(gateHypothesis({...hyp,claimType:'missing_csp'},[{...evidence,endpoint:'other',supports:['missing_csp']}]).verificationStatus).toBe('NEEDS_VERIFICATION');
    expect(gateHypothesis(hyp,[{...evidence,supports:['missing_csp']}]).verificationStatus).toBe('NEEDS_VERIFICATION');
  });
  it('exact backend configuration proof can be verified',()=>expect(gateHypothesis({...hyp,claimType:'missing_csp'},[{...evidence,supports:['missing_csp']}]).verificationStatus).toBe('VERIFIED'));
  it('rejection also needs exact counterevidence',()=>{
    expect(gateHypothesis({...hyp,verificationStatus:'REJECTED'},[]).verificationStatus).toBe('NEEDS_VERIFICATION');
    expect(gateHypothesis({...hyp,verificationStatus:'REJECTED'},[{...evidence,refutes:['missing_authentication']}]).verificationStatus).toBe('REJECTED');
  });
  it.each(['http://localhost.attacker.invalid/api','http://127.0.0.1.attacker.invalid/','http://localhost:9999/','http://127.0.0.1:3000/','http://user:password@localhost:3000/','file:///etc/passwd'])('denies unauthorized target %s',url=>expect(isAllowed(url,['http://localhost:3000'])).toBe(false));
  it('accepts only exact explicit origins',()=>expect(isAllowed('http://localhost:3000/path',['http://localhost:3000'])).toBe(true));
  it('rejects session override and unknown arguments',()=>expect(()=>toolSchemas.get_session_evidence.parse({sessionId:'another-session'})).toThrow());
  it('rejects fractional or oversized probe budgets',()=>{
    const args={exchangeId:'11111111-1111-4111-8111-111111111111'};
    expect(()=>toolSchemas.check_rate_limit_with_budget.parse({...args,budget:1.5})).toThrow();
    expect(()=>toolSchemas.check_rate_limit_with_budget.parse({...args,budget:6})).toThrow();
  });
  it('requires explicit authorization and bounded execution limits',()=>{
    for(const data of [{authorized:false},{authorized:true,maxSteps:100},{authorized:true,maxTimeSeconds:999},{authorized:true,requestBudget:500}]) expect(()=>StartAuditSchema.parse(data)).toThrow();
  });
  it.each(['http://model.invalid','http://model.invalid/','http://model.invalid/v1','http://model.invalid/v1/','http://model.invalid/v1/chat/completions'])('normalizes model URL %s',base=>expect(completionUrl(base)).toBe('http://model.invalid/v1/chat/completions'));
  it('preserves custom compatible API prefixes',()=>expect(completionUrl('https://model.invalid/api/v2')).toBe('https://model.invalid/api/v2/chat/completions'));
  it('form passwords, arbitrary cookie values, private personal JSON fields are redacted',()=>{
    expect(sanitizeBody('password=private-test-value','application/x-www-form-urlencoded')).not.toContain('private-test-value');
    expect(sanitizeHeaders({cookie:'sid=secret-value; preference=private-value'}).cookie).not.toContain('secret-value');
    expect(sanitizeBody('{"email":"private@example.invalid","phone":"1234567890"}','application/json')).not.toContain('private@example.invalid');
  });
  it('malformed JSON never falls back to raw text',()=>expect(sanitizeBody('{"password":"private-test-value"','application/json')).not.toContain('private-test-value'));
  it('model projection excludes ALL captured payload values and unknown field names',()=>{
    const shape=JSON.stringify(bodyShape('{"user":{"name":"Private Person","password":"secret-value","private@example.invalid":"private"},"id":123456789}'));
    for(const value of ['Private Person','secret-value','private@example.invalid','123456789'])expect(shape).not.toContain(value);
  });
  it('model endpoint references exclude path, query, credentials and fragment',()=>{
    const reference=endpointRef('http://user:password@localhost:3000/PrivatePerson?token=secret#private');
    for(const value of ['PrivatePerson','password','secret','#private'])expect(reference).not.toContain(value);
  });
  it('model headers carry only facts, never arbitrary header values',()=>expect(JSON.stringify(headerFacts({authorization:'Bearer private-token','content-security-policy':'private@example.invalid'}))).not.toContain('private'));
  it('parseModelJson handles raw JSON and markdown-fenced JSON',()=>{
    expect(parseModelJson('{"ok":true}')).toEqual({ok:true});
    expect(parseModelJson('```json\n{"ok":true}\n```')).toEqual({ok:true});
    expect(parseModelJson('```\n{"ok":true}\n```')).toEqual({ok:true});
  });
  it('scrubText redacts HF tokens and env secret',()=>{
    expect(scrubText('hf_123456789012345678901234567890')).toBe('[REDACTED_TOKEN]');
  });
  it('AiSecurityProvider recognizes Hugging Face provider configuration',()=>{
    const provider = new AiSecurityProvider();
    const origEnv = { ...process.env };
    try {
      process.env.AI_ENABLED = 'true';
      process.env.AI_PROVIDER = 'huggingface';
      process.env.HF_TOKEN = 'hf_testtoken12345678901234567890';
      process.env.AI_MODEL = 'DeepHat/DeepHat-V1-7B:featherless-ai';
      delete process.env.AI_BASE_URL;

      expect(provider.isEnabled()).toBe(true);
      const summary = provider.getConfigSummary();
      expect(summary.enabled).toBe(true);
      expect(summary.provider).toBe('huggingface');
      expect(summary.model).toBe('DeepHat/DeepHat-V1-7B:featherless-ai');
      expect(summary.baseUrl).toBe('https://router.huggingface.co');
    } finally {
      process.env = origEnv;
    }
  });
});
