import { afterEach, expect, it, vi } from 'vitest';
import { z } from 'zod';
import { AiSecurityProvider } from './provider.js';
afterEach(()=>{vi.unstubAllEnvs();vi.unstubAllGlobals();});
function setup() {
  for(const [key,value] of Object.entries({AI_ENABLED:'true',AI_PROVIDER:'custom',HF_TOKEN:'must-not-select-cloud',AI_BASE_URL:'http://127.0.0.1:18001/v1',AI_MODEL:'DeepHat/DeepHat-V1-7B',AI_TOKENIZER_URL:'http://127.0.0.1:18001/tokenize',AI_CONTEXT_TOKENS:'32768',AI_MAX_OUTPUT_TOKENS:'2048',AI_REQUEST_TIMEOUT_MS:'180000'}))vi.stubEnv(key,value);
  return new AiSecurityProvider();
}
it('keeps explicit local selection and rejects overflow before generating without truncating evidence',async()=>{
  const provider=setup(); const fetchMock=vi.fn().mockResolvedValue(new Response(JSON.stringify({count:31000,max_model_len:32768})));
  vi.stubGlobal('fetch',fetchMock);
  expect(provider.isHuggingFace()).toBe(false);
  await expect(provider.complete('system',{evidence:'preserved'},z.object({ok:z.boolean()}))).rejects.toThrow('31000 tokens plus 2048');
  expect(fetchMock).toHaveBeenCalledTimes(1);
  expect(JSON.parse(fetchMock.mock.calls[0][1].body).messages[1].content).toContain('preserved');
});
it('reserves output budget and rejects a truncated generation',async()=>{
  const provider=setup(); const fetchMock=vi.fn()
    .mockResolvedValueOnce(new Response(JSON.stringify({count:5000,max_model_len:32768})))
    .mockResolvedValueOnce(new Response(JSON.stringify({choices:[{finish_reason:'length',message:{content:'{"ok":true}'}}]})));
  vi.stubGlobal('fetch',fetchMock);
  await expect(provider.complete('system',{},z.object({ok:z.boolean()}))).rejects.toThrow('No partial findings');
  expect(JSON.parse(fetchMock.mock.calls[1][1].body).max_tokens).toBe(2048);
});
it('uses the advertised server limit even when the app is configured for more',async()=>{
  const provider=setup();vi.stubGlobal('fetch',vi.fn().mockResolvedValue(new Response(JSON.stringify({count:4384,max_model_len:2048}))));
  await expect(provider.complete('system',{},z.object({ok:z.boolean()}))).rejects.toThrow('server limit of 2048');
});
