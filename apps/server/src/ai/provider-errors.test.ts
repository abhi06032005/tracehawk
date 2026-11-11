import { expect, it } from 'vitest';
import { z } from 'zod';
import { modelFailureMessage, modelHttpFailure } from './provider.js';

it('explains context overflow without copying server prompt contents', () => {
  const error = modelHttpFailure(400, 'maximum context length is 2048 tokens; private-prompt-here');
  expect(modelFailureMessage(error)).toContain('YaRN launch script');
  expect(modelFailureMessage(error)).not.toContain('private-prompt-here');
});
it('distinguishes structured output failures and other HTTP errors', () => {
  expect(modelFailureMessage(modelHttpFailure(400, 'response_format json_object unsupported'))).toContain('AI_JSON_MODE');
  expect(modelFailureMessage(modelHttpFailure(401, 'secret'))).toContain('HTTP 401');
  expect(modelFailureMessage(modelHttpFailure(401, 'secret'))).not.toContain('secret');
});
it('does not leak invalid JSON, schema values, or backend exception text', () => {
  expect(modelFailureMessage(new SyntaxError('private-content'))).toContain('invalid JSON');
  const result = z.object({phase:z.literal('ANALYZE')}).safeParse({phase:'private-content'});
  if (!result.success) expect(modelFailureMessage(result.error)).toContain('JSON schema');
  expect(modelFailureMessage(new Error('private-content'))).not.toContain('private-content');
});
