import "dotenv/config";
import { InferenceClient } from "@huggingface/inference";

const token = process.env.HF_TOKEN;

function getClient(): InferenceClient {
  const activeToken = process.env.HF_TOKEN || token;
  if (!activeToken) {
    throw new Error("HF_TOKEN missing");
  }
  return new InferenceClient(activeToken);
}

export const client = token ? new InferenceClient(token) : null;

export async function analyzeWithDeepHat(
  browserLogs: unknown
): Promise<string> {
  const activeClient = getClient();
  const response = await activeClient.chatCompletion({
    model: process.env.AI_MODEL || "DeepHat/DeepHat-V1-7B:featherless-ai",
    messages: [
      {
        role: "system",
        content: `You are an application security analyst.

Analyze recorded browser traffic from authorized applications.

Identify potential vulnerabilities, CWE categories,
attacker impact, supporting evidence, verification
requirements, and recommended fixes.

Distinguish confirmed findings from hypotheses.
Do not invent missing evidence.`,
      },
      {
        role: "user",
        content: JSON.stringify(browserLogs),
      },
    ],
    max_tokens: 1500,
    temperature: 0.2,
  });

  return response.choices[0]?.message?.content ?? "";
}
