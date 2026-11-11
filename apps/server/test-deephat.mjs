import "dotenv/config";
import { InferenceClient } from "@huggingface/inference";

const client = new InferenceClient(process.env.HF_TOKEN);

const model = "DeepHat/DeepHat-V1-7B:featherless-ai";

console.log("🚀 Testing DeepHat-V1-7B...\n");

try {
  const response = await client.chatCompletion({
    model,

    messages: [
      {
        role: "system",
        content: `You are a cybersecurity security analyst.
Analyze application code and browser evidence.
Identify potential vulnerabilities, explain their
impact and suggest appropriate verification steps.
Do not claim findings are confirmed without evidence.`
      },
      {
        role: "user",
        content: `
Analyze this Express.js code for security weaknesses:

app.get('/user', async (req, res) => {
  const result = await db.query(
    "SELECT * FROM users WHERE id = " + req.query.id
  );
  res.json(result.rows);
});

Tell me:
1. What vulnerabilities might exist?
2. What CWE categories apply?
3. What could be the impact?
4. How can we verify the issue in our local test app?
5. How should we fix it?
`
      }
    ],

    max_tokens: 800,
    temperature: 0.2
  });

  console.log("✅ DEEPHAT RESPONSE:\n");
  console.log(response.choices[0]?.message?.content);

} catch (error) {
  console.error("❌ DeepHat API Error:");
  console.error(error.message);
}
