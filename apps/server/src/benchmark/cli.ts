import { resolve } from 'node:path';
import { existsSync } from 'node:fs';
import { mkdir, writeFile } from 'node:fs/promises';
import dotenv from 'dotenv';

// Load environment variables from root or apps/server .env
dotenv.config();
dotenv.config({ path: resolve(process.cwd(), 'apps/server/.env') });
dotenv.config({ path: resolve(process.cwd(), '../../.env') });

import { BenchmarkRunner } from './runner.js';
import { BenchmarkReporter } from './reporter.js';
import { ModelProviderRegistry } from './providers/registry.js';

interface CliArgs {
  fixturePath: string;
  models: string[];
  promptVariants: string[];
  repeats: number;
  outputDir: string;
  outputFormat: 'md' | 'json' | 'both';
}

function getDefaultFixturePath(): string {
  const serverPath = resolve(process.cwd(), 'src/benchmark/fixtures/juice-shop-fixture.json');
  if (existsSync(serverPath)) return serverPath;
  return resolve(process.cwd(), 'apps/server/src/benchmark/fixtures/juice-shop-fixture.json');
}

function getDefaultOutputDir(): string {
  if (process.cwd().replace(/\\/g, '/').endsWith('apps/server')) {
    return resolve(process.cwd(), '../../artifacts/benchmark');
  }
  return resolve(process.cwd(), 'artifacts/benchmark');
}

function parseArgs(args: string[]): CliArgs {
  const result: CliArgs = {
    fixturePath: getDefaultFixturePath(),
    models: ['deephat'],
    promptVariants: ['default', 'correctness-review'],
    repeats: 3,
    outputDir: getDefaultOutputDir(),
    outputFormat: 'both',
  };

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === '--fixture' && args[i + 1]) {
      result.fixturePath = resolve(args[++i]);
    } else if (arg === '--models' && args[i + 1]) {
      result.models = args[++i].split(',').map((s) => s.trim().toLowerCase()).filter(Boolean);
    } else if ((arg === '--prompt-variants' || arg === '--variants') && args[i + 1]) {
      result.promptVariants = args[++i].split(',').map((s) => s.trim()).filter(Boolean);
    } else if ((arg === '--repeats' || arg === '-n') && args[i + 1]) {
      result.repeats = parseInt(args[++i], 10) || 3;
    } else if (arg === '--output-dir' && args[i + 1]) {
      result.outputDir = resolve(args[++i]);
    } else if (arg === '--output-format' && args[i + 1]) {
      const fmt = args[++i].toLowerCase();
      if (['md', 'json', 'both'].includes(fmt)) {
        result.outputFormat = fmt as any;
      }
    } else if (arg === '--help' || arg === '-h') {
      console.log(`
TraceHawk Research Benchmark Suite
Usage:
  tracehawk benchmark [options]

Options:
  --fixture <path>           Path to ground-truth fixture JSON (default: juice-shop-fixture.json)
  --models <list>            Comma-separated provider IDs: deephat, gpt, gemini, groq, whiterabbitneo
  --prompt-variants <list>   Comma-separated prompt IDs: default, correctness-review
  --repeats <n>              Number of repeat runs per model and prompt variant (default: 3)
  --output-dir <path>        Directory to store output reports (default: ./artifacts/benchmark)
  --output-format <format>   md | json | both (default: both)
  --help, -h                 Show this help message
`);
      process.exit(0);
    }
  }

  return result;
}

export async function runCli(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));

  console.log(`=======================================================`);
  console.log(` TraceHawk Research Model Benchmark Harness`);
  console.log(`=======================================================`);
  console.log(`Fixture:         ${args.fixturePath}`);
  console.log(`Models:          ${args.models.join(', ')}`);
  console.log(`Prompt Variants: ${args.promptVariants.join(', ')}`);
  console.log(`Repeats:         ${args.repeats}`);
  console.log(`Output Dir:      ${args.outputDir}`);
  console.log(`-------------------------------------------------------`);

  const availableProviders = ModelProviderRegistry.listProviders();
  console.log(`Provider Configuration Status:`);
  for (const p of availableProviders) {
    const isSelected = args.models.includes(p.id);
    const mark = p.isConfigured ? '✓ Ready' : '✗ Missing API Key/URL';
    console.log(`  ${isSelected ? '▶' : ' '} [${p.id}] ${p.name}: ${mark}`);
  }
  console.log(`-------------------------------------------------------\n`);

  const benchmarkResult = await BenchmarkRunner.run({
    fixture: args.fixturePath,
    models: args.models,
    promptVariants: args.promptVariants,
    repeats: args.repeats,
    onProgress: (info) => {
      console.log(
        `[${info.currentStep}/${info.totalSteps}] ${info.model} | variant=${info.variant} | run ${info.repeat}/${args.repeats} - ${info.status}`
      );
    },
  });

  console.log(`\n=======================================================`);
  console.log(` Benchmark Run Completed (${benchmarkResult.runs.length} runs executed)`);
  console.log(`=======================================================\n`);

  const mdReport = BenchmarkReporter.generateMarkdown(benchmarkResult);
  const jsonReport = BenchmarkReporter.generateJson(benchmarkResult);

  await mkdir(args.outputDir, { recursive: true });
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const mdPath = resolve(args.outputDir, `benchmark-report-${timestamp}.md`);
  const jsonPath = resolve(args.outputDir, `benchmark-report-${timestamp}.json`);

  if (args.outputFormat === 'md' || args.outputFormat === 'both') {
    await writeFile(mdPath, mdReport, 'utf8');
    console.log(`Saved Markdown Report: ${mdPath}`);
  }

  if (args.outputFormat === 'json' || args.outputFormat === 'both') {
    await writeFile(jsonPath, jsonReport, 'utf8');
    console.log(`Saved JSON Report:     ${jsonPath}`);
  }

  // Generate individual model reports containing everything the model wrote down
  const modelReports = BenchmarkReporter.generateIndividualModelReports(benchmarkResult);
  const modelReportsDir = resolve(args.outputDir, 'model-reports');
  await mkdir(modelReportsDir, { recursive: true });

  for (const [modelName, reportContent] of modelReports.entries()) {
    const slug = modelName.replace(/[^a-zA-Z0-9_-]/g, '_').toLowerCase();
    const modelReportPath = resolve(modelReportsDir, `model-report-${slug}-${timestamp}.md`);
    await writeFile(modelReportPath, reportContent, 'utf8');
    console.log(`Saved Individual Model Report (${modelName}): ${modelReportPath}`);
  }

  console.log(`\n${mdReport}`);
}

// Auto-run if executed directly via CLI
if (process.argv[1]?.replace(/\\/g, '/').endsWith('benchmark/cli.ts') || process.argv[1]?.replace(/\\/g, '/').endsWith('benchmark/cli.js')) {
  runCli().catch((err) => {
    console.error(`[Benchmark Error]:`, err);
    process.exit(1);
  });
}
