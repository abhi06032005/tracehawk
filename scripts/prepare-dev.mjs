import { spawnSync } from 'node:child_process';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
function run(command, args, quiet = false) {
  const result = spawnSync(command, args, { cwd: root, stdio: quiet ? 'ignore' : 'inherit', windowsHide: true });
  return result.status === 0;
}
function required(command, args) {
  if (!run(command, args)) throw new Error(`Startup failed: ${command} ${args.join(' ')}`);
}
try {
  console.log('Preparing TraceHawk local services...');
  if (!run('docker', ['info'], true)) {
    console.log('Starting Docker Desktop...');
    required('docker', ['desktop', 'start']);
    let ready = false;
    for (let attempt = 0; attempt < 60; attempt++) {
      if (run('docker', ['info'], true)) { ready = true; break; }
      await delay(2000);
    }
    if (!ready) throw new Error('Docker is not ready. Open Docker Desktop and retry npm run dev.');
  }
  required('docker', ['compose', '--profile', 'security-test', 'up', '-d']);
  let databaseReady = false;
  for (let attempt = 0; attempt < 60; attempt++) {
    if (run('docker', ['compose', 'exec', '-T', 'postgres', 'pg_isready', '-U', 'postgres', '-d', 'tracehawk'], true)) {
      databaseReady = true; break;
    }
    await delay(1000);
  }
  if (!databaseReady) throw new Error('The local database did not become ready.');
  // npm_execpath avoids Windows command-shell quoting and uses the invoking npm.
  required(process.execPath, [process.env.npm_execpath, '--workspace=apps/server', 'run', 'db:generate']);
  required(process.execPath, [process.env.npm_execpath, '--workspace=apps/server', 'run', 'db:deploy']);
  console.log('Ready. Dashboard: http://localhost:3001 | Demo target: http://localhost:3000');
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
}
