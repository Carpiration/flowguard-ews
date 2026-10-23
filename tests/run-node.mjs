// Запуск тестов в Node 18+:  node tests/run-node.mjs
import { runAll } from './harness.js';
import './core.test.js';
import './samples.test.js';

const results = await runAll((r) => {
  const mark = r.ok ? '✓' : '✗';
  console.log(`${mark} [${r.file}] ${r.name} (${r.ms.toFixed(0)} мс)`);
  if (!r.ok) console.log(`    ${r.error.stack || r.error.message}`);
});
const failed = results.filter((r) => !r.ok).length;
console.log(`\n${results.length - failed} из ${results.length} тестов пройдено.`);
process.exit(failed ? 1 : 0);
