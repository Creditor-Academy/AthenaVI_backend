/**
 * Phase 0.1 — why presentation exports fail, from the export jobs table.
 *
 *   node scripts/presentation-eval/export-failures.js [--days 30] [--json]
 *
 * Run it where the database is (inside the production container: the env is already set;
 * locally it loads .env.production / .env.development like server.js). It reads only the
 * export rows (format, status, error, dates) — never deck content — and prints:
 *   - counts by status and format,
 *   - failed exports grouped by error message (most frequent first),
 *   - exports stuck in QUEUED / RENDERING.
 *
 * Also check the logs for: presentation_export_failed, export_browser_unavailable,
 * export_renderer_unavailable, pptx_renderer_capture_failed.
 */

const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, '../..');
const envFile = process.env.NODE_ENV === 'production' ? '.env.production' : '.env.development';
if (!process.env.DATABASE_URL && fs.existsSync(path.join(root, envFile))) {
  require('dotenv').config({ path: path.join(root, envFile) });
}

function arg(name, fallback) {
  const i = process.argv.indexOf(`--${name}`);
  return i > -1 ? process.argv[i + 1] : fallback;
}

/** Group error messages that differ only by ids, numbers or URLs. */
function errorKey(message) {
  return String(message || '(no message)')
    .replace(/https?:\/\/\S+/g, '<url>')
    .replace(/[0-9a-f]{8}-[0-9a-f-]{27,}/gi, '<id>')
    .replace(/\bc[a-z0-9]{20,}\b/gi, '<id>')
    .replace(/\d+/g, '<n>')
    .slice(0, 240);
}

async function main() {
  const days = Math.max(1, Number(arg('days', 30)) || 30);
  const asJson = process.argv.includes('--json');
  const since = new Date(Date.now() - days * 24 * 60 * 60 * 1000);
  const prisma = require('../../src/shared/config/prismaClient');

  try {
    const rows = await prisma.deckExport.findMany({
      where: { createdAt: { gte: since } },
      select: { format: true, status: true, error: true, createdAt: true, updatedAt: true },
      orderBy: { createdAt: 'desc' },
    });

    const byStatus = {};
    const byFormat = {};
    const failures = new Map();
    const stuck = [];
    for (const row of rows) {
      byStatus[row.status] = (byStatus[row.status] || 0) + 1;
      const f = (byFormat[row.format] = byFormat[row.format] || { total: 0, failed: 0 });
      f.total += 1;
      if (row.status === 'FAILED') {
        f.failed += 1;
        const key = errorKey(row.error);
        const group = failures.get(key) || { count: 0, formats: {}, last: null, example: row.error };
        group.count += 1;
        group.formats[row.format] = (group.formats[row.format] || 0) + 1;
        if (!group.last || row.createdAt > group.last) group.last = row.createdAt;
        failures.set(key, group);
      }
      if ((row.status === 'QUEUED' || row.status === 'RENDERING') && Date.now() - row.updatedAt > 15 * 60 * 1000) {
        stuck.push({ format: row.format, status: row.status, since: row.updatedAt });
      }
    }

    const report = {
      since: since.toISOString(),
      total: rows.length,
      byStatus,
      byFormat: Object.fromEntries(
        Object.entries(byFormat).map(([k, v]) => [k, { ...v, failureRate: v.total ? Math.round((v.failed / v.total) * 1000) / 10 : 0 }])
      ),
      failures: [...failures.entries()]
        .sort((a, b) => b[1].count - a[1].count)
        .map(([key, g]) => ({ count: g.count, formats: g.formats, last: g.last, error: key, example: String(g.example || '').slice(0, 400) })),
      stuck,
    };

    if (asJson) {
      console.log(JSON.stringify(report, null, 2));
      return;
    }
    console.log(`Presentation exports since ${report.since}: ${report.total}`);
    console.log('By status:', JSON.stringify(report.byStatus));
    console.log('\nBy format:');
    for (const [format, v] of Object.entries(report.byFormat)) {
      console.log(`  ${format.padEnd(5)} ${String(v.total).padStart(5)} exports, ${String(v.failed).padStart(4)} failed (${v.failureRate}%)`);
    }
    console.log('\nFailures by error (most frequent first):');
    if (!report.failures.length) console.log('  none');
    for (const f of report.failures) {
      console.log(`  ${String(f.count).padStart(4)} × ${JSON.stringify(f.formats)}  last ${new Date(f.last).toISOString()}`);
      console.log(`         ${f.example}`);
    }
    console.log(`\nStuck in QUEUED / RENDERING for over 15 minutes: ${report.stuck.length}`);
  } finally {
    await prisma.$disconnect();
  }
}

main().catch((err) => {
  console.error('export-failures failed:', err.message);
  process.exit(1);
});
