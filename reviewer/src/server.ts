// Обработчик webhook GitHub для запуска в Docker (второй способ поставки, кроме GitHub Actions).
import { createHmac, timingSafeEqual } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { review } from './main.ts';

export function verifySignature(secret: string, payload: Buffer, header: string | undefined): boolean {
  if (!header?.startsWith('sha256=')) return false;
  const expected = Buffer.from('sha256=' + createHmac('sha256', secret).update(payload).digest('hex'));
  const got = Buffer.from(header);
  return expected.length === got.length && timingSafeEqual(expected, got);
}

export function shouldReview(event: string, body: any): number | undefined {
  if (event === 'pull_request' && ['opened', 'synchronize', 'reopened', 'ready_for_review'].includes(body.action)) return body.pull_request?.number;
  if (event === 'issue_comment' && body.action === 'created' && body.issue?.pull_request && /^\/ai-review\b/.test(body.comment?.body ?? '')) return body.issue.number;
  return undefined;
}

let queue: Promise<unknown> = Promise.resolve();

async function handle(repo: string, pr: number) {
  const token = process.env.GITHUB_TOKEN!;
  const info: any = await (await fetch(`https://api.github.com/repos/${repo}/pulls/${pr}`, {
    headers: { authorization: `Bearer ${token}`, accept: 'application/vnd.github+json', 'user-agent': 'ai-pr-review' },
  })).json();
  const dir = mkdtempSync(join(tmpdir(), 'rv-'));
  try {
    const url = `https://x-access-token:${token}@github.com/${repo}.git`;
    execFileSync('git', ['clone', '--quiet', '--filter=blob:none', '--no-checkout', url, dir]);
    execFileSync('git', ['-C', dir, 'fetch', '--quiet', 'origin', info.base.sha, info.head.sha]);
    execFileSync('git', ['-C', dir, 'checkout', '--quiet', info.head.sha]);
    const r = await review({ repoDir: dir, base: info.base.sha, head: info.head.sha, repo, pr, prTitle: info.title, prBody: info.body ?? '', dryRun: false });
    console.log(JSON.stringify({ repo, pr, findings: r.findings.length, ms: r.durationMs, llmCostUsd: r.llm.costUsd }));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

if (process.argv[1]?.endsWith('server.ts')) {
  const secret = process.env.WEBHOOK_SECRET;
  if (!secret || !process.env.GITHUB_TOKEN) throw new Error('нужны WEBHOOK_SECRET и GITHUB_TOKEN');
  createServer((req, res) => {
    if (req.method === 'GET' && req.url === '/healthz') return void res.end('ok');
    if (req.method !== 'POST' || req.url !== '/webhook') return void res.writeHead(404).end();
    const chunks: Buffer[] = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const payload = Buffer.concat(chunks);
      if (!verifySignature(secret, payload, req.headers['x-hub-signature-256'] as string)) return void res.writeHead(401).end();
      const body = JSON.parse(payload.toString('utf8'));
      const pr = shouldReview(String(req.headers['x-github-event']), body);
      res.writeHead(202).end();
      if (pr) queue = queue.then(() => handle(body.repository.full_name, pr)).catch((e) => console.error(e));
    });
  }).listen(Number(process.env.PORT ?? 8080), () => console.log('ai-review webhook: слушаю', process.env.PORT ?? 8080));
}
