import { appendFileSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { parseArgs } from 'node:util';
import { runAnalyzers } from './analyzers.ts';
import { isIgnored, loadConfig, type Config } from './config.ts';
import { fileAtHead, getDiff } from './diff.ts';
import { alreadyThere, commentBody, GitHub, SUMMARY_MARK } from './github.ts';
import { runLlm } from './llm.ts';
import { fingerprint, fitIndent, leaksLiteral, mergeFindings, suggestionFits, type MergeStats } from './merge.ts';
import { CLASS_LABEL, CLASSES, SEVERITIES, SEVERITY_LABEL, type AnalyzerRun, type Finding, type LlmRun } from './types.ts';

export interface ReviewOptions {
  repoDir: string;
  base: string;
  head: string;
  repo?: string;
  pr?: number;
  prTitle?: string;
  prBody?: string;
  dryRun: boolean;
  out?: string;
  runUrl?: string;
  label?: string;
}

export interface ReviewReport {
  repo?: string;
  pr?: number;
  base: string;
  head: string;
  startedAt: string;
  durationMs: number;
  changedFiles: number;
  changedLines: number;
  analyzers: AnalyzerRun[];
  llm: Omit<LlmRun, 'raw'> & { rawFindings: number };
  merge: MergeStats;
  findings: Finding[];
  published: { newComments: number; alreadyPublished: number; falsePositiveMarked: number; failed: number; summaryOnly: number };
  status: 'success' | 'failure';
}

const plural = (n: number) => `${n}`;

export function summaryMarkdown(r: ReviewReport, cfg: Config, label = ''): string {
  const bySev = SEVERITIES.map((s) => `${SEVERITY_LABEL[s]}: **${r.findings.filter((f) => f.severity === s).length}**`).join(' · ');
  const byCls = CLASSES.map((c) => [CLASS_LABEL[c], r.findings.filter((f) => f.cls === c).length] as const).filter(([, n]) => n);
  const crit = r.findings.filter((f) => f.severity === 'critical').length;
  const statusLine = crit
    ? cfg.blockOnCritical ? '⛔ Есть критичные замечания, слияние заблокировано (blockOnCritical: true).' : '⚠️ Есть критичные замечания. Блокировка слияния выключена в конфиге, решение за ревьюером.'
    : '✅ Критичных замечаний нет, можно передавать ревьюеру.';
  const lines = [
    `## 🤖 AI-ревью${label}: ${plural(r.findings.length)} замечаний`,
    '',
    bySev,
    '',
    statusLine,
    '',
    '| Класс | Замечаний |',
    '|---|---|',
    ...byCls.map(([c, n]) => `| ${c} | ${n} |`),
  ];
  const off = r.findings.filter((f) => f.summaryOnly);
  if (off.length) {
    lines.push('', '**Не привязаны к строкам diff:**');
    for (const f of off) lines.push(`- ${SEVERITY_LABEL[f.severity]} \`${f.path}\` — ${f.title}`);
  }
  const an = r.analyzers.map((a) => `${a.name} ${a.status === 'ok' ? `${a.count} (${(a.ms / 1000).toFixed(1)} с)` : a.status === 'skipped' ? 'пропущен' : 'ошибка'}`).join(', ');
  const llm = r.llm.provider === 'none' ? 'выключена'
    : `${r.llm.model} (${r.llm.provider}), вызовов ${r.llm.calls}, токенов ${r.llm.promptTokens} вх. / ${r.llm.completionTokens} вых., ` +
      `≈ $${r.llm.costUsd.toFixed(4)}, ${(r.llm.ms / 1000).toFixed(1)} с${r.llm.error ? `, ошибка: ${r.llm.error}` : ''}`;
  lines.push(
    '',
    '<details><summary>Журнал проверки</summary>',
    '',
    `- Изменено: ${r.changedFiles} файлов, +${r.changedLines} строк; коммит \`${r.head.slice(0, 7)}\``,
    `- Анализаторы: ${an}`,
    `- LLM: ${llm}`,
    `- LLM: принято ${r.merge.llmAccepted}, уточнило замечаний анализаторов ${r.merge.llmEnriched}, отброшено по строке ${r.merge.llmDroppedLine}, по уверенности ${r.merge.llmDroppedConfidence}, понижено с «критично» ${r.merge.llmDowngraded}; склеено дублей ${r.merge.deduplicated}`,
    `- Комментарии: новых ${r.published.newComments}, уже были ${r.published.alreadyPublished}, отмечены 👎 как ложные ${r.published.falsePositiveMarked}`,
    `- Время проверки: ${(r.durationMs / 1000).toFixed(1)} с`,
    '',
    '</details>',
    '',
    '<sub>Демо-стенд TEMIRLAB для задачи AstanaHub. Ассистент только комментирует: не сливает, не отклоняет и не пишет в ветки. Перезапуск: комментарий `/ai-review`.</sub>',
    SUMMARY_MARK,
  );
  return lines.join('\n');
}

export async function review(o: ReviewOptions, env: NodeJS.ProcessEnv = process.env): Promise<ReviewReport> {
  const t0 = Date.now();
  const cfg = loadConfig(o.repoDir, env);
  const files = getDiff(o.repoDir, o.base, o.head).filter((f) => !f.binary && !isIgnored(f.path, cfg.ignorePaths));
  const changedLines = files.reduce((s, f) => s + f.added.size, 0);

  const { findings: statics, runs } = await runAnalyzers({ repoDir: o.repoDir, base: o.base, head: o.head, files, config: cfg });

  const withContent = files.filter((f) => f.status !== 'deleted' && f.added.size > 0)
    .map((file) => ({ file, content: fileAtHead(o.repoDir, o.head, file.path) }));
  const meta = [
    `Pull request${o.pr ? ` #${o.pr}` : ''}: ${o.prTitle ?? ''}`,
    o.prBody ? `Описание: ${o.prBody.slice(0, 1500)}` : '',
    `Изменённые файлы: ${files.map((f) => f.path).join(', ')}`,
  ].filter(Boolean).join('\n');
  const llm = await runLlm(cfg.llm, withContent, statics, meta, env);

  const { findings, stats } = mergeFindings(statics, llm.raw, files, cfg, cfg.llm.model);
  for (const f of findings) {
    const content = withContent.find((w) => w.file.path === f.path)?.content ?? [];
    f.fingerprint = fingerprint(f, content[f.line - 1] ?? `${f.line}`);
    if (f.suggestion && content[f.line - 1] !== undefined) f.suggestion = fitIndent(f.suggestion, content[f.line - 1]);
    if (f.suggestion && f.cls === 'secrets' && leaksLiteral(f.suggestion, content.slice(f.line - 1, f.endLine ?? f.line))) f.suggestion = undefined;
    if (f.suggestion && !suggestionFits(f.suggestion, content.slice(f.line - 1, f.endLine ?? f.line))) f.suggestion = undefined;
    // Исправление, которое ничего не меняет, только шумит.
    if (f.suggestion && f.suggestion.trim() === content.slice(f.line - 1, f.endLine ?? f.line).join('\n').trim()) f.suggestion = undefined;
  }

  const report: ReviewReport = {
    repo: o.repo, pr: o.pr, base: o.base, head: o.head, startedAt: new Date(t0).toISOString(), durationMs: 0,
    changedFiles: files.length, changedLines, analyzers: runs,
    llm: { ...llm, raw: undefined, rawFindings: llm.raw.length } as ReviewReport['llm'],
    merge: stats, findings,
    published: { newComments: 0, alreadyPublished: 0, falsePositiveMarked: 0, failed: 0, summaryOnly: findings.filter((f) => f.summaryOnly).length },
    status: cfg.blockOnCritical && findings.some((f) => f.severity === 'critical') ? 'failure' : 'success',
  };

  if (!o.dryRun && o.repo && o.pr) {
    const token = env.GITHUB_TOKEN ?? '';
    const gh = new GitHub(o.repo, token);
    const existing = await gh.existing(o.pr);
    const fresh = findings.filter((f) => !f.summaryOnly && !alreadyThere(f, existing));
    const toPost = fresh.slice(0, cfg.maxComments);
    const res = await gh.postReview(o.pr, o.head, toPost.map((f) => ({
      path: f.path, line: f.endLine ?? f.line, start_line: f.endLine ? f.line : undefined, body: commentBody(f),
    })));
    report.published = {
      ...report.published, newComments: res.posted, failed: res.failed,
      alreadyPublished: findings.filter((f) => alreadyThere(f, existing)).length,
      falsePositiveMarked: existing.filter((c) => c.falsePositive).length,
    };
    report.durationMs = Date.now() - t0;
    await gh.upsertSummary(o.pr, summaryMarkdown(report, cfg, o.label ?? ''));
    const crit = findings.filter((f) => f.severity === 'critical').length;
    await gh.status(o.head, report.status, `${findings.length} замечаний, критичных ${crit}`, o.runUrl);
  }
  report.durationMs = Date.now() - t0;
  return report;
}

async function cli() {
  const { values } = parseArgs({
    options: {
      'repo-dir': { type: 'string', default: '.' },
      base: { type: 'string' },
      head: { type: 'string', default: 'HEAD' },
      repo: { type: 'string' },
      pr: { type: 'string' },
      'pr-json': { type: 'string' },
      'dry-run': { type: 'boolean', default: false },
      out: { type: 'string', default: 'ai-review-report.json' },
      label: { type: 'string', default: '' },
    },
  });
  if (!values.base) throw new Error('нужен --base <sha>');
  const prJson = values['pr-json'] ? JSON.parse(readFileSync(values['pr-json'], 'utf8')) : {};
  const env = process.env;
  const runUrl = env.GITHUB_RUN_ID ? `${env.GITHUB_SERVER_URL}/${env.GITHUB_REPOSITORY}/actions/runs/${env.GITHUB_RUN_ID}` : undefined;
  const report = await review({
    repoDir: resolve(values['repo-dir']!), base: values.base, head: values.head!, repo: values.repo,
    pr: values.pr ? Number(values.pr) : undefined, prTitle: prJson.title, prBody: prJson.body ?? undefined,
    dryRun: values['dry-run']!, runUrl, label: values.label,
  });
  writeFileSync(values.out!, JSON.stringify(report, null, 2));
  const cfg = loadConfig(resolve(values['repo-dir']!));
  const md = summaryMarkdown(report, cfg, values.label);
  if (env.GITHUB_STEP_SUMMARY) {
    const table = ['', '| Уровень | Класс | Файл:строка | Замечание | Источник |', '|---|---|---|---|---|',
      ...report.findings.map((f) => `| ${SEVERITY_LABEL[f.severity]} | ${CLASS_LABEL[f.cls]} | \`${f.path}:${f.line}\` | ${f.title.replace(/\|/g, '\\|')} | ${f.sources.join(', ')} |`)];
    appendFileSync(env.GITHUB_STEP_SUMMARY, md + '\n' + table.join('\n') + '\n');
  }
  console.log(md);
  console.log('analyzers:', JSON.stringify(report.analyzers));
  for (const f of report.findings) console.log(`${f.severity.padEnd(8)} ${f.cls.padEnd(8)} ${f.path}:${f.line}  ${f.title}  [${f.sources.join(', ')}]`);
}

if (/main\.ts$/.test(process.argv[1] ?? '')) {
  cli().catch((e) => {
    console.error(e);
    process.exit(1);
  });
}
