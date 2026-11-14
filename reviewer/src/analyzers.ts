import { spawn } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, relative, isAbsolute } from 'node:path';
import type { Config } from './config.ts';
import type { DiffFile } from './diff.ts';
import type { AnalyzerRun, Finding, FindingClass, Severity } from './types.ts';

export interface AnalyzerContext {
  repoDir: string;
  base: string;
  head: string;
  files: DiffFile[];
  config: Config;
}

let seq = 0;
const nextId = () => `S${++seq}`;

function run(cmd: string, args: string[], cwd: string, timeoutMs = 180_000): Promise<{ stdout: string; stderr: string; code: number | null; missing: boolean }> {
  return new Promise((resolve) => {
    let stdout = '';
    let stderr = '';
    let done = false;
    const p = spawn(cmd, args, { cwd });
    const timer = setTimeout(() => p.kill(), timeoutMs);
    p.stdout.on('data', (d) => (stdout += d));
    p.stderr.on('data', (d) => (stderr += d));
    p.on('error', (e: NodeJS.ErrnoException) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      resolve({ stdout, stderr: String(e.message), code: null, missing: e.code === 'ENOENT' });
    });
    p.on('close', (code) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      resolve({ stdout, stderr, code, missing: false });
    });
  });
}

async function timed(name: string, fn: () => Promise<{ findings: Finding[]; status?: AnalyzerRun['status']; note?: string }>) {
  const t0 = Date.now();
  try {
    const r = await fn();
    return { findings: r.findings, run: { name, status: r.status ?? 'ok', ms: Date.now() - t0, count: r.findings.length, note: r.note } as AnalyzerRun };
  } catch (e) {
    return { findings: [], run: { name, status: 'error', ms: Date.now() - t0, count: 0, note: String((e as Error).message ?? e).slice(0, 300) } as AnalyzerRun };
  }
}

const isTestPath = (p: string) =>
  /(^|\/)(tests?|__tests__|spec)\//i.test(p) || /(^|\/)test_[^/]*\.py$/.test(p) || /_test\.py$/.test(p) ||
  /\.(test|spec)\.[jt]sx?$/.test(p) || /Tests?\.java$/.test(p);
const isCodePath = (p: string) => /\.(py|ts|tsx|js|jsx|java|kt|cs|go)$/.test(p);

/** Оставляем только находки на добавленных строках (±1 для многострочных конструкций). */
function onChangedLines(files: DiffFile[], path: string, start: number, end: number): number | undefined {
  const f = files.find((x) => x.path === path);
  if (!f) return undefined;
  for (let l = start; l <= Math.max(start, end); l++) if (f.added.has(l)) return l;
  return undefined;
}

// ---------- Semgrep ----------
export function mapSemgrep(json: any, files: DiffFile[], disabled: string[]): Finding[] {
  const out: Finding[] = [];
  for (const r of json?.results ?? []) {
    if (disabled.includes(r.check_id)) continue;
    const line = onChangedLines(files, r.path, r.start?.line ?? 0, r.end?.line ?? 0);
    if (!line) continue;
    const md = r.extra?.metadata ?? {};
    const cat = String(md.category ?? '').toLowerCase();
    const id = String(r.check_id);
    let cls: FindingClass = 'quality';
    if (cat === 'security') cls = /secret|credential|hardcoded/i.test(id) ? 'secrets' : 'security';
    else if (cat === 'correctness') cls = 'logic';
    const sev0 = String(r.extra?.severity ?? 'INFO').toUpperCase();
    let severity: Severity = sev0 === 'ERROR' ? 'high' : sev0 === 'WARNING' ? 'medium' : 'low';
    if (cls === 'security' && (String(md.impact).toUpperCase() === 'HIGH' || sev0 === 'ERROR') &&
      String(md.likelihood ?? md.confidence).toUpperCase() === 'HIGH') severity = 'critical';
    if (cls === 'security' && severity === 'medium' && String(md.impact).toUpperCase() === 'HIGH') severity = 'high';
    const cwe = Array.isArray(md.cwe) ? md.cwe[0] : md.cwe;
    out.push({
      id: nextId(), path: r.path, line, cls, severity,
      title: String(r.extra?.message ?? id).split(/\.\s/)[0].slice(0, 140),
      explanation: String(r.extra?.message ?? '') + (cwe ? `\n\n${cwe}` : ''),
      suggestion: undefined,
      sources: ['semgrep'], ruleIds: [`semgrep:${id.split('.').slice(-1)[0]}`],
    });
  }
  return out;
}

async function semgrep(ctx: AnalyzerContext) {
  const targets = ctx.files.filter((f) => f.status !== 'deleted' && !f.binary && f.added.size > 0).map((f) => f.path);
  if (!targets.length) return { findings: [], note: 'нет файлов' };
  const args = ['scan', '--json', '--quiet', '--metrics=off', '--disable-version-check', '--timeout', '60'];
  for (const c of ctx.config.analyzers.semgrep.configs) args.push('--config', c);
  const r = await run('semgrep', [...args, ...targets], ctx.repoDir);
  if (r.missing) return { findings: [], status: 'skipped' as const, note: 'semgrep не установлен' };
  if (!r.stdout.trim()) throw new Error(`semgrep код ${r.code}: ${r.stderr.slice(-400)}`);
  const json = JSON.parse(r.stdout);
  if (json.errors?.length) console.error('semgrep errors:', JSON.stringify(json.errors).slice(0, 800));
  return { findings: mapSemgrep(json, ctx.files, ctx.config.disabledRules), note: `${json?.results?.length ?? 0} результатов до фильтра по diff` };
}

// ---------- Ruff (Python) ----------
const RUFF_TITLE_RU: Record<string, string> = {
  S608: 'Возможная SQL-инъекция: запрос собирается из строки',
  S506: 'Небезопасный yaml.load: можно создать произвольный объект',
  S301: 'Небезопасная десериализация pickle',
  S602: 'Запуск команды через shell с внешними данными',
  S105: 'Пароль или секрет прямо в коде',
  S106: 'Пароль или секрет прямо в коде',
  S107: 'Пароль по умолчанию в аргументе функции',
  S201: 'Flask запущен с debug=True',
  S501: 'Отключена проверка TLS-сертификата',
  F821: 'Неопределённое имя',
  F841: 'Переменная присвоена, но не используется',
  F401: 'Импорт не используется',
};

const RUFF_MAP: Record<string, [FindingClass, Severity]> = {
  S608: ['security', 'critical'], S506: ['security', 'critical'], S301: ['security', 'high'], S602: ['security', 'critical'],
  S605: ['security', 'high'], S105: ['secrets', 'high'], S106: ['secrets', 'high'], S107: ['secrets', 'high'],
  S201: ['security', 'high'], S501: ['security', 'high'], F821: ['logic', 'high'], F841: ['quality', 'low'],
  F401: ['quality', 'low'], E9: ['logic', 'high'],
};

export function mapRuff(json: any[], repoDir: string, files: DiffFile[], disabled: string[]): Finding[] {
  const out: Finding[] = [];
  for (const r of json ?? []) {
    const code = String(r.code ?? 'E999');
    if (disabled.includes(`ruff:${code}`) || disabled.includes(code)) continue;
    const fn = String(r.filename);
    const path = (isAbsolute(fn) ? relative(repoDir, fn) : fn).replace(/\\/g, '/');
    const line = onChangedLines(files, path, r.location?.row ?? 0, r.end_location?.row ?? 0);
    if (!line) continue;
    const [cls, severity] = RUFF_MAP[code] ?? RUFF_MAP[code.slice(0, 2)] ??
      (code.startsWith('S') ? ['security', 'medium'] : code.startsWith('B') ? ['logic', 'medium'] : ['quality', 'low']);
    out.push({
      id: nextId(), path, line, cls, severity,
      title: RUFF_TITLE_RU[code] ?? String(r.message).slice(0, 140),
      explanation: `${r.message} (ruff ${code})${r.url ? `\n\nПравило: ${r.url}` : ''}`,
      sources: ['ruff'], ruleIds: [`ruff:${code}`],
    });
  }
  return out;
}

async function ruff(ctx: AnalyzerContext) {
  const py = ctx.files.filter((f) => f.status !== 'deleted' && f.path.endsWith('.py') && f.added.size > 0).map((f) => f.path);
  if (!py.length) return { findings: [], note: 'нет Python-файлов' };
  const r = await run('ruff', ['check', '--output-format', 'json', '--no-cache', '--exit-zero',
    '--select', ctx.config.analyzers.ruff.select.join(','), ...py], ctx.repoDir);
  if (r.missing) return { findings: [], status: 'skipped' as const, note: 'ruff не установлен' };
  return { findings: mapRuff(JSON.parse(r.stdout || '[]'), ctx.repoDir, ctx.files, ctx.config.disabledRules) };
}

// ---------- Gitleaks ----------
export function mapGitleaks(json: any[], files: DiffFile[]): Finding[] {
  const out: Finding[] = [];
  const seen = new Set<string>();
  for (const r of json ?? []) {
    const path = String(r.File).replace(/\\/g, '/');
    const f = files.find((x) => x.path === path);
    if (!f) continue;
    const line = f.added.has(r.StartLine) ? r.StartLine : [...f.added].find((l) => Math.abs(l - r.StartLine) <= 3);
    const key = `${path}:${r.RuleID}:${line ?? r.StartLine}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({
      id: nextId(), path, line: line ?? r.StartLine, cls: 'secrets', severity: 'critical',
      title: `Секрет в коде (${r.RuleID})`,
      explanation: `Gitleaks (правило \`${r.RuleID}\`) нашёл значение, похожее на секрет. Значение в отчёте скрыто. ` +
        'Уберите его из кода, перенесите в секреты CI или переменные окружения и отзовите ключ: он уже попал в историю git.',
      sources: ['gitleaks'], ruleIds: [`gitleaks:${r.RuleID}`], summaryOnly: line === undefined,
    });
  }
  return out;
}

async function gitleaks(ctx: AnalyzerContext) {
  const dir = mkdtempSync(join(tmpdir(), 'gl-'));
  const report = join(dir, 'gitleaks.json');
  try {
    const r = await run('gitleaks', ['git', `--log-opts=${ctx.base}..${ctx.head}`, '--report-format', 'json', '--report-path', report,
      '--redact', '--no-banner', '--exit-code', '0', '.'], ctx.repoDir);
    if (r.missing) return { findings: [], status: 'skipped' as const, note: 'gitleaks не установлен' };
    const json = JSON.parse(readFileSync(report, 'utf8') || '[]');
    return { findings: mapGitleaks(json, ctx.files) };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

// ---------- OSV: зависимости, добавленные в PR ----------
export interface DepRef { ecosystem: 'PyPI' | 'npm'; name: string; version: string; path: string; line: number; text: string }

export function extractDeps(files: DiffFile[]): DepRef[] {
  const deps: DepRef[] = [];
  for (const f of files) {
    const isReq = /(^|\/)requirements[^/]*\.txt$/.test(f.path);
    const isPkg = /(^|\/)package\.json$/.test(f.path);
    if (!isReq && !isPkg) continue;
    for (const h of f.hunks) for (const l of h.lines) {
      if (l.kind !== '+' || !l.newLine) continue;
      if (isReq) {
        const m = /^\s*([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?\s*==\s*([^\s;#]+)/.exec(l.text);
        if (m) deps.push({ ecosystem: 'PyPI', name: m[1], version: m[2], path: f.path, line: l.newLine, text: l.text });
      } else {
        const m = /^\s*"(@?[^"\s]+)"\s*:\s*"[\^~=]?(\d+\.\d+\.\d+[^"]*)"/.exec(l.text);
        if (m && !['version', 'node', 'npm'].includes(m[1])) deps.push({ ecosystem: 'npm', name: m[1], version: m[2], path: f.path, line: l.newLine, text: l.text });
      }
    }
  }
  return deps;
}

function cmpVer(a: string, b: string): number {
  const pa = a.split(/[.\-+]/).map((x) => parseInt(x, 10) || 0);
  const pb = b.split(/[.\-+]/).map((x) => parseInt(x, 10) || 0);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (d) return d;
  }
  return 0;
}

const OSV_SEV: Record<string, Severity> = { CRITICAL: 'critical', HIGH: 'high', MODERATE: 'medium', MEDIUM: 'medium', LOW: 'low' };

async function osv(ctx: AnalyzerContext) {
  const deps = extractDeps(ctx.files);
  if (!deps.length) return { findings: [], note: 'зависимости не менялись' };
  const res = await fetch('https://api.osv.dev/v1/querybatch', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ queries: deps.map((d) => ({ package: { name: d.name, ecosystem: d.ecosystem }, version: d.version })) }),
  });
  if (!res.ok) throw new Error(`OSV ${res.status}`);
  const batch: any = await res.json();
  const out: Finding[] = [];
  for (let i = 0; i < deps.length; i++) {
    const vulns: any[] = batch.results?.[i]?.vulns ?? [];
    if (!vulns.length) continue;
    const d = deps[i];
    let worst: Severity = 'low';
    let fixed: string | undefined;
    const lines: string[] = [];
    for (const v of vulns.slice(0, 6)) {
      const det: any = await (await fetch(`https://api.osv.dev/v1/vulns/${encodeURIComponent(v.id)}`)).json();
      const sev = OSV_SEV[String(det.database_specific?.severity ?? '').toUpperCase()] ?? 'medium';
      if (SEV_RANK[sev] > SEV_RANK[worst]) worst = sev;
      const cve = (det.aliases ?? []).find((a: string) => a.startsWith('CVE-'));
      lines.push(`- ${det.id}${cve ? ` (${cve})` : ''}: ${det.summary ?? 'см. описание'}`);
      for (const a of det.affected ?? []) {
        if (String(a.package?.name).toLowerCase() !== d.name.toLowerCase()) continue;
        for (const r of a.ranges ?? []) for (const e of r.events ?? []) {
          if (e.fixed && cmpVer(e.fixed, d.version) > 0 && (!fixed || cmpVer(e.fixed, fixed) > 0)) fixed = e.fixed;
        }
      }
    }
    out.push({
      id: nextId(), path: d.path, line: d.line, cls: 'security', severity: worst,
      title: `Уязвимая зависимость ${d.name} ${d.version}: ${vulns.length} уязв. в OSV`,
      explanation: `Версия \`${d.name}==${d.version}\` есть в базе OSV:\n${lines.join('\n')}` +
        (vulns.length > 6 ? `\n- …и ещё ${vulns.length - 6}` : '') + (fixed ? `\n\nИсправлено в версии ${fixed}.` : ''),
      suggestion: fixed ? d.text.replace(d.version, fixed) : undefined,
      sources: ['osv'], ruleIds: vulns.slice(0, 3).map((v) => `osv:${v.id}`),
    });
  }
  return { findings: out, note: `${deps.length} зависимостей проверено` };
}
const SEV_RANK: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1 };

// ---------- Тесты ----------
const SKIP_RE = /(@pytest\.mark\.skip|pytest\.skip\(|\b(it|test|describe)\.skip\(|\bx(it|describe)\(|@Disabled\b|@Ignore\b|unittest\.skip)/;
const TEST_DEF_RE = /^\s*(def test_\w+|(it|test)(\.(skip|only|todo))?\(\s*['"`]|@Test\b)/;

export function testsHeuristics(files: DiffFile[], minChanged: number): Finding[] {
  const out: Finding[] = [];
  const testsTouched = files.some((f) => isTestPath(f.path) && f.status !== 'deleted' && f.added.size > 0);
  const src = files.filter((f) => isCodePath(f.path) && !isTestPath(f.path) && f.status !== 'deleted');
  const total = src.reduce((s, f) => s + f.added.size, 0);
  if (!testsTouched && total >= minChanged && src.length) {
    const main = [...src].sort((a, b) => b.added.size - a.added.size)[0];
    out.push({
      id: nextId(), path: main.path, line: Math.min(...main.added), cls: 'tests', severity: 'medium',
      title: 'Логика изменена без тестов',
      explanation: `В PR добавлено ${total} строк кода в ${src.length} файл(ах), но ни один тест не добавлен и не изменён. ` +
        'Добавьте тесты на новое поведение, хотя бы на основной сценарий и граничный случай.',
      sources: ['tests'], ruleIds: ['tests:no-tests'],
    });
  }
  for (const f of files) {
    if (!isTestPath(f.path)) continue;
    for (const h of f.hunks) for (const l of h.lines) {
      if (l.kind === '+' && l.newLine && SKIP_RE.test(l.text)) {
        out.push({
          id: nextId(), path: f.path, line: l.newLine, cls: 'tests', severity: 'medium',
          title: 'Тест отключён', explanation: 'Тест помечен как пропускаемый. Если он падает, нужно чинить код или тест, а не выключать проверку. Если отключение временное, оставьте ссылку на задачу.',
          sources: ['tests'], ruleIds: ['tests:skipped'],
        });
      }
    }
    const removedDefs = f.removed.filter((l) => TEST_DEF_RE.test(l.text));
    const addedDefs = f.hunks.flatMap((h) => h.lines).filter((l) => l.kind === '+' && TEST_DEF_RE.test(l.text));
    if (removedDefs.length > addedDefs.length) {
      out.push({
        id: nextId(), path: f.path, line: Math.min(...(f.commentable.size ? f.commentable : new Set([1]))), cls: 'tests', severity: 'medium',
        title: `Удалено тестов: ${removedDefs.length - addedDefs.length}`,
        explanation: `Из ${f.path} удалены тесты: ${removedDefs.map((l) => '`' + l.text.trim() + '`').join(', ')}.`,
        sources: ['tests'], ruleIds: ['tests:removed'], summaryOnly: f.status === 'deleted',
      });
    }
  }
  return out;
}

export async function runAnalyzers(ctx: AnalyzerContext): Promise<{ findings: Finding[]; runs: AnalyzerRun[] }> {
  const a = ctx.config.analyzers;
  const jobs: Promise<{ findings: Finding[]; run: AnalyzerRun }>[] = [];
  if (a.semgrep.enabled) jobs.push(timed('semgrep', () => semgrep(ctx)));
  if (a.ruff.enabled) jobs.push(timed('ruff', () => ruff(ctx)));
  if (a.gitleaks.enabled) jobs.push(timed('gitleaks', () => gitleaks(ctx)));
  if (a.osv.enabled) jobs.push(timed('osv', () => osv(ctx)));
  if (a.tests.enabled) jobs.push(timed('tests', async () => ({ findings: testsHeuristics(ctx.files, a.tests.minChangedLines) })));
  const results = await Promise.all(jobs);
  return { findings: results.flatMap((r) => r.findings), runs: results.map((r) => r.run) };
}
