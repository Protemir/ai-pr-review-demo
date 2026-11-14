import { createHash } from 'node:crypto';
import type { Config } from './config.ts';
import { snapToAdded, type DiffFile } from './diff.ts';
import { CLASSES, SEVERITIES, SEVERITY_ORDER, type Finding, type FindingClass, type LlmRawFinding, type Severity } from './types.ts';

export interface MergeStats {
  llmAccepted: number;
  llmEnriched: number;
  llmDroppedLine: number;
  llmDroppedConfidence: number;
  llmDowngraded: number;
  deduplicated: number;
}

const maxSev = (a: Severity, b: Severity): Severity => (SEVERITY_ORDER[a] >= SEVERITY_ORDER[b] ? a : b);
const group = (c: FindingClass) => (c === 'secrets' ? 'security' : c);

export function fingerprint(f: Finding, lineText: string): string {
  return createHash('sha1').update(`${f.path}|${group(f.cls)}|${lineText.trim().replace(/\s+/g, ' ')}`).digest('hex').slice(0, 12);
}

const SECURITY_WORDS = /\bXSS\b|инъекц|injection|prototype pollution|десериализ|deserializ|авторизац|authoriz|доступ к чуж/i;
const normTitle = (t: string) => t.toLowerCase().replace(/[^a-zа-яё0-9]+/g, ' ').trim();

/** Заглушки вместо кода («...», «…», «{ ... }») — такое исправление нельзя применить. */
export function isPlaceholder(s: string): boolean {
  return /…/.test(s) || /\{\s*\.\.\.\s*\}/.test(s) || /\.\.\.\s*(<|`|'|"|\)|\]|;|$)/m.test(s) || /^\s*\.\.\./m.test(s);
}

/** «Используйте параметризованный запрос.» — совет, а не код; в suggestion такое не кладём. */
export function looksLikeCode(s: string): boolean {
  const t = s.trim();
  if (!t) return false;
  const prose = /^[А-ЯЁA-Z][а-яёa-z]+\s+[а-яёa-z]/.test(t) && /[а-яё]{3,}/i.test(t);
  return !prose && /[=(){}\[\];:<>"'`]/.test(t);
}

/** Модель часто теряет отступ: выравниваем исправление по первой заменяемой строке. */
export function fitIndent(suggestion: string, original: string): string {
  const want = /^\s*/.exec(original)?.[0] ?? '';
  const lines = suggestion.replace(/\r/g, '').replace(/\n+$/, '').split('\n');
  const have = /^\s*/.exec(lines[0])?.[0] ?? '';
  if (have === want) return lines.join('\n');
  return lines.map((l) => (l.startsWith(have) ? want + l.slice(have.length) : want + l.trimStart())).join('\n');
}

export function mergeFindings(
  statics: Finding[],
  raw: LlmRawFinding[],
  files: DiffFile[],
  cfg: Config,
  modelName: string,
): { findings: Finding[]; stats: MergeStats } {
  const stats: MergeStats = { llmAccepted: 0, llmEnriched: 0, llmDroppedLine: 0, llmDroppedConfidence: 0, llmDowngraded: 0, deduplicated: 0 };
  const all: Finding[] = statics.map((s) => ({ ...s }));
  const byId = new Map(all.map((s) => [s.id, s]));
  let n = 0;
  for (const r0 of raw) {
    // Модели пишут «secrets/critical», «Security» и т. п. — нормализуем.
    const r = {
      ...r0,
      class: r0.class ? String(r0.class).toLowerCase().split(/[\/|,\s]/)[0] : undefined,
      severity: r0.severity ? String(r0.severity).toLowerCase().split(/[\/|,\s]/)[0] : undefined,
      suggestion: r0.suggestion && looksLikeCode(r0.suggestion) ? r0.suggestion : undefined,
    };
    const conf = typeof r.confidence === 'number' ? r.confidence : 0.7;
    let related = r.related_static_id ? byId.get(r.related_static_id) : undefined;
    // Маленькие модели путают id: принимаем уточнение, только если строка и класс сходятся.
    if (related && ((r.line && Math.abs(r.line - related.line) > 3) ||
      (r.class && CLASSES.includes(r.class as FindingClass) && group(r.class as FindingClass) !== group(related.cls)) ||
      (r.path && r.path !== related.path))) related = undefined;
    const file = files.find((f) => f.path === (r.path ?? related?.path));
    if (r.related_static_id && !related && !r.title) {
      stats.llmDroppedLine++;
      continue;
    }
    if (related) {
      // LLM уточняет замечание анализатора: добавляем объяснение и исправление.
      if (r.title && /[а-яё]/i.test(r.title)) related.title = r.title.slice(0, 140);
      if (r.explanation) related.explanation = `${r.explanation}\n\n_Анализатор: ${related.explanation.split('\n')[0]}_`;
      if (r.suggestion && !isPlaceholder(r.suggestion) && !related.suggestion && file && r.line && Math.abs(r.line - related.line) <= 3) {
        related.origLine ??= related.line;
        related.line = r.line;
        related.endLine = r.end_line && r.end_line >= r.line ? r.end_line : undefined;
        related.suggestion = r.suggestion;
      }
      if (r.severity && SEVERITIES.includes(r.severity as Severity) && conf >= cfg.llm.minConfidence) {
        related.severity = maxSev(related.severity, r.severity as Severity);
      }
      related.sources.push(`llm:${modelName}`);
      stats.llmEnriched++;
      continue;
    }
    if (!file || !r.line) {
      stats.llmDroppedLine++;
      continue;
    }
    if (conf < cfg.llm.minConfidence) {
      stats.llmDroppedConfidence++;
      continue;
    }
    const line = snapToAdded(file, Math.round(r.line), 3);
    if (!line) {
      stats.llmDroppedLine++;
      continue;
    }
    let severity: Severity = SEVERITIES.includes(r.severity as Severity) ? (r.severity as Severity) : 'medium';
    if (SEVERITY_ORDER[severity] < SEVERITY_ORDER[cfg.llm.minSeverity ?? 'low']) {
      stats.llmDroppedConfidence++;
      continue;
    }
    if (severity === 'critical' && conf < cfg.llm.criticalMinConfidence) {
      severity = 'high';
      stats.llmDowngraded++;
    }
    let cls: FindingClass = CLASSES.includes(r.class as FindingClass) ? (r.class as FindingClass) : 'logic';
    if (cls !== 'security' && SECURITY_WORDS.test(`${r.title} ${r.explanation}`)) cls = 'security';
    const title = String(r.title ?? 'Замечание').slice(0, 140);
    // Маленькая модель повторяет одно замечание на соседних строках — оставляем первое.
    const repeat = all.find((o) => o.id.startsWith('L') && o.path === file.path && normTitle(o.title) === normTitle(title) && Math.abs(o.line - line) <= 15);
    if (repeat) {
      stats.deduplicated++;
      continue;
    }
    // Если строку пришлось сдвинуть, исправление уже не ложится на нужные строки — не публикуем его.
    const exact = line === Math.round(r.line);
    let endLine = exact && r.end_line && r.end_line > line ? Math.round(r.end_line) : undefined;
    if (endLine && [...Array(endLine - line + 1).keys()].some((k) => !file.commentable.has(line + k))) endLine = undefined;
    const multiLineSuggestion = (r.suggestion ?? '').split('\n').length > 1;
    const rangeOk = endLine || !r.end_line || r.end_line <= r.line || !multiLineSuggestion;
    const suggestion = exact && r.suggestion && rangeOk && !isPlaceholder(r.suggestion) ? r.suggestion : undefined;
    all.push({
      id: `L${++n}`, path: file.path, line, endLine: endLine && endLine > line ? endLine : undefined, cls, severity,
      title, explanation: String(r.explanation ?? ''),
      suggestion: suggestion || undefined, sources: [`llm:${modelName}`], ruleIds: [], confidence: conf,
    });
    stats.llmAccepted++;
  }

  // Дедупликация: та же строка и группа класса — одно замечание. Соседние строки (±2) склеиваем,
  // если замечания пришли из разных источников (Ruff и Semgrep про один SQL, LLM повторил анализатор);
  // два замечания одного источника на соседних строках — обычно разные проблемы.
  const tool = (x: Finding) => x.sources[0].split(':')[0];
  const ranges = (x: Finding) => [x.line, x.endLine ?? x.line, x.origLine ?? x.line];
  const near = (a: Finding, b: Finding) => ranges(a).some((la) => ranges(b).some((lb) => Math.abs(la - lb) <= 2));
  const out: Finding[] = [];
  for (const f of all.sort((a, b) => SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity])) {
    const dup = out.find((o) => o.path === f.path && group(o.cls) === group(f.cls) &&
      (o.line === f.line || (near(o, f) && tool(o) !== tool(f))));
    if (!dup) {
      out.push(f);
      continue;
    }
    stats.deduplicated++;
    dup.sources = [...new Set([...dup.sources, ...f.sources])];
    dup.ruleIds = [...new Set([...dup.ruleIds, ...f.ruleIds])];
    if (!dup.suggestion && f.suggestion) {
      // Исправление привязано к своим строкам — переносим якорь вместе с ним.
      dup.suggestion = f.suggestion;
      dup.origLine ??= dup.line;
      dup.line = f.line;
      dup.endLine = f.endLine;
    }
    if (f.explanation.length > dup.explanation.length && f.sources.some((s) => s.startsWith('llm'))) dup.explanation = f.explanation;
  }

  const minRank = SEVERITY_ORDER[cfg.minSeverity];
  const filtered = out.filter((f) => SEVERITY_ORDER[f.severity] >= minRank && !f.ruleIds.some((r) => cfg.disabledRules.includes(r)));
  filtered.sort((a, b) => SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity] || a.path.localeCompare(b.path) || a.line - b.line);
  return { findings: filtered, stats };
}
