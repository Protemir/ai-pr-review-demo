import { readFileSync } from 'node:fs';
import type { Config } from './config.ts';
import type { DiffFile } from './diff.ts';
import type { Finding, LlmRawFinding, LlmRun } from './types.ts';

export const SYSTEM_PROMPT = `Ты — старший инженер и делаешь код-ревью pull request.
Ищи только реальные проблемы в ДОБАВЛЕННЫХ строках (в листинге они помечены «+»):
- logic: неверные условия, null/None, граничные случаи, off-by-one, коллекции, даты и часовые пояса;
- security: внедрение SQL и команд, XSS, небезопасная десериализация, ошибки авторизации, SSRF, path traversal;
- secrets: ключи, пароли, токены в коде, небезопасные настройки;
- quality: дублирование, лишняя сложность, производительность (N+1, лишние циклы);
- tests: изменение логики без тестов, удалённые или отключённые тесты.
Правила:
1. Не пиши о форматировании, именовании и вкусовщине. Если не уверен, промолчи. Лучше 3 точных замечания, чем 10 сомнительных.
2. line — номер строки из листинга (новая версия файла); end_line — последняя строка, если замечание о нескольких строках.
3. suggestion — готовый код, который ЦЕЛИКОМ заменит строки line..end_line, с теми же отступами и без пояснений. Если исправление не помещается в эти строки, оставь suggestion пустой строкой.
4. severity: critical — эксплуатируемая уязвимость, утечка секрета, потеря данных; high — ошибка, которая точно сломает поведение; medium — вероятная ошибка или риск; low — улучшение.
5. confidence — твоя уверенность от 0 до 1.
6. Ниже есть список замечаний статических анализаторов (id вида S1). Не дублируй их отдельными замечаниями. Если можешь дать к ним исправление или точнее объяснить, верни объект с related_static_id и теми же path/line.
7. Объяснения пиши по-русски, коротко: что не так и чем грозит.
Ответ — строго JSON без markdown:
{"findings":[{"path":"...","line":12,"end_line":12,"class":"logic|security|secrets|quality|tests","severity":"critical|high|medium|low","title":"...","explanation":"...","suggestion":"...","confidence":0.9,"related_static_id":""}]}
Если проблем нет: {"findings":[]}`;

const estTokens = (s: string) => Math.ceil(s.length / 3.2);

/** Листинг файла: окна вокруг ханков, номера строк новой версии, «+» у добавленных строк. */
export function renderFile(f: DiffFile, content: string[], context = 12): string {
  const head = `### ${f.path}${f.status === 'added' ? ' (новый файл)' : ''}`;
  const show = new Set<number>();
  if (f.status === 'added' || content.length <= 220) for (let i = 1; i <= content.length; i++) show.add(i);
  else for (const h of f.hunks) {
    const nums = h.lines.filter((l) => l.newLine).map((l) => l.newLine as number);
    if (!nums.length) continue;
    for (let i = Math.max(1, Math.min(...nums) - context); i <= Math.min(content.length, Math.max(...nums) + context); i++) show.add(i);
  }
  const out = [head];
  let prev = 0;
  for (const i of [...show].sort((a, b) => a - b)) {
    if (i > prev + 1 && prev) out.push('     …');
    const t = content[i - 1] ?? '';
    if (i === content.length && t === '') continue;
    out.push(`${String(i).padStart(5)} ${f.added.has(i) ? '+' : ' '} ${t}`);
    prev = i;
  }
  const removed = f.removed.length ? `\n(удалено строк: ${f.removed.length}; примеры: ${f.removed.slice(0, 5).map((l) => JSON.stringify(l.text.trim())).join(', ')})` : '';
  return out.join('\n') + removed;
}

export function buildChunks(files: { file: DiffFile; content: string[] }[], statics: Finding[], meta: string, maxTokens: number): string[] {
  const parts = files.map(({ file, content }) => {
    const st = statics.filter((s) => s.path === file.path);
    const stText = st.length ? '\nЗамечания анализаторов к этому файлу:\n' + st.map((s) => `[${s.id}] строка ${s.line}, ${s.cls}/${s.severity}: ${s.title}`).join('\n') : '';
    return renderFile(file, content) + stText;
  });
  const chunks: string[] = [];
  let cur = '';
  for (const p of parts) {
    if (cur && estTokens(cur + p) > maxTokens) {
      chunks.push(cur);
      cur = '';
    }
    cur += (cur ? '\n\n' : '') + p;
  }
  if (cur) chunks.push(cur);
  return chunks.map((c) => `${meta}\n\n${c}`);
}

export function parseLlmJson(text: string): LlmRawFinding[] {
  const s = text.trim().replace(/^```(?:json)?\s*/i, '').replace(/```\s*$/, '');
  const start = s.indexOf('{');
  const end = s.lastIndexOf('}');
  if (start < 0 || end < 0) return [];
  const obj = JSON.parse(s.slice(start, end + 1));
  const arr = Array.isArray(obj) ? obj : obj.findings;
  return Array.isArray(arr) ? arr.filter((x) => x && typeof x === 'object') : [];
}

async function chat(cfg: Config['llm'], user: string, env: NodeJS.ProcessEnv) {
  const key = env[cfg.apiKeyEnv] ?? '';
  const body: Record<string, unknown> = {
    model: cfg.model,
    temperature: cfg.temperature,
    max_tokens: cfg.maxOutputTokens,
    messages: [
      { role: 'system', content: SYSTEM_PROMPT + (cfg.extraInstructions ? `\n${cfg.extraInstructions}` : '') },
      { role: 'user', content: user },
    ],
    response_format: { type: 'json_object' },
  };
  for (let attempt = 0; attempt < 4; attempt++) {
    const res = await fetch(`${cfg.baseUrl.replace(/\/$/, '')}/chat/completions`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', ...(key ? { authorization: `Bearer ${key}` } : {}) },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(170_000),
    });
    if (res.status === 429 || res.status >= 500) {
      const wait = Math.min(60, Number(res.headers.get('retry-after')) || 5 * 2 ** attempt);
      await new Promise((r) => setTimeout(r, wait * 1000));
      continue;
    }
    if (!res.ok) throw new Error(`LLM HTTP ${res.status}: ${(await res.text()).slice(0, 300)}`);
    const j: any = await res.json();
    return {
      text: String(j.choices?.[0]?.message?.content ?? ''),
      promptTokens: Number(j.usage?.prompt_tokens ?? estTokens(user)),
      completionTokens: Number(j.usage?.completion_tokens ?? 0),
    };
  }
  throw new Error('LLM: превышено число повторов (429/5xx)');
}

export async function runLlm(
  cfg: Config['llm'],
  files: { file: DiffFile; content: string[] }[],
  statics: Finding[],
  meta: string,
  env: NodeJS.ProcessEnv = process.env,
): Promise<LlmRun> {
  const t0 = Date.now();
  const r: LlmRun = { provider: cfg.provider, model: cfg.model, calls: 0, promptTokens: 0, completionTokens: 0, costUsd: 0, ms: 0, raw: [] };
  if (cfg.provider === 'none' || !files.length) return r;
  try {
    if (cfg.provider === 'mock') {
      // Записанный ответ модели: для локальной отладки и автотестов без сети.
      r.raw = parseLlmJson(readFileSync(cfg.mockFile ?? 'fixtures/llm-response.json', 'utf8'));
      r.calls = 1;
    } else {
      const chunks = buildChunks(files, statics, meta, cfg.maxInputTokensPerCall);
      for (const c of chunks) {
        const res = await chat(cfg, c, env);
        r.calls++;
        r.promptTokens += res.promptTokens;
        r.completionTokens += res.completionTokens;
        try {
          r.raw.push(...parseLlmJson(res.text));
        } catch (e) {
          r.error = `не удалось разобрать JSON ответа: ${(e as Error).message}`;
        }
      }
    }
  } catch (e) {
    r.error = String((e as Error).message ?? e).slice(0, 300);
  }
  r.costUsd = (r.promptTokens * cfg.pricePer1MInput + r.completionTokens * cfg.pricePer1MOutput) / 1e6;
  r.ms = Date.now() - t0;
  return r;
}
