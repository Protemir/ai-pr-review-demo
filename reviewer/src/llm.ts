import { readFileSync } from 'node:fs';
import type { Config } from './config.ts';
import type { DiffFile } from './diff.ts';
import type { Finding, LlmRawFinding, LlmRun } from './types.ts';

export const SYSTEM_PROMPT = `Ты — старший инженер, делаешь код-ревью pull request. Пиши только по-русски.
Шаблонные уязвимости (SQL-инъекции, секреты, yaml.load, уязвимые версии библиотек) уже нашли статические анализаторы — их список дан в конце листинга.
Твоя задача — реальные ошибки, которые анализаторы НЕ видят, в строках с «+»:
- None/null/undefined: запись не найдена, пользователь не авторизован;
- права доступа: перевёрнутое условие (and/or, ==/!=, not), доступ к чужим данным;
- границы: off-by-one в страницах и индексах, floor/ceil;
- даты: месяцы с нуля в JS, часовые пояса;
- вывод пользовательских данных в HTML без экранирования (XSS), слияние объектов из URL (prototype pollution).
Точность важнее полноты. Сообщай только об ошибке, для которой можешь назвать конкретный вход или сценарий, ломающий код, — назови его в explanation.
Нет такого сценария — не пиши. Не пиши о стиле, именовании, «отсутствии проверок» без последствий. Корректный код — пустой findings.

Формат ответа — строго JSON без markdown:
{"findings":[{"path":"файл","line":12,"end_line":12,"class":"logic|security|secrets|quality|tests","severity":"critical|high|medium|low","title":"коротко по-русски","explanation":"что не так и чем грозит, по-русски","suggestion":"код","confidence":0.9}],
 "fixes":[{"static_id":"S3","line":57,"suggestion":"код","explanation":"по-русски"}]}
- findings — только НОВЫЕ проблемы, которых нет в списке анализаторов.
- fixes — исправления к замечаниям анализаторов (по их id), если можешь их дать.
- line — номер строки из листинга; end_line — последняя строка, если замечание о нескольких строках.
- suggestion — готовый код, который целиком заменит строки line..end_line, с теми же отступами; без пояснений. Нельзя исправить в этих строках — "".
- severity: critical — эксплуатируемая уязвимость или потеря данных; high — точно сломает поведение; medium — вероятная ошибка; low — улучшение.
Если проблем нет: {"findings":[],"fixes":[]}`;

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
  return chunks.map((c) => {
    const fns = newFunctions(c);
    const fnLine = fns.length ? `\n\nНовые функции: ${fns.join(', ')}.` : '';
    return `${meta}\n\n${c}${fnLine}\n\nОтветь JSON. findings — не больше 6, fixes — только к критичным и высоким замечаниям анализаторов, не больше 3. ` +
      'Одна проблема — одно замечание. explanation — до 200 символов. Все тексты на русском.';
  });
}

/** Имена функций, объявленных в добавленных строках листинга (Python, TS/JS, Java). */
export function newFunctions(listing: string): string[] {
  const names = new Set<string>();
  for (const line of listing.split('\n')) {
    if (!/^\s*\d+ \+ /.test(line)) continue;
    const code = line.replace(/^\s*\d+ \+ /, '');
    const m = /^\s*(?:async\s+)?def\s+(\w+)/.exec(code) ??
      /^\s*(?:export\s+)?(?:async\s+)?function\s+(\w+)/.exec(code) ??
      /^\s*(?:export\s+)?const\s+(\w+)\s*=\s*(?:async\s*)?\(/.exec(code) ??
      /^\s*(?:public|private|protected)\s+[\w<>\[\], ]+\s+(\w+)\s*\(/.exec(code);
    if (m && !m[1].startsWith('test')) names.add(m[1]);
  }
  return [...names].slice(0, 20);
}

export function parseLlmJson(text: string): LlmRawFinding[] {
  const s = text.trim().replace(/^```(?:json)?\s*/i, '').replace(/```\s*$/, '');
  const start = s.indexOf('{');
  const end = s.lastIndexOf('}');
  if (start < 0 || end < 0) return [];
  const obj = JSON.parse(s.slice(start, end + 1));
  const arr = Array.isArray(obj) ? obj : obj.findings;
  const out: LlmRawFinding[] = Array.isArray(arr) ? arr.filter((x) => x && typeof x === 'object') : [];
  for (const f of Array.isArray(obj.fixes) ? obj.fixes : []) {
    if (f && typeof f === 'object' && f.static_id) {
      out.push({ related_static_id: String(f.static_id), line: f.line, end_line: f.end_line, suggestion: f.suggestion, explanation: f.explanation, title: f.title });
    }
  }
  return out;
}

export async function readSse(res: Response, user: string) {
  const decoder = new TextDecoder();
  let buf = '';
  let text = '';
  let promptTokens = 0;
  let completionTokens = 0;
  const handle = (line: string) => {
    const l = line.trim();
    if (!l.startsWith('data:')) return;
    const data = l.slice(5).trim();
    if (!data || data === '[DONE]') return;
    const j = JSON.parse(data);
    text += j.choices?.[0]?.delta?.content ?? '';
    if (j.usage) {
      promptTokens = Number(j.usage.prompt_tokens ?? 0);
      completionTokens = Number(j.usage.completion_tokens ?? 0);
    }
  };
  for await (const chunk of res.body as unknown as AsyncIterable<Uint8Array>) {
    buf += decoder.decode(chunk, { stream: true });
    let i;
    while ((i = buf.indexOf('\n')) >= 0) {
      handle(buf.slice(0, i));
      buf = buf.slice(i + 1);
    }
  }
  handle(buf);
  return { text, promptTokens: promptTokens || estTokens(user), completionTokens: completionTokens || estTokens(text) };
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
    // Потоковый ответ: медленная локальная модель не упирается в тайм-аут ожидания заголовков (300 с в Node).
    stream: true,
    stream_options: { include_usage: true },
  };
  for (let attempt = 0; attempt < 4; attempt++) {
    const res = await fetch(`${cfg.baseUrl.replace(/\/$/, '')}/chat/completions`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', ...(key ? { authorization: `Bearer ${key}` } : {}) },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout((cfg.timeoutSec ?? 300) * 1000),
    });
    if (res.status === 429 || res.status >= 500) {
      const wait = Math.min(60, Number(res.headers.get('retry-after')) || 5 * 2 ** attempt);
      await new Promise((r) => setTimeout(r, wait * 1000));
      continue;
    }
    if (!res.ok) throw new Error(`LLM HTTP ${res.status}: ${(await res.text()).slice(0, 300)}`);
    if (!String(res.headers.get('content-type')).includes('event-stream')) {
      const j: any = await res.json();
      return {
        text: String(j.choices?.[0]?.message?.content ?? ''),
        promptTokens: Number(j.usage?.prompt_tokens ?? estTokens(user)),
        completionTokens: Number(j.usage?.completion_tokens ?? 0),
      };
    }
    return readSse(res, user);
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
          (r.rawText ??= []).push(res.text.slice(0, 6000));
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
