import { CLASS_LABEL, SEVERITY_LABEL, type Finding } from './types.ts';

export const FP_MARK = /<!-- ai-review:fp=([0-9a-f]+)(?:;g=([a-z]+))? -->/;

export interface PublishedComment { fp: string; path: string; line: number; group?: string; title?: string; falsePositive: boolean }

const KEY = /xss|sql|yaml|json|prototype|csrf|ssrf|секрет|ключ|парол|токен|десериализ|авторизац|прав доступа|null|none|undefined|пагинац|страниц|дат|тест/gi;
const keys = (t = '') => new Set((t.toLowerCase().match(KEY) ?? []));
const shareKey = (a?: string, b?: string) => [...keys(a)].some((k) => keys(b).has(k));

/** Уже есть такое замечание: тот же отпечаток или тот же файл и группа класса в пределах ±3 строк. */
export function alreadyThere(f: Finding, list: PublishedComment[], onlyFalse = false): boolean {
  const g = f.cls === 'secrets' ? 'security' : f.cls;
  return list.some((c) => (!onlyFalse || c.falsePositive) &&
    (c.fp === f.fingerprint || (c.path === f.path && c.group === g &&
      (Math.abs(c.line - f.line) <= 3 || (Math.abs(c.line - f.line) <= 12 && shareKey(c.title, f.title))))));
}
export const SUMMARY_MARK = '<!-- ai-review:summary -->';

export class GitHub {
  api: string;
  token: string;
  repo: string;
  constructor(repo: string, token: string, api = process.env.GITHUB_API_URL ?? 'https://api.github.com') {
    this.repo = repo;
    this.token = token;
    this.api = api;
  }

  async req(method: string, path: string, body?: unknown): Promise<any> {
    const res = await fetch(`${this.api}${path.startsWith('/repos') ? '' : `/repos/${this.repo}`}${path}`, {
      method,
      headers: {
        authorization: `Bearer ${this.token}`,
        accept: 'application/vnd.github+json',
        'x-github-api-version': '2022-11-28',
        'content-type': 'application/json',
        'user-agent': 'ai-pr-review-demo',
      },
      body: body ? JSON.stringify(body) : undefined,
    });
    if (!res.ok) {
      const err = new Error(`GitHub ${method} ${path}: ${res.status} ${(await res.text()).slice(0, 300)}`) as Error & { status: number };
      err.status = res.status;
      throw err;
    }
    return res.status === 204 ? null : res.json();
  }

  async paginate(path: string): Promise<any[]> {
    const out: any[] = [];
    for (let page = 1; page < 20; page++) {
      const sep = path.includes('?') ? '&' : '?';
      const items = await this.req('GET', `${path}${sep}per_page=100&page=${page}`);
      out.push(...items);
      if (items.length < 100) break;
    }
    return out;
  }

  async pr(n: number) {
    return this.req('GET', `/pulls/${n}`);
  }

  /** Уже опубликованные замечания и те, что люди отметили 👎 как ложные. */
  async existing(n: number): Promise<PublishedComment[]> {
    const out: PublishedComment[] = [];
    for (const c of await this.paginate(`/pulls/${n}/comments`)) {
      const m = FP_MARK.exec(c.body ?? '');
      if (!m) continue;
      // Старые комментарии без g=: группа по подписи класса в первой строке.
      const label = Object.entries(CLASS_LABEL).find(([, l]) => String(c.body).split('\n')[0].includes(`· ${l}`))?.[0];
      const group = m[2] ?? (label === 'secrets' ? 'security' : label);
      const title = String(c.body).split('\n')[0].split(' — ').slice(1).join(' — ');
      out.push({ fp: m[1], group, title, path: c.path, line: c.line ?? c.original_line ?? 0, falsePositive: (c.reactions?.['-1'] ?? 0) > 0 });
    }
    return out;
  }

  async postReview(n: number, commitId: string, comments: { path: string; line: number; start_line?: number; body: string }[]) {
    if (!comments.length) return { posted: 0, failed: 0 };
    const toApi = (c: (typeof comments)[number]) => ({
      path: c.path, line: c.line, side: 'RIGHT',
      ...(c.start_line ? { start_line: c.start_line, start_side: 'RIGHT' } : {}),
      body: c.body,
    });
    try {
      await this.req('POST', `/pulls/${n}/reviews`, { commit_id: commitId, event: 'COMMENT', comments: comments.map(toApi) });
      return { posted: comments.length, failed: 0 };
    } catch (e) {
      if ((e as { status?: number }).status !== 422) throw e;
      // Одна неверная строка роняет весь review — публикуем по одному и пропускаем сбойные.
      let posted = 0;
      let failed = 0;
      for (const c of comments) {
        try {
          await this.req('POST', `/pulls/${n}/comments`, { commit_id: commitId, ...toApi(c) });
          posted++;
        } catch {
          failed++;
        }
      }
      return { posted, failed };
    }
  }

  async upsertSummary(n: number, body: string) {
    const comments = await this.paginate(`/issues/${n}/comments`);
    const mine = comments.find((c) => String(c.body ?? '').includes(SUMMARY_MARK));
    if (mine) await this.req('PATCH', `/issues/comments/${mine.id}`, { body });
    else await this.req('POST', `/issues/${n}/comments`, { body });
  }

  async status(sha: string, state: 'success' | 'failure' | 'pending' | 'error', description: string, targetUrl?: string) {
    await this.req('POST', `/statuses/${sha}`, { state, context: 'ai-review', description: description.slice(0, 140), target_url: targetUrl });
  }
}

export function commentBody(f: Finding): string {
  const parts = [`**${SEVERITY_LABEL[f.severity]} · ${CLASS_LABEL[f.cls]}** — ${f.title}`, '', f.explanation.trim()];
  if (f.suggestion !== undefined && f.suggestion.trim() !== '') parts.push('', '```suggestion', f.suggestion.replace(/\n$/, ''), '```');
  const src = f.sources.map((s) => s.replace(/^llm:/, 'LLM ')).join(', ');
  const rules = f.ruleIds.length ? ` · ${f.ruleIds.slice(0, 3).join(', ')}` : '';
  const conf = typeof f.confidence === 'number' ? ` · уверенность ${f.confidence.toFixed(2)}` : '';
  parts.push('', `<sub>Источник: ${src}${rules}${conf} · ложное замечание — поставьте 👎</sub>`, `<!-- ai-review:fp=${f.fingerprint};g=${f.cls === 'secrets' ? 'security' : f.cls} -->`);
  return parts.join('\n');
}
