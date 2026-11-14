import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { Severity } from './types.ts';

export interface Config {
  llm: {
    provider: 'github-models' | 'openai-compatible' | 'mock' | 'none';
    model: string;
    baseUrl: string;
    apiKeyEnv: string;
    temperature: number;
    timeoutSec: number;
    maxOutputTokens: number;
    maxInputTokensPerCall: number;
    pricePer1MInput: number;
    pricePer1MOutput: number;
    minConfidence: number;
    /** замечания только от LLM ниже этого уровня не публикуются */
    minSeverity: Severity;
    criticalMinConfidence: number;
    mockFile?: string;
    extraInstructions?: string;
  };
  analyzers: {
    semgrep: { enabled: boolean; configs: string[] };
    ruff: { enabled: boolean; select: string[] };
    gitleaks: { enabled: boolean };
    osv: { enabled: boolean };
    tests: { enabled: boolean; minChangedLines: number };
  };
  minSeverity: Severity;
  maxComments: number;
  blockOnCritical: boolean;
  ignorePaths: string[];
  disabledRules: string[];
}

export const DEFAULT_CONFIG: Config = {
  llm: {
    // По умолчанию — локальная модель (код не уходит наружу). Облако: любой OpenAI-совместимый API + ключ в секрете CI.
    provider: 'openai-compatible',
    model: 'qwen2.5-coder:7b',
    baseUrl: 'http://localhost:11434/v1',
    apiKeyEnv: 'LLM_API_KEY',
    temperature: 0.1,
    timeoutSec: 300,
    maxOutputTokens: 1500,
    maxInputTokensPerCall: 5000,
    pricePer1MInput: 0,
    pricePer1MOutput: 0,
    minConfidence: 0.6,
    minSeverity: 'medium',
    criticalMinConfidence: 0.85,
  },
  analyzers: {
    semgrep: { enabled: true, configs: ['p/default'] },
    ruff: { enabled: true, select: ['E9', 'F', 'B', 'S'] },
    gitleaks: { enabled: true },
    osv: { enabled: true },
    tests: { enabled: true, minChangedLines: 15 },
  },
  minSeverity: 'low',
  maxComments: 25,
  blockOnCritical: false,
  ignorePaths: ['**/*.md', '**/*.lock', '**/package-lock.json', 'docs/**'],
  disabledRules: [],
};

function deepMerge<T>(base: T, over: unknown): T {
  if (over === null || typeof over !== 'object' || Array.isArray(over)) return (over ?? base) as T;
  const out: Record<string, unknown> = { ...(base as Record<string, unknown>) };
  for (const [k, v] of Object.entries(over as Record<string, unknown>)) {
    const b = out[k];
    out[k] = b && typeof b === 'object' && !Array.isArray(b) ? deepMerge(b, v) : v;
  }
  return out as T;
}

/** Конфигурация: значения по умолчанию ← .ai-review.json в репозитории ← переменные окружения. */
export function loadConfig(repoDir: string, env: NodeJS.ProcessEnv = process.env): Config {
  let cfg = DEFAULT_CONFIG;
  const file = join(repoDir, '.ai-review.json');
  if (existsSync(file)) cfg = deepMerge(cfg, JSON.parse(readFileSync(file, 'utf8')));
  const llm = { ...cfg.llm };
  if (env.AI_REVIEW_PROVIDER) llm.provider = env.AI_REVIEW_PROVIDER as Config['llm']['provider'];
  if (env.AI_REVIEW_MODEL) llm.model = env.AI_REVIEW_MODEL;
  if (env.AI_REVIEW_BASE_URL) llm.baseUrl = env.AI_REVIEW_BASE_URL;
  if (env.AI_REVIEW_API_KEY_ENV) llm.apiKeyEnv = env.AI_REVIEW_API_KEY_ENV;
  if (env.AI_REVIEW_PRICE_IN) llm.pricePer1MInput = Number(env.AI_REVIEW_PRICE_IN);
  if (env.AI_REVIEW_PRICE_OUT) llm.pricePer1MOutput = Number(env.AI_REVIEW_PRICE_OUT);
  if (env.AI_REVIEW_MAX_INPUT) llm.maxInputTokensPerCall = Number(env.AI_REVIEW_MAX_INPUT);
  if (env.AI_REVIEW_MAX_OUTPUT) llm.maxOutputTokens = Number(env.AI_REVIEW_MAX_OUTPUT);
  if (env.AI_REVIEW_MOCK_FILE) llm.mockFile = env.AI_REVIEW_MOCK_FILE;
  return { ...cfg, llm };
}

export function globToRegex(glob: string): RegExp {
  let re = '';
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i];
    if (c === '*') {
      if (glob[i + 1] === '*') {
        re += '.*';
        i++;
        if (glob[i + 1] === '/') i++;
      } else re += '[^/]*';
    } else if (c === '?') re += '[^/]';
    else re += c.replace(/[.+^${}()|[\]\\]/g, '\\$&');
  }
  return new RegExp('^' + re + '$');
}

export function isIgnored(path: string, patterns: string[]): boolean {
  return patterns.some((p) => globToRegex(p).test(path));
}
