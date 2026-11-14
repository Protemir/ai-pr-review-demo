export type Severity = 'critical' | 'high' | 'medium' | 'low';
export type FindingClass = 'logic' | 'security' | 'secrets' | 'quality' | 'tests';

export const SEVERITY_ORDER: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1 };
export const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low'];
export const CLASSES: FindingClass[] = ['logic', 'security', 'secrets', 'quality', 'tests'];

export const SEVERITY_LABEL: Record<Severity, string> = {
  critical: '🔴 Критично',
  high: '🟠 Высокий',
  medium: '🟡 Средний',
  low: '🔵 Низкий',
};

export const CLASS_LABEL: Record<FindingClass, string> = {
  logic: 'Ошибка логики',
  security: 'Безопасность',
  secrets: 'Секреты и конфигурация',
  quality: 'Качество',
  tests: 'Тесты',
};

export interface Finding {
  id: string;
  path: string;
  line: number;
  endLine?: number;
  /** исходная строка, если якорь перенесли к строкам исправления */
  origLine?: number;
  cls: FindingClass;
  severity: Severity;
  title: string;
  explanation: string;
  suggestion?: string;
  sources: string[];
  ruleIds: string[];
  confidence?: number;
  fingerprint?: string;
  /** true — замечание не привязать к строке diff, уходит только в сводку */
  summaryOnly?: boolean;
}

export interface AnalyzerRun {
  name: string;
  status: 'ok' | 'skipped' | 'error';
  ms: number;
  count: number;
  note?: string;
}

export interface LlmRawFinding {
  path?: string;
  line?: number;
  end_line?: number;
  class?: string;
  severity?: string;
  title?: string;
  explanation?: string;
  suggestion?: string;
  confidence?: number;
  related_static_id?: string;
}

export interface LlmRun {
  provider: string;
  model: string;
  calls: number;
  promptTokens: number;
  completionTokens: number;
  costUsd: number;
  ms: number;
  raw: LlmRawFinding[];
  rawText?: string[];
  error?: string;
}
