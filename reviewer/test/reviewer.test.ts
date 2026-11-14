import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { parseDiff, snapToAdded } from '../src/diff.ts';
import { DEFAULT_CONFIG, globToRegex, isIgnored } from '../src/config.ts';
import { mergeFindings, fingerprint, fitIndent, isPlaceholder, suggestionFits } from '../src/merge.ts';
import { extractDeps, mapGitleaks, mapRuff, mapSemgrep, testsHeuristics } from '../src/analyzers.ts';
import { newFunctions, parseLlmJson, readSse, renderFile, runLlm } from '../src/llm.ts';
import { createServer } from 'node:http';
import { alreadyThere, commentBody, FP_MARK } from '../src/github.ts';
import { shouldReview, verifySignature } from '../src/server.ts';
import type { Finding } from '../src/types.ts';

const DIFF = `diff --git a/app/x.py b/app/x.py
index 1111111..2222222 100644
--- a/app/x.py
+++ b/app/x.py
@@ -1,4 +1,6 @@
 import os
-def f(a):
+def f(a, b):
+    if a == None:
+        return 0
     return a

diff --git a/requirements.txt b/requirements.txt
index 3333333..4444444 100644
--- a/requirements.txt
+++ b/requirements.txt
@@ -1,1 +1,2 @@
 flask==3.0.3
+PyYAML==5.3
diff --git a/tests/test_x.py b/tests/test_x.py
deleted file mode 100644
--- a/tests/test_x.py
+++ /dev/null
@@ -1,2 +0,0 @@
-def test_f():
-    assert f(1) == 1
`;

test('parseDiff: добавленные строки, контекст, удалённые файлы', () => {
  const files = parseDiff(DIFF);
  assert.equal(files.length, 3);
  const x = files[0];
  assert.equal(x.path, 'app/x.py');
  assert.deepEqual([...x.added].sort(), [2, 3, 4]);
  assert.ok(x.commentable.has(1) && x.commentable.has(5));
  assert.equal(x.removed.length, 1);
  assert.equal(files[2].status, 'deleted');
  assert.equal(files[2].path, 'tests/test_x.py');
});

test('snapToAdded: притягивает к ближайшей добавленной строке в пределах ±3', () => {
  const [x] = parseDiff(DIFF);
  assert.equal(snapToAdded(x, 3), 3);
  assert.equal(snapToAdded(x, 6), 4);
  assert.equal(snapToAdded(x, 9), undefined);
});

test('glob: ignorePaths', () => {
  assert.ok(globToRegex('**/*.md').test('README.md'));
  assert.ok(isIgnored('docs/a/b.txt', ['docs/**']));
  assert.ok(!isIgnored('src/a.ts', DEFAULT_CONFIG.ignorePaths));
});

test('OSV: зависимости только из добавленных строк', () => {
  const deps = extractDeps(parseDiff(DIFF));
  assert.deepEqual(deps.map((d) => [d.ecosystem, d.name, d.version, d.line]), [['PyPI', 'PyYAML', '5.3', 2]]);
});

test('tests: удалённый тест и логика без тестов', () => {
  const f = testsHeuristics(parseDiff(DIFF), 2);
  assert.ok(f.some((x) => x.ruleIds.includes('tests:no-tests')));
  assert.ok(f.some((x) => x.ruleIds.includes('tests:removed') && x.summaryOnly));
});

test('semgrep/ruff/gitleaks: только находки на изменённых строках', () => {
  const files = parseDiff(DIFF);
  const sg = mapSemgrep({ results: [
    { check_id: 'python.lang.security.audit.formatted-sql-query', path: 'app/x.py', start: { line: 3 }, end: { line: 3 }, extra: { message: 'SQL. Use params', severity: 'ERROR', metadata: { category: 'security', likelihood: 'HIGH', impact: 'HIGH' } } },
    { check_id: 'x', path: 'app/x.py', start: { line: 1 }, end: { line: 1 }, extra: { message: 'old line', severity: 'ERROR', metadata: {} } },
  ] }, files, []);
  assert.equal(sg.length, 1);
  assert.equal(sg[0].severity, 'critical');
  const rf = mapRuff([{ code: 'E711', message: 'cmp None', filename: 'app/x.py', location: { row: 3 }, end_location: { row: 3 } }], '.', files, []);
  assert.equal(rf.length, 1);
  const gl = mapGitleaks([{ File: 'app/x.py', StartLine: 2, RuleID: 'generic-api-key', Description: 'Generic API Key' }], files);
  assert.equal(gl[0].severity, 'critical');
  assert.equal(gl[0].cls, 'secrets');
});

test('merge: LLM уточняет анализатор, дубль склеивается, сомнительный critical понижается', () => {
  const files = parseDiff(DIFF);
  const s: Finding = { id: 'S1', path: 'app/x.py', line: 3, cls: 'logic', severity: 'low', title: 'cmp None', explanation: 'E711', sources: ['ruff'], ruleIds: ['ruff:E711'] };
  const { findings, stats } = mergeFindings([s], [
    { related_static_id: 'S1', path: 'app/x.py', line: 3, severity: 'medium', explanation: 'Сравнивайте через is None', suggestion: '    if a is None:', confidence: 0.9 },
    { path: 'app/x.py', line: 2, class: 'logic', severity: 'critical', title: 'b не используется', explanation: '...', confidence: 0.7 },
    { path: 'app/x.py', line: 40, class: 'logic', severity: 'high', title: 'мимо diff', explanation: '...', confidence: 0.9 },
    { path: 'app/x.py', line: 4, class: 'quality', severity: 'low', title: 'сомнительно', explanation: '...', confidence: 0.3 },
  ], files, DEFAULT_CONFIG, 'test-model');
  assert.equal(stats.llmEnriched, 1);
  assert.equal(stats.llmDowngraded, 1);
  assert.equal(stats.llmDroppedLine, 1);
  assert.equal(stats.llmDroppedConfidence, 1);
  const merged = findings.find((f) => f.ruleIds.includes('ruff:E711'))!;
  assert.equal(merged.severity, 'high'); // склеено с LLM-замечанием на соседней строке (критично → высокий)
  assert.equal(merged.suggestion, '    if a is None:');
});

test('fingerprint не зависит от номера строки и формулировки', () => {
  const a: Finding = { id: '1', path: 'p', line: 3, cls: 'security', severity: 'high', title: 'A', explanation: '', sources: [], ruleIds: [] };
  const b = { ...a, line: 10, title: 'B', cls: 'secrets' as const };
  assert.equal(fingerprint(a, '  x = 1 '), fingerprint(b, 'x = 1'));
});

test('parseLlmJson: ответ в ```json и мусор вокруг', () => {
  assert.equal(parseLlmJson('```json\n{"findings":[{"path":"a","line":1}]}\n```').length, 1);
  assert.equal(parseLlmJson('Вот ответ: {"findings": []}').length, 0);
});

test('renderFile: номера строк и метки «+»', () => {
  const [x] = parseDiff(DIFF);
  const r = renderFile(x, ['import os', 'def f(a, b):', '    if a == None:', '        return 0', '    return a', '']);
  assert.match(r, /\s3 \+ {5}if a == None:/);
  assert.match(r, /\s1 {3}import os/);
});

test('commentBody: suggestion и скрытая метка для дедупликации', () => {
  const f: Finding = { id: '1', path: 'p', line: 1, cls: 'security', severity: 'critical', title: 'SQL', explanation: 'плохо', suggestion: 'x = 1', sources: ['semgrep', 'llm:m'], ruleIds: ['semgrep:r'], fingerprint: 'abcdef123456' };
  const body = commentBody(f);
  assert.match(body, /```suggestion\nx = 1\n```/);
  assert.equal(FP_MARK.exec(body)?.[1], 'abcdef123456');
});

test('webhook: подпись и выбор событий', () => {
  const payload = Buffer.from('{"a":1}');
  const sig = 'sha256=' + createHmac('sha256', 's3').update(payload).digest('hex');
  assert.ok(verifySignature('s3', payload, sig));
  assert.ok(!verifySignature('other', payload, sig));
  assert.equal(shouldReview('pull_request', { action: 'opened', pull_request: { number: 5 } }), 5);
  assert.equal(shouldReview('issue_comment', { action: 'created', issue: { number: 7, pull_request: {} }, comment: { body: '/ai-review' } }), 7);
  assert.equal(shouldReview('issue_comment', { action: 'created', issue: { number: 7 }, comment: { body: '/ai-review' } }), undefined);
});

test('fitIndent: возвращает потерянный отступ', () => {
  assert.equal(fitIndent('data = yaml.safe_load(x)', '    data = yaml.load(x)'), '    data = yaml.safe_load(x)');
  assert.equal(fitIndent('if a:\n    b()', '        old()'), '        if a:\n            b()');
});

test('parseLlmJson: fixes превращаются в уточнения замечаний анализаторов', () => {
  const r = parseLlmJson('{"findings":[],"fixes":[{"static_id":"S2","line":5,"suggestion":"x"}]}');
  assert.equal(r[0].related_static_id, 'S2');
});

test('isPlaceholder: заглушки вместо кода не публикуются как suggestion', () => {
  assert.ok(isPlaceholder("root.innerHTML = a.map(x => `<b>...</b>`)"));
  assert.ok(isPlaceholder("test('x', () => { ... });"));
  assert.ok(!isPlaceholder('const all = [...items, extra];'));
});

test('newFunctions: функции из добавленных строк', () => {
  const listing = '   10 + def list_comments(slug):\n   11   def old():\n   12 + export function formatDate(iso: string) {\n   13 + const isOwn = (a) => a';
  assert.deepEqual(newFunctions(listing), ['list_comments', 'formatDate', 'isOwn']);
});

test('readSse: собирает потоковый ответ и usage', async () => {
  const sse = 'data: {"choices":[{"delta":{"content":"{\\"fin"}}]}\n\ndata: {"choices":[{"delta":{"content":"dings\\":[]}"}}]}\n\ndata: {"choices":[],"usage":{"prompt_tokens":11,"completion_tokens":4}}\n\ndata: [DONE]\n';
  const r = await readSse(new Response(sse), 'x');
  assert.equal(r.text, '{"findings":[]}');
  assert.equal(r.promptTokens, 11);
});

test('merge: повтор одного замечания на соседних строках склеивается, XSS — это безопасность', () => {
  const files = parseDiff(DIFF);
  const { findings } = mergeFindings([], [
    { path: 'app/x.py', line: 2, class: 'logic', severity: 'medium', title: 'XSS в выводе', explanation: '...', confidence: 0.9 },
    { path: 'app/x.py', line: 4, class: 'logic', severity: 'medium', title: 'XSS в выводе', explanation: '...', confidence: 0.9 },
  ], files, DEFAULT_CONFIG, 'm');
  assert.equal(findings.length, 1);
  assert.equal(findings[0].cls, 'security');
});

test('merge: совет текстом не становится suggestion; «secrets/critical» понимается; Ruff+Semgrep про один SQL склеиваются', () => {
  const files = parseDiff(DIFF);
  const ruff: Finding = { id: 'S1', path: 'app/x.py', line: 3, cls: 'security', severity: 'critical', title: 'SQL', explanation: 'ruff', sources: ['ruff'], ruleIds: ['ruff:S608'] };
  const sg: Finding = { id: 'S2', path: 'app/x.py', line: 2, cls: 'security', severity: 'high', title: 'SQL', explanation: 'semgrep', sources: ['semgrep'], ruleIds: ['semgrep:sql'] };
  const { findings } = mergeFindings([ruff, sg], [
    { related_static_id: 'S1', line: 3, suggestion: 'Используйте параметризованный запрос.' },
    { path: 'app/x.py', line: 4, class: 'secrets/critical', severity: 'critical/high', title: 'Ключ в коде', explanation: 'x', confidence: 0.9 },
  ], files, DEFAULT_CONFIG, 'm');
  const sql = findings.filter((f) => f.cls === 'security' && f.ruleIds.some((r) => r.startsWith('ruff') || r.startsWith('semgrep')));
  assert.equal(sql.length, 1);
  assert.equal(sql[0].suggestion, undefined);
  // секрет от LLM в той же группе «безопасность» и рядом с SQL — склеивается с ним, отдельного шума нет
  assert.ok(findings.length <= 2);
});

test('suggestionFits: исправление не должно ломать скобки вокруг', () => {
  assert.ok(!suggestionFits('db.execute(f"SELECT ? ", (slug,))', ['    rows = get_db().execute(']));
  assert.ok(suggestionFits('    data = yaml.safe_load(request.data)', ['    data = yaml.load(request.data)']));
  assert.ok(suggestionFits('x = ")("', ['x = 1']));
});

test('runLlm: OpenAI-совместимый сервер со стримингом (как Ollama)', async () => {
  const srv = createServer((req, res) => {
    let b = '';
    req.on('data', (c) => (b += c));
    req.on('end', () => {
      assert.equal(JSON.parse(b).stream, true);
      res.writeHead(200, { 'content-type': 'text/event-stream' });
      res.write('data: {"choices":[{"delta":{"content":"{\\"findings\\":[{\\"path\\":\\"a.py\\",\\"line\\":2"}}]}\n\n');
      setTimeout(() => {
        res.write('data: {"choices":[{"delta":{"content":",\\"title\\":\\"t\\"}]}"}}]}\n\ndata: {"choices":[],"usage":{"prompt_tokens":100,"completion_tokens":20}}\n\ndata: [DONE]\n\n');
        res.end();
      }, 50);
    });
  });
  await new Promise<void>((r) => srv.listen(0, r));
  const port = (srv.address() as { port: number }).port;
  const [x] = parseDiff(DIFF);
  const r = await runLlm({ ...DEFAULT_CONFIG.llm, baseUrl: `http://127.0.0.1:${port}/v1`, pricePer1MInput: 1, pricePer1MOutput: 2 },
    [{ file: x, content: ['a', 'b', 'c', 'd', 'e'] }], [], 'meta', {});
  srv.close();
  assert.equal(r.error, undefined);
  assert.equal(r.raw.length, 1);
  assert.equal(r.promptTokens, 100);
  assert.ok(Math.abs(r.costUsd - 0.00014) < 1e-9);
});

test('alreadyThere: то же замечание на соседней строке не публикуется повторно', () => {
  const f: Finding = { id: '1', path: 'a.ts', line: 43, cls: 'security', severity: 'high', title: 'XSS', explanation: '', sources: [], ruleIds: [], fingerprint: 'new' };
  assert.ok(alreadyThere(f, [{ fp: 'old', path: 'a.ts', line: 44, group: 'security', falsePositive: false }]));
  assert.ok(!alreadyThere(f, [{ fp: 'old', path: 'a.ts', line: 44, group: 'logic', falsePositive: false }]));
  assert.ok(!alreadyThere(f, [{ fp: 'old', path: 'a.ts', line: 56, group: 'security', falsePositive: false }]));
  assert.ok(alreadyThere(f, [{ fp: 'old', path: 'a.ts', line: 50, group: 'security', title: 'XSS в выводе', falsePositive: false }]));
  assert.ok(!alreadyThere(f, [{ fp: 'old', path: 'a.ts', line: 50, group: 'security', title: 'SQL-инъекция', falsePositive: false }]));
});
