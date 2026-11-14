import { execFileSync } from 'node:child_process';

export interface DiffLine {
  kind: '+' | '-' | ' ';
  text: string;
  newLine?: number;
  oldLine?: number;
}

export interface DiffHunk {
  oldStart: number;
  newStart: number;
  lines: DiffLine[];
}

export interface DiffFile {
  path: string;
  oldPath?: string;
  status: 'added' | 'modified' | 'deleted' | 'renamed';
  binary: boolean;
  hunks: DiffHunk[];
  /** номера добавленных строк в новой версии файла */
  added: Set<number>;
  /** строки, к которым GitHub разрешает комментарий (добавленные + контекст ханка) */
  commentable: Set<number>;
  removed: DiffLine[];
}

export function parseDiff(text: string): DiffFile[] {
  const files: DiffFile[] = [];
  let cur: DiffFile | null = null;
  let hunk: DiffHunk | null = null;
  let o = 0;
  let n = 0;
  for (const rawLine of text.split('\n')) {
    const raw = rawLine.replace(/\r$/, '');
    if (raw.startsWith('diff --git ')) {
      const m = /^diff --git a\/(.+) b\/(.+)$/.exec(raw);
      cur = {
        path: m ? m[2] : '',
        status: 'modified',
        binary: false,
        hunks: [],
        added: new Set(),
        commentable: new Set(),
        removed: [],
      };
      files.push(cur);
      hunk = null;
      continue;
    }
    if (!cur) continue;
    if (raw.startsWith('@@')) {
      const m = /^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@/.exec(raw);
      if (m) {
        o = Number(m[1]);
        n = Number(m[2]);
        hunk = { oldStart: o, newStart: n, lines: [] };
        cur.hunks.push(hunk);
      }
      continue;
    }
    if (!hunk) {
      if (raw.startsWith('new file mode')) cur.status = 'added';
      else if (raw.startsWith('deleted file mode')) cur.status = 'deleted';
      else if (raw.startsWith('rename from ')) {
        cur.oldPath = raw.slice('rename from '.length);
        cur.status = 'renamed';
      } else if (raw.startsWith('rename to ')) cur.path = raw.slice('rename to '.length);
      else if (raw.startsWith('Binary files')) cur.binary = true;
      else if (raw.startsWith('+++ ')) {
        const p = raw.slice(4);
        if (p !== '/dev/null') cur.path = p.replace(/^b\//, '');
      }
      continue;
    }
    const c = raw[0];
    if (c === '+') {
      hunk.lines.push({ kind: '+', text: raw.slice(1), newLine: n });
      cur.added.add(n);
      cur.commentable.add(n);
      n++;
    } else if (c === '-') {
      const l: DiffLine = { kind: '-', text: raw.slice(1), oldLine: o };
      hunk.lines.push(l);
      cur.removed.push(l);
      o++;
    } else if (c === ' ') {
      hunk.lines.push({ kind: ' ', text: raw.slice(1), newLine: n, oldLine: o });
      cur.commentable.add(n);
      n++;
      o++;
    }
  }
  return files;
}

export function git(repoDir: string, args: string[]): string {
  return execFileSync('git', ['-C', repoDir, ...args], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
}

export function getDiff(repoDir: string, base: string, head: string): DiffFile[] {
  const text = git(repoDir, ['diff', '--no-color', '--unified=3', '--find-renames', `${base}...${head}`]);
  return parseDiff(text);
}

/** Содержимое файла в head-коммите (не зависит от того, что сейчас в рабочей копии). */
export function fileAtHead(repoDir: string, head: string, path: string): string[] {
  try {
    return git(repoDir, ['show', `${head}:${path}`]).replace(/\r\n/g, '\n').split('\n');
  } catch {
    return [];
  }
}

/** Ближайшая добавленная строка в пределах ±window, иначе undefined. */
export function snapToAdded(file: DiffFile, line: number, window = 3): number | undefined {
  if (file.added.has(line)) return line;
  for (let d = 1; d <= window; d++) {
    if (file.added.has(line - d)) return line - d;
    if (file.added.has(line + d)) return line + d;
  }
  return undefined;
}
