import type { Article } from './types.ts';

const API_URL = 'https://api.realworld.io/api';

export async function fetchArticles(limit = 10, offset = 0): Promise<{ articles: Article[]; articlesCount: number }> {
  const res = await fetch(`${API_URL}/articles?limit=${limit}&offset=${offset}`);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}
