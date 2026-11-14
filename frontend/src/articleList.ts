import type { Article } from './types.ts';
import { pluralize } from './format.ts';

export function renderArticleList(root: HTMLElement, articles: Article[]): void {
  root.replaceChildren();
  for (const a of articles) {
    const item = document.createElement('article');
    const h = document.createElement('h2');
    h.textContent = a.title;
    const likes = document.createElement('span');
    likes.textContent = pluralize(a.favoritesCount, 'like', 'likes');
    item.append(h, likes);
    root.append(item);
  }
}
