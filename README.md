# AI-ревью pull request: демо-стенд (demo)

> **Демо.** Репозиторий сделан студией [TEMIRLAB](https://temirlab.com) как proof для технологической задачи AstanaHub
> «ИИ-ассистент автоматической проверки pull request (код-ревью): статический анализ и LLM».
> Код в `backend/` и `frontend/` — учебная мини-реализация RealWorld (Conduit). Дефекты в открытых PR внесены **намеренно**,
> а «секреты» в них ненастоящие.

## Что делает

На каждый pull request (и по команде `/ai-review` в комментарии) шаг GitHub Actions:

1. берёт diff PR (`base...head`) и анализирует только изменённые строки с контекстом файла;
2. гоняет статический анализ: **Semgrep** (`p/default`), **Ruff** (Python, вкл. правила безопасности `S`), **Gitleaks** (секреты в коммитах PR),
   **OSV** (добавленные зависимости из `requirements*.txt` и `package.json`), эвристику тестов (логика без тестов, отключённые и удалённые тесты);
3. отправляет в LLM листинг изменённых файлов с номерами строк и замечания анализаторов. Модель ищет ошибки логики и возвращает JSON с исправлениями;
4. склеивает дубли, отбрасывает замечания вне diff и с низкой уверенностью, понижает сомнительные «критично»;
5. публикует комментарии к строкам с уровнем серьёзности и блоком `suggestion`, итоговую сводку и статус `ai-review`;
6. пишет журнал: время, источники, токены и стоимость LLM (`ai-review-report.json` в артефактах и в Summary job).

Повторный запуск не дублирует комментарии: у каждого есть скрытый отпечаток (файл + класс + текст строки).
Если поставить 👎 на замечание, оно считается ложным: его учитывают в сводке и больше не публикуют.

Сервис не сливает и не отклоняет PR и не пишет в ветки. Права: `contents: read`, `pull-requests: write`, `issues: write`, `statuses: write`, `models: read`.

## LLM

| Режим | Где | Как включить |
|---|---|---|
| Облачная модель | GitHub Models (`openai/gpt-4.1`) по встроенному `GITHUB_TOKEN` | по умолчанию, `.ai-review.json` |
| Любой OpenAI-совместимый API | OpenAI, Azure, vLLM, LM Studio | `AI_REVIEW_PROVIDER=openai-compatible`, `AI_REVIEW_BASE_URL`, `AI_REVIEW_MODEL`, ключ в секрете |
| Локальная модель, код никуда не уходит | Ollama в раннере или на своём GPU-сервере | workflow `ai-review-local-llm` (`qwen2.5-coder`) |
| Без сети | записанный ответ | `AI_REVIEW_PROVIDER=mock AI_REVIEW_MOCK_FILE=...` |

## Подключение к своему репозиторию

1. Скопировать `reviewer/` и `.github/workflows/ai-review.yml` (в продукте это будет `uses: org/ai-review@v1`).
2. Положить в корень `.ai-review.json`: модель, анализаторы, пороги, `ignorePaths`, `disabledRules`, `blockOnCritical`.
3. Открыть PR. Ничего собирать не нужно: Node 24 запускает TypeScript напрямую, npm-зависимостей у ревьюера нет.

Webhook-режим: `docker build -t ai-pr-review reviewer && docker run -e GITHUB_TOKEN=... -e WEBHOOK_SECRET=... -p 8080:8080 ai-pr-review`,
в настройках репозитория webhook на `/webhook` (события Pull requests и Issue comments).

## Локально

```bash
cd reviewer && node --test test/reviewer.test.ts
node reviewer/src/main.ts --dry-run --base origin/main --head HEAD
```

## Зависимости и лицензии

| Компонент | Лицензия | Как используется |
|---|---|---|
| Node.js 24 (встроенные `fetch`, `node:test`, type stripping) | MIT | среда выполнения, npm-пакетов нет |
| Semgrep CE 1.95 | LGPL-2.1 | внешний процесс |
| Ruff 0.7 | MIT | внешний процесс |
| Gitleaks 8.21 | MIT | внешний процесс |
| OSV API | Apache-2.0 (данные CC-BY 4.0) | HTTPS-запросы |
| Ollama / Qwen2.5-Coder | MIT / Apache-2.0 | локальная модель |

Код ревьюера — MIT.
