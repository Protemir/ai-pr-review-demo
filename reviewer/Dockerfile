# Webhook-режим: контейнер принимает события GitHub и запускает ту же проверку, что и шаг Actions.
FROM node:24-bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends git python3 pipx ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*
ENV PIPX_HOME=/opt/pipx PIPX_BIN_DIR=/usr/local/bin
RUN pipx install semgrep==1.95.0 && pipx install ruff==0.7.4 \
 && curl -sSL https://github.com/gitleaks/gitleaks/releases/download/v8.21.2/gitleaks_8.21.2_linux_x64.tar.gz | tar -xz -C /usr/local/bin gitleaks
WORKDIR /app
COPY package.json ./
COPY src ./src
USER node
EXPOSE 8080
HEALTHCHECK CMD node -e "fetch('http://localhost:8080/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node", "src/server.ts"]
