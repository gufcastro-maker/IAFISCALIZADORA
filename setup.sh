#!/usr/bin/env bash
set -euo pipefail

# ==========
# IA FISCALIZADORA – SETUP
# Cria o projeto completo (API + Web + Docker + Postgres + Alembic + RBAC)
# Uso:
#   bash setup.sh
# Requisitos: bash, docker, docker-compose (ou docker compose), conexão à internet (para imagens)
# ==========

PROJECT_DIR="$(pwd)"
echo "Criando projeto em: $PROJECT_DIR"

write_file() {
  local path="$1"
  shift
  mkdir -p "$(dirname "$path")"
  cat > "$path" <<'EOF'
'"$@"'
EOF
  echo "  + $path"
}

# ---------------- Top-level ----------------
write_file ".gitignore" '
# Node/Next
node_modules
.next
out
# Python
__pycache__
*.pyc
# Docker
pgdata
# OS
.DS_Store
Thumbs.db
'

write_file "README.md" '
# IA Fiscalizadora – Starter (API + Web + RBAC + Postgres + Docker)

## Subir rápido (dev)
```bash
docker compose up --build -d
docker compose exec api alembic upgrade head
docker compose exec api python seed_users.py
# Web: http://localhost:3000
# API: http://localhost:8000/docs
# Logins: admin/secret | analyst/secret | viewer/secret
