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
'

write_file "docker-compose.yml" '
version: "3.9"
services:
db:
image: postgres:16
environment:
POSTGRES_USER: app
POSTGRES_PASSWORD: app
POSTGRES_DB: fiscalizadora
ports: ["5432:5432"]
volumes: ["pgdata:/var/lib/postgresql/data"]

api:
build: ./api
environment:
JWT_SECRET: change-me-in-prod
ACCESS_TOKEN_EXPIRE_MINUTES: 240
DATABASE_URL: postgresql+psycopg://app:app@db:5432/fiscalizadora
WEB_ORIGIN: http://localhost:3000

ports: ["8000:8000"]
depends_on: [db]

web:
build: ./web
environment:
NEXT_PUBLIC_API_URL: http://localhost:8000

ports: ["3000:3000"]
depends_on: [api]

volumes:
pgdata:
'

---------------- API ----------------

write_file "api/requirements.txt" '
fastapi
uvicorn
python-jose[cryptography]
passlib[bcrypt]
pydantic
sqlalchemy>=2.0
psycopg[binary]
alembic
python-multipart
'

write_file "api/Dockerfile" '
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
ENV PYTHONUNBUFFERED=1
EXPOSE 8000
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
'

write_file "api/db.py" '
import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql+psycopg://app:app@db:5432/fiscalizadora")
engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
'

write_file "api/models.py" '
from sqlalchemy.orm import declarative_base
from sqlalchemy import Column, Text, Boolean, TIMESTAMP, Integer, ForeignKey, text
from sqlalchemy.dialects.postgresql import UUID

Base = declarative_base()

class User(Base):
tablename = "users"
table_args = {"schema": "auth"}
id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
username = Column(Text, unique=True, nullable=False)
password_hash = Column(Text, nullable=False)
is_active = Column(Boolean, nullable=False, server_default=text("true"))
created_at = Column(TIMESTAMP, nullable=False, server_default=text("now()"))

class Role(Base):
tablename = "roles"
table_args = {"schema": "auth"}
id = Column(Integer, primary_key=True)
name = Column(Text, unique=True, nullable=False)

class UserRole(Base):
tablename = "user_roles"
table_args = {"schema": "auth"}
user_id = Column(UUID(as_uuid=True), ForeignKey("auth.users.id", ondelete="CASCADE"), primary_key=True)
role_id = Column(Integer, ForeignKey("auth.roles.id", ondelete="CASCADE"), primary_key=True)
'

write_file "api/models_config.py" '
from sqlalchemy.orm import declarative_base
from sqlalchemy import Column, Integer, String, Text, Boolean, TIMESTAMP, text

BaseConfig = declarative_base()

class FonteORM(BaseConfig):
tablename = "fontes"
table_args = {"schema": "config"}
id = Column(Integer, primary_key=True)
nome = Column(String(100), nullable=False, unique=True)
url = Column(Text, nullable=False)
ativo = Column(Boolean, nullable=False, server_default=text("true"))
criado_em = Column(TIMESTAMP, nullable=False, server_default=text("now()"))
'

write_file "api/auth_db.py" '
import os
from datetime import datetime, timedelta
from typing import Optional, List
from jose import jwt
from passlib.context import CryptContext
from sqlalchemy import select, join
from sqlalchemy.orm import Session
from db import SessionLocal
from models import User, Role, UserRole

JWT_SECRET = os.getenv("JWT_SECRET", "change-me-in-prod")
JWT_ALG = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "240"))

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class AuthService:
def init(self):
self._session_factory = SessionLocal
def create_token(self, subject: str, roles: List[str]) -> str:
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {"sub": subject, "roles": roles, "exp": int(expire.timestamp())}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)

def authenticate(self, username: str, password: str) -> Optional[dict]:
    with self._session_factory() as db:  # type: Session
        u = db.execute(select(User).where(User.username == username)).scalar_one_or_none()
        if not u or not u.is_active:
            return None
        if not pwd_context.verify(password, u.password_hash):
            return None
        q = select(Role.name).select_from(join(UserRole, Role, UserRole.role_id == Role.id)).where(UserRole.user_id == u.id)
        roles = [r[0] for r in db.execute(q).all()]
        return {"username": u.username, "roles": roles}
		auth_service = AuthService()
'

write_file "api/deps.py" '
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from typing import List
from jose import jwt, JWTError
import os

JWT_SECRET = os.getenv("JWT_SECRET", "change-me-in-prod")
JWT_ALG = "HS256"

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

class UserCtx:
def init(self, username: str, roles: List[str]):
self.username = username
self.roles = roles

async def get_current_user(token: str = Depends(oauth2_scheme)) -> UserCtx:
try:
payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
return UserCtx(username=payload.get("sub"), roles=payload.get("roles", []))
except JWTError:
raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Credenciais inválidas")

class require_roles:
def init(self, allowed: List[str]):
self.allowed = set(allowed)
def call(self, user: UserCtx = Depends(get_current_user)):
if not set(user.roles) & self.allowed:
raise HTTPException(status_code=403, detail="Sem permissão")
return user
'

write_file "api/schemas_config.py" '
from pydantic import BaseModel, AnyHttpUrl, Field
from typing import Optional
from datetime import datetime

class FonteCreate(BaseModel):
nome: str = Field(min_length=2, max_length=100)
url: AnyHttpUrl

class FonteUpdate(BaseModel):
nome: Optional[str] = Field(default=None, min_length=2, max_length=100)
url: Optional[AnyHttpUrl] = None
ativo: Optional[bool] = None

class FonteRead(BaseModel):
id: int
nome: str
url: AnyHttpUrl
ativo: bool
criado_em: datetime
class Config:
from_attributes = True
'

write_file "api/routes_config.py" '
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import select
from typing import List

from db import SessionLocal
from deps import require_roles
from models_config import FonteORM
from schemas_config import FonteCreate, FonteUpdate, FonteRead

router = APIRouter(prefix="/config", tags=["config"], dependencies=[Depends(require_roles(["ADMIN"]))])

async def get_db():
db = SessionLocal()
try:
yield db
finally:
db.close()

@router.get("/fontes", response_model=List[FonteRead])
async def list_fontes(db: Session = Depends(get_db)):
rows = db.execute(select(FonteORM).order_by(FonteORM.nome.asc())).scalars().all()
return rows

@router.post("/fontes", response_model=FonteRead, status_code=status.HTTP_201_CREATED)
async def create_fonte(body: FonteCreate, db: Session = Depends(get_db)):
exists = db.execute(select(FonteORM).where(FonteORM.nome == body.nome)).scalar_one_or_none()
if exists:
raise HTTPException(status_code=400, detail="Já existe uma fonte com este nome")
f = FonteORM(nome=body.nome, url=str(body.url), ativo=True)
db.add(f)
db.commit()
db.refresh(f)
return f

@router.put("/fontes/{fonte_id}", response_model=FonteRead)
async def update_fonte(fonte_id: int, body: FonteUpdate, db: Session = Depends(get_db)):
f = db.get(FonteORM, fonte_id)
if not f:
raise HTTPException(status_code=404, detail="Fonte não encontrada")
if body.nome is not None:
if body.nome != f.nome:
dup = db.execute(select(FonteORM).where(FonteORM.nome == body.nome)).scalar_one_or_none()
if dup:
raise HTTPException(400, detail="Já existe uma fonte com este nome")
f.nome = body.nome
if body.url is not None:
f.url = str(body.url)
if body.ativo is not None:
f.ativo = body.ativo
db.commit()
db.refresh(f)
return f

@router.delete("/fontes/{fonte_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_fonte(fonte_id: int, db: Session = Depends(get_db)):
f = db.get(FonteORM, fonte_id)
if not f:
raise HTTPException(status_code=404, detail="Fonte não encontrada")
db.delete(f)
db.commit()
return
'

write_file "api/app.py" '
import os, io, csv
from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List, Literal, Dict
from datetime import date
from auth_db import auth_service
from deps import require_roles, get_current_user
from routes_config import router as config_router

app = FastAPI(title="IA Fiscalizadora – API", version="0.4.0")

ALLOWED_ORIGINS = [os.getenv("WEB_ORIGIN", "http://localhost:3000")]
app.add_middleware(CORSMiddleware, allow_origins=ALLOWED_ORIGINS, allow_credentials=True, allow_methods=[""], allow_headers=[""])

-------- Auth --------

class LoginRequest(BaseModel):
username: str
password: str
class Token(BaseModel):
access_token: str
token_type: str = "bearer"

@app.post("/auth/login", response_model=Token)
def login(body: LoginRequest):
user = auth_service.authenticate(body.username, body.password)
if not user:
raise HTTPException(status_code=401, detail="Usuário ou senha inválidos")
return Token(access_token=auth_service.create_token(user["username"], user["roles"]))

@app.get("/auth/me")
async def me(user = Depends(get_current_user)):
return {"username": user.username, "roles": user.roles}

-------- Mock domain (contratos/empenhos) --------

class Alerta(BaseModel):
regra: str
severidade: Literal["Baixa","Média","Alta"]
resumo: str
pagina: Optional[int] = None
fonte_url: Optional[str] = None
class TimelineItem(BaseModel):
t: date
e: str
class ContratoCard(BaseModel):
id: str
orgao: str
fornecedor_cnpj: str
fornecedor_nome: str
objeto: str
valor_inicial: float
dt_assinatura: date
score: int
class ContratoDetalhe(ContratoCard):
alertas: List[Alerta] = []
timeline: List[TimelineItem] = []
class Paginacao(BaseModel):
total: int
page: int
page_size: int
class ListaContratos(BaseModel):
data: List[ContratoCard]
pagination: Paginacao

MOCK: Dict[str, ContratoDetalhe] = {
"CT-2025-001": ContratoDetalhe(
id="CT-2025-001", orgao="Secretaria de Saúde", fornecedor_cnpj="12.345.678/0001-99",
fornecedor_nome="Clínica ABC LTDA", objeto="Serviços de exames de imagem",
valor_inicial=450000.0, dt_assinatura=date(2025,3,12), score=86,
alertas=[Alerta(regra="Aditivo > 25%", severidade="Alta", resumo="Aditivos somam 38%", pagina=6)],
timeline=[TimelineItem(t=date(2025,1,22), e="Edital publicado"), TimelineItem(t=date(2025,3,12), e="Contrato assinado")]
),
"CT-2025-021": ContratoDetalhe(
id="CT-2025-021", orgao="Secretaria de Administração", fornecedor_cnpj="11.222.333/0001-44",
fornecedor_nome="Comercial XYZ ME", objeto="Materiais de escritório",
valor_inicial=88000.0, dt_assinatura=date(2025,5,19), score=34, alertas=[], timeline=[]
),
}

@app.get("/health")
def health(): return {"status":"ok"}

@app.get("/contratos", response_model=ListaContratos)
def listar_contratos(page: int=1, page_size: int=10, orgao: Optional[str]=None, q: Optional[str]=None, min_score: int=0):
items = list(MOCK.values())
if orgao and orgao.lower() != "todos":
items = [c for c in items if c.orgao.lower() == orgao.lower()]
if q:
ql = q.lower()
items = [c for c in items if ql in c.id.lower() or ql in c.objeto.lower()]
if min_score:
items = [c for c in items if c.score >= min_score]
total = len(items)
start = (page-1)*page_size
slice_ = [ContratoCard(**c.dict()) for c in items[start:start+page_size]]
return ListaContratos(data=slice_, pagination=Paginacao(total=total, page=page, page_size=page_size))

@app.get("/contratos/{id}", response_model=ContratoDetalhe)
def obter_contrato(id: str):
c = MOCK.get(id)
if not c:
raise HTTPException(404, "Contrato não encontrado")
return c

@app.get("/empenhos/{id}")
def empenhos(id: str):
return {
"id_contrato": id,
"serie_pagamentos": [{"mes":"2025-01","pago": 120000}, {"mes":"2025-02","pago": 80000}, {"mes":"2025-03","pago": 100000}],
"serie_producao": [{"mes":"2025-01","quantidade": 350}, {"mes":"2025-02","quantidade": 280}, {"mes":"2025-03","quantidade": 310}],
}

@app.get("/fornecedores/participacao")
def participacao(orgao: Optional[str]=None, meses: int=12):
return {
"orgao": orgao or "Todos",
"meses": meses,
"dados": [
{"cnpj":"12.345.678/0001-99", "nome":"Clínica ABC LTDA", "participacao_percentual": 65.2},
{"cnpj":"11.222.333/0001-44", "nome":"Comercial XYZ ME", "participacao_percentual": 34.8},
]
}

from fastapi.responses import Response
@app.get("/export/contratos.csv")
def export_csv(orgao: Optional[str]=None):
items = list(MOCK.values())
if orgao and orgao.lower()!="todos":
items = [c for c in items if c.orgao.lower()==orgao.lower()]
buf = io.StringIO()
w = csv.writer(buf)
w.writerow(["id","orgao","fornecedor_cnpj","fornecedor_nome","objeto","valor_inicial","dt_assinatura","score"])
for c in items:
w.writerow([c.id, c.orgao, c.fornecedor_cnpj, c.fornecedor_nome, c.objeto, c.valor_inicial, c.dt_assinatura.isoformat(), c.score])
return Response(content=buf.getvalue(), media_type="text/csv; charset=utf-8", headers={"Content-Disposition":"attachment; filename=contratos.csv"})

class DossieRequest(BaseModel):
contratos: List[str]
incluir_evidencias: bool = True
idioma: Literal["pt-BR","en-US"] = "pt-BR"
class DossieResponse(BaseModel):
relatorio_id: str
url_download: str

@app.post("/relatorios/dossie", response_model=DossieResponse, dependencies=[Depends(require_roles(["ADMIN","ANALYST"]))])
def gerar_dossie(req: DossieRequest):
if not req.contratos:
raise HTTPException(400, "Informe ao menos um contrato")
rid = "REL-" + "-".join(req.contratos)
return DossieResponse(relatorio_id=rid, url_download=f"https://example.com/reports/{rid}.pdf
")

Rotas de configuração protegidas

app.include_router(config_router)
'

write_file "api/seed_users.py" '
import os
from passlib.context import CryptContext
from sqlalchemy import insert, select
from db import SessionLocal
from models import User, Role, UserRole

pwd = CryptContext(schemes=["bcrypt"], deprecated="auto")
PASSWORD = os.getenv("SEED_PASSWORD", "secret")
USERS = [("admin", ["ADMIN"]), ("analyst", ["ANALYST"]), ("viewer", ["VIEWER"])]
ROLES = ["ADMIN","ANALYST","VIEWER"]

with SessionLocal() as db:
role_ids = {}
for r in ROLES:
row = db.execute(select(Role).where(Role.name==r)).scalar_one_or_none()
if not row:
rid = db.execute(insert(Role).values(name=r).returning(Role.id)).scalar_one()
role_ids[r] = rid
else:
role_ids[r] = row.id
auth_service = AuthService()
'

write_file "api/deps.py" '
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from typing import List
from jose import jwt, JWTError
import os

JWT_SECRET = os.getenv("JWT_SECRET", "change-me-in-prod")
JWT_ALG = "HS256"

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

class UserCtx:
def init(self, username: str, roles: List[str]):
self.username = username
self.roles = roles

async def get_current_user(token: str = Depends(oauth2_scheme)) -> UserCtx:
try:
payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
return UserCtx(username=payload.get("sub"), roles=payload.get("roles", []))
except JWTError:
raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Credenciais inválidas")

class require_roles:
def init(self, allowed: List[str]):
self.allowed = set(allowed)
def call(self, user: UserCtx = Depends(get_current_user)):
if not set(user.roles) & self.allowed:
raise HTTPException(status_code=403, detail="Sem permissão")
return user
'

write_file "api/schemas_config.py" '
from pydantic import BaseModel, AnyHttpUrl, Field
from typing import Optional
from datetime import datetime

class FonteCreate(BaseModel):
nome: str = Field(min_length=2, max_length=100)
url: AnyHttpUrl

class FonteUpdate(BaseModel):
nome: Optional[str] = Field(default=None, min_length=2, max_length=100)
url: Optional[AnyHttpUrl] = None
ativo: Optional[bool] = None

class FonteRead(BaseModel):
id: int
nome: str
url: AnyHttpUrl
ativo: bool
criado_em: datetime
class Config:
from_attributes = True
'

write_file "api/routes_config.py" '
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import select
from typing import List

from db import SessionLocal
from deps import require_roles
from models_config import FonteORM
from schemas_config import FonteCreate, FonteUpdate, FonteRead

router = APIRouter(prefix="/config", tags=["config"], dependencies=[Depends(require_roles(["ADMIN"]))])

async def get_db():
db = SessionLocal()
try:
yield db
finally:
db.close()

@router.get("/fontes", response_model=List[FonteRead])
async def list_fontes(db: Session = Depends(get_db)):
rows = db.execute(select(FonteORM).order_by(FonteORM.nome.asc())).scalars().all()
return rows

@router.post("/fontes", response_model=FonteRead, status_code=status.HTTP_201_CREATED)
async def create_fonte(body: FonteCreate, db: Session = Depends(get_db)):
exists = db.execute(select(FonteORM).where(FonteORM.nome == body.nome)).scalar_one_or_none()
if exists:
raise HTTPException(status_code=400, detail="Já existe uma fonte com este nome")
f = FonteORM(nome=body.nome, url=str(body.url), ativo=True)
db.add(f)
db.commit()
db.refresh(f)
return f

@router.put("/fontes/{fonte_id}", response_model=FonteRead)
async def update_fonte(fonte_id: int, body: FonteUpdate, db: Session = Depends(get_db)):
f = db.get(FonteORM, fonte_id)
if not f:
raise HTTPException(status_code=404, detail="Fonte não encontrada")
if body.nome is not None:
if body.nome != f.nome:
dup = db.execute(select(FonteORM).where(FonteORM.nome == body.nome)).scalar_one_or_none()
if dup:
raise HTTPException(400, detail="Já existe uma fonte com este nome")
f.nome = body.nome
if body.url is not None:
f.url = str(body.url)
if body.ativo is not None:
f.ativo = body.ativo
db.commit()
db.refresh(f)
return f

@router.delete("/fontes/{fonte_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_fonte(fonte_id: int, db: Session = Depends(get_db)):
f = db.get(FonteORM, fonte_id)
if not f:
raise HTTPException(status_code=404, detail="Fonte não encontrada")
db.delete(f)
db.commit()
return
'

write_file "api/app.py" '
import os, io, csv
from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List, Literal, Dict
from datetime import date
from auth_db import auth_service
from deps import require_roles, get_current_user
from routes_config import router as config_router

app = FastAPI(title="IA Fiscalizadora – API", version="0.4.0")

ALLOWED_ORIGINS = [os.getenv("WEB_ORIGIN", "http://localhost:3000")]
app.add_middleware(CORSMiddleware, allow_origins=ALLOWED_ORIGINS, allow_credentials=True, allow_methods=[""], allow_headers=[""])

-------- Auth --------

class LoginRequest(BaseModel):
username: str
password: str
class Token(BaseModel):
access_token: str
token_type: str = "bearer"

@app.post("/auth/login", response_model=Token)
def login(body: LoginRequest):
user = auth_service.authenticate(body.username, body.password)
if not user:
raise HTTPException(status_code=401, detail="Usuário ou senha inválidos")
return Token(access_token=auth_service.create_token(user["username"], user["roles"]))

@app.get("/auth/me")
async def me(user = Depends(get_current_user)):
return {"username": user.username, "roles": user.roles}

-------- Mock domain (contratos/empenhos) --------

class Alerta(BaseModel):
regra: str
severidade: Literal["Baixa","Média","Alta"]
resumo: str
pagina: Optional[int] = None
fonte_url: Optional[str] = None
class TimelineItem(BaseModel):
t: date
e: str
class ContratoCard(BaseModel):
id: str
orgao: str
fornecedor_cnpj: str
fornecedor_nome: str
objeto: str
valor_inicial: float
dt_assinatura: date
score: int
class ContratoDetalhe(ContratoCard):
alertas: List[Alerta] = []
timeline: List[TimelineItem] = []
class Paginacao(BaseModel):
total: int
page: int
page_size: int
class ListaContratos(BaseModel):
data: List[ContratoCard]
pagination: Paginacao

MOCK: Dict[str, ContratoDetalhe] = {
"CT-2025-001": ContratoDetalhe(
id="CT-2025-001", orgao="Secretaria de Saúde", fornecedor_cnpj="12.345.678/0001-99",
fornecedor_nome="Clínica ABC LTDA", objeto="Serviços de exames de imagem",
valor_inicial=450000.0, dt_assinatura=date(2025,3,12), score=86,
alertas=[Alerta(regra="Aditivo > 25%", severidade="Alta", resumo="Aditivos somam 38%", pagina=6)],
timeline=[TimelineItem(t=date(2025,1,22), e="Edital publicado"), TimelineItem(t=date(2025,3,12), e="Contrato assinado")]
),
"CT-2025-021": ContratoDetalhe(
id="CT-2025-021", orgao="Secretaria de Administração", fornecedor_cnpj="11.222.333/0001-44",
fornecedor_nome="Comercial XYZ ME", objeto="Materiais de escritório",
valor_inicial=88000.0, dt_assinatura=date(2025,5,19), score=34, alertas=[], timeline=[]
),
}

@app.get("/health")
def health(): return {"status":"ok"}

@app.get("/contratos", response_model=ListaContratos)
def listar_contratos(page: int=1, page_size: int=10, orgao: Optional[str]=None, q: Optional[str]=None, min_score: int=0):
items = list(MOCK.values())
if orgao and orgao.lower() != "todos":
items = [c for c in items if c.orgao.lower() == orgao.lower()]
if q:
ql = q.lower()
items = [c for c in items if ql in c.id.lower() or ql in c.objeto.lower()]
if min_score:
items = [c for c in items if c.score >= min_score]
total = len(items)
start = (page-1)*page_size
slice_ = [ContratoCard(**c.dict()) for c in items[start:start+page_size]]
return ListaContratos(data=slice_, pagination=Paginacao(total=total, page=page, page_size=page_size))

@app.get("/contratos/{id}", response_model=ContratoDetalhe)
def obter_contrato(id: str):
c = MOCK.get(id)
if not c:
raise HTTPException(404, "Contrato não encontrado")
return c

@app.get("/empenhos/{id}")
def empenhos(id: str):
return {
"id_contrato": id,
"serie_pagamentos": [{"mes":"2025-01","pago": 120000}, {"mes":"2025-02","pago": 80000}, {"mes":"2025-03","pago": 100000}],
"serie_producao": [{"mes":"2025-01","quantidade": 350}, {"mes":"2025-02","quantidade": 280}, {"mes":"2025-03","quantidade": 310}],
}

@app.get("/fornecedores/participacao")
def participacao(orgao: Optional[str]=None, meses: int=12):
return {
"orgao": orgao or "Todos",
"meses": meses,
"dados": [
{"cnpj":"12.345.678/0001-99", "nome":"Clínica ABC LTDA", "participacao_percentual": 65.2},
{"cnpj":"11.222.333/0001-44", "nome":"Comercial XYZ ME", "participacao_percentual": 34.8},
]
}

from fastapi.responses import Response
@app.get("/export/contratos.csv")
def export_csv(orgao: Optional[str]=None):
items = list(MOCK.values())
if orgao and orgao.lower()!="todos":
items = [c for c in items if c.orgao.lower()==orgao.lower()]
buf = io.StringIO()
w = csv.writer(buf)
w.writerow(["id","orgao","fornecedor_cnpj","fornecedor_nome","objeto","valor_inicial","dt_assinatura","score"])
for c in items:
w.writerow([c.id, c.orgao, c.fornecedor_cnpj, c.fornecedor_nome, c.objeto, c.valor_inicial, c.dt_assinatura.isoformat(), c.score])
return Response(content=buf.getvalue(), media_type="text/csv; charset=utf-8", headers={"Content-Disposition":"attachment; filename=contratos.csv"})

class DossieRequest(BaseModel):
contratos: List[str]
incluir_evidencias: bool = True
idioma: Literal["pt-BR","en-US"] = "pt-BR"
class DossieResponse(BaseModel):
relatorio_id: str
url_download: str

@app.post("/relatorios/dossie", response_model=DossieResponse, dependencies=[Depends(require_roles(["ADMIN","ANALYST"]))])
def gerar_dossie(req: DossieRequest):
if not req.contratos:
raise HTTPException(400, "Informe ao menos um contrato")
rid = "REL-" + "-".join(req.contratos)
return DossieResponse(relatorio_id=rid, url_download=f"https://example.com/reports/{rid}.pdf
")

Rotas de configuração protegidas

app.include_router(config_router)
'

write_file "api/seed_users.py" '
import os
from passlib.context import CryptContext
from sqlalchemy import insert, select
from db import SessionLocal
from models import User, Role, UserRole

pwd = CryptContext(schemes=["bcrypt"], deprecated="auto")
PASSWORD = os.getenv("SEED_PASSWORD", "secret")
USERS = [("admin", ["ADMIN"]), ("analyst", ["ANALYST"]), ("viewer", ["VIEWER"])]
ROLES = ["ADMIN","ANALYST","VIEWER"]

with SessionLocal() as db:
role_ids = {}
for r in ROLES:
row = db.execute(select(Role).where(Role.name==r)).scalar_one_or_none()
if not row:
rid = db.execute(insert(Role).values(name=r).returning(Role.id)).scalar_one()
role_ids[r] = rid
else:
role_ids[r] = row.id
print("Seed concluído.")
'

Alembic basics

write_file "api/alembic.ini" '
[alembic]
script_location = alembic
sqlalchemy.url = postgresql+psycopg://app:app@db:5432/fiscalizadora
'

write_file "api/alembic/env.py" '
from logging.config import fileConfig
from sqlalchemy import engine_from_config, pool
from alembic import context

config = context.config
if config.config_file_name is not None:
fileConfig(config.config_file_name)

target_metadata = None

def run_migrations_offline():
url = config.get_main_option("sqlalchemy.url")
context.configure(url=url, literal_binds=True)
with context.begin_transaction():
context.run_migrations()

def run_migrations_online():
connectable = engine_from_config(
config.get_section(config.config_ini_section),
prefix="sqlalchemy.",
poolclass=pool.NullPool,
)
with connectable.connect() as connection:
context.configure(connection=connection)
with context.begin_transaction():
context.run_migrations()

if context.is_offline_mode():
run_migrations_offline()
else:
run_migrations_online()
'

write_file "api/alembic/versions/20250901_0001_init_auth.py" '
from alembic import op
import sqlalchemy as sa

revision = "20250901_0001_init_auth"
down_revision = None

def upgrade():
op.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto;")
op.execute("CREATE SCHEMA IF NOT EXISTS auth;")
op.create_table(
"users",
sa.Column("id", sa.UUID(), primary_key=True, server_default=sa.text("gen_random_uuid()")),
sa.Column("username", sa.Text(), nullable=False, unique=True),
sa.Column("password_hash", sa.Text(), nullable=False),
sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
sa.Column("created_at", sa.TIMESTAMP(), nullable=False, server_default=sa.text("now()")),
schema="auth",
)
op.create_table(
"roles",
sa.Column("id", sa.Integer(), primary_key=True),
sa.Column("name", sa.Text(), nullable=False, unique=True),
schema="auth",
)
op.create_table(
"user_roles",
sa.Column("user_id", sa.UUID(), sa.ForeignKey("auth.users.id", ondelete="CASCADE"), primary_key=True),
sa.Column("role_id", sa.Integer(), sa.ForeignKey("auth.roles.id", ondelete="CASCADE"), primary_key=True),
schema="auth",
)
op.create_index("idx_users_username", "users", ["username"], schema="auth")

def downgrade():
op.drop_index("idx_users_username", table_name="users", schema="auth")
op.drop_table("user_roles", schema="auth")
op.drop_table("roles", schema="auth")
op.drop_table("users", schema="auth")
'

write_file "api/alembic/versions/20250902_0002_fontes.py" '
from alembic import op
import sqlalchemy as sa

revision = "20250902_0002_fontes"
down_revision = "20250901_0001_init_auth"

def upgrade():
op.execute("CREATE SCHEMA IF NOT EXISTS config;")
op.create_table(
"fontes",
sa.Column("id", sa.Integer(), primary_key=True),
sa.Column("nome", sa.String(length=100), nullable=False),
sa.Column("url", sa.Text(), nullable=False),
sa.Column("ativo", sa.Boolean(), nullable=False, server_default=sa.text("true")),
sa.Column("criado_em", sa.TIMESTAMP(), nullable=False, server_default=sa.text("now()")),
schema="config",
)
op.create_unique_constraint("uq_fontes_nome", "fontes", ["nome"], schema="config")

def downgrade():
op.drop_constraint("uq_fontes_nome", "fontes", type_="unique", schema="config")
op.drop_table("fontes", schema="config")
'

---------------- WEB ----------------

write_file "web/Dockerfile" '
FROM node:20-alpine
WORKDIR /app
COPY package.json package-lock.json* pnpm-lock.yaml* yarn.lock* ./
RUN npm ci || yarn || pnpm i
COPY . .
EXPOSE 3000
CMD ["npm", "run", "dev"]
'

write_file "web/package.json" '
{
"name": "ia-fiscalizadora-web",
"private": true,
"version": "0.1.0",
"scripts": {
"dev": "next dev -p 3000",
"build": "next build",
"start": "next start -p 3000"
},
"dependencies": {
"next": "14.2.5",
"react": "18.3.1",
"react-dom": "18.3.1",
"recharts": "2.12.7",
"lucide-react": "0.468.0"
},
"devDependencies": {
"typescript": "5.4.5",
"@types/react": "18.3.3",
"@types/node": "20.12.12"
}
}
'

write_file "web/next.config.js" 'module.exports = {}'

write_file "web/tsconfig.json" '
{
"compilerOptions": {
"target": "ES2020",
"lib": ["dom", "dom.iterable", "esnext"],
"allowJs": true,
"skipLibCheck": true,
"strict": false,
"forceConsistentCasingInFileNames": true,
"noEmit": true,
"esModuleInterop": true,
"module": "esnext",
"moduleResolution": "bundler",
"resolveJsonModule": true,
"isolatedModules": true,
"jsx": "preserve",
"incremental": true,
"types": ["node"]
},
"include": ["next-env.d.ts", "/*.ts", "/*.tsx"],
"exclude": ["node_modules"]
}
'

write_file "web/styles.css" '

{ box-sizing: border-box; }
body { margin: 0; font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Ubuntu, Cantarell, Helvetica, Arial; }
input, select, textarea, button { outline: none; }
table { border-collapse: collapse; width: 100%; }
th, td { padding: 0.5rem; }
'

write_file "web/context/AuthContext.tsx" '
import React, { createContext, useContext, useEffect, useState } from "react";

interface AuthCtx {
token: string | null;
roles: string[];
login: (u: string, p: string) => Promise<void>;
logout: () => void;
hasRole: (...r: string[]) => boolean;
}

const Ctx = createContext<AuthCtx>({ token: null, roles: [], login: async () => {}, logout: () => {}, hasRole: () => false });
const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000
";

export function AuthProvider({ children }: { children: React.ReactNode }) {
const [token, setToken] = useState<string | null>(null);
const [roles, setRoles] = useState<string[]>([]);

async function fetchMe(tok: string) {
try {
const res = await fetch(${API_BASE}/auth/me, { headers: { Authorization: Bearer ${tok} } });
if (res.ok) {
const js = await res.json();
setRoles(js.roles || []);
} else {
setRoles([]);
}
} catch { setRoles([]); }
}

useEffect(() => {
const t = localStorage.getItem("token");
if (t) { setToken(t); fetchMe(t); }
}, []);

const login = async (username: string, password: string) => {
const res = await fetch(${API_BASE}/auth/login, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ username, password }) });
if (!res.ok) throw new Error("Login falhou");
const js = await res.json();
localStorage.setItem("token", js.access_token);
setToken(js.access_token);
await fetchMe(js.access_token);
};
const logout = () => { localStorage.removeItem("token"); setToken(null); setRoles([]); };
const hasRole = (...r: string[]) => roles.some((x) => r.includes(x));

return <Ctx.Provider value={{ token, roles, login, logout, hasRole }}>{children}</Ctx.Provider>;
}

export function useAuth() { return useContext(Ctx); }
'

write_file "web/components/RequireAuth.tsx" '
import React, { useEffect } from "react";
import { useAuth } from "../context/AuthContext";
import { useRouter } from "next/router";

export default function RequireAuth({ children }: { children: React.ReactNode }) {
const { token } = useAuth();
const r = useRouter();
useEffect(() => { if (!token) r.replace("/login"); }, [token]);
if (!token) return null;
return <>{children}</>;
}
'

write_file "web/components/RoleGate.tsx" '
import React from "react";
import { useAuth } from "../context/AuthContext";

export default function RoleGate({ roles, children }: { roles: string[]; children: React.ReactNode }) {
const { hasRole } = useAuth();
if (!hasRole(...roles)) return null;
return <>{children}</>;
}
'

write_file "web/components/PainelRBAC.tsx" '
import React, { useEffect, useMemo, useState } from "react";
import { AlertTriangle, FileText, Search, Filter, ChevronRight, Download, LogOut } from "lucide-react";
import { LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer, Legend, BarChart, Bar, CartesianGrid } from "recharts";
import RoleGate from "../components/RoleGate";
import { useAuth } from "../context/AuthContext";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000
";

interface Alerta { regra: string; severidade: "Baixa" | "Média" | "Alta"; resumo: string; pagina?: number; fonte_url?: string }
interface TimelineItem { t: string; e: string }
interface ContratoCard { id: string; orgao: string; fornecedor_cnpj: string; fornecedor_nome: string; objeto: string; valor_inicial: number; dt_assinatura: string; score: number }
interface ContratoDetalhe extends ContratoCard { alertas: Alerta[]; timeline: TimelineItem[] }
interface Pagination { total: number; page: number; page_size: number }
interface ListaContratos { data: ContratoCard[]; pagination: Pagination }
interface ParticipacaoResponse { orgao: string; meses: number; dados: { cnpj: string; nome: string; participacao_percentual: number }[] }

async function listContratos(params: { orgao?: string; q?: string; min_score?: number; page?: number; page_size?: number } = {}): Promise<ListaContratos> {
const url = new URL(${API_BASE}/contratos);
Object.entries(params).forEach(([k, v]) => { if (v !== undefined && v !== null && v !== "") url.searchParams.set(k, String(v)); });
const res = await fetch(url.toString(), { cache: "no-store" }); if (!res.ok) throw new Error(Erro ao listar contratos: ${res.status}); return res.json();
}
async function getContrato(id: string): Promise<ContratoDetalhe> { const res = await fetch(${API_BASE}/contratos/${id}, { cache: "no-store" }); if (!res.ok) throw new Error("Contrato não encontrado"); return res.json(); }
async function getEmpenhos(id: string): Promise<{ id_contrato: string; serie_pagamentos: { mes: string; pago: number }[]; serie_producao: { mes: string; quantidade: number }[] }> { const res = await fetch(${API_BASE}/empenhos/${id}, { cache: "no-store" }); if (!res.ok) throw new Error("Falha ao carregar séries"); return res.json(); }
async function getParticipacao(orgao: string): Promise<ParticipacaoResponse> { const url = new URL(${API_BASE}/fornecedores/participacao); if (orgao && orgao !== "Todos") url.searchParams.set("orgao", orgao); const res = await fetch(url.toString(), { cache: "no-store" }); if (!res.ok) throw new Error("Falha ao carregar participação"); return res.json(); }
async function postDossie(contratos: string[]): Promise<{ relatorio_id: string; url_download: string }> { const res = await fetch(${API_BASE}/relatorios/dossie, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ contratos, incluir_evidencias: true, idioma: "pt-BR" }) }); if (!res.ok) throw new Error(Erro ao gerar dossiê: ${res.status}); return res.json(); }

function Badge({ children, tone = "default" }: { children: React.ReactNode; tone?: "default" | "high" | "medium" | "low" }) { const tones: Record<string, string> = { default: "bg-gray-100 text-gray-700", high: "bg-red-100 text-red-700", medium: "bg-amber-100 text-amber-700", low: "bg-blue-100 text-blue-700" }; return <span className={px-2 py-1 rounded-full text-xs font-medium ${tones[tone]}}>{children}</span>; }
function Card({ children }: { children: React.ReactNode }) { return <div className="rounded-2xl border p-4 shadow-sm bg-white">{children}</div>; }
function RiskChip({ score }: { score: number }) { const tone = score >= 80 ? "text-red-600 bg-red-50" : score >= 60 ? "text-amber-700 bg-amber-50" : "text-gray-700 bg-gray-50"; return (<span className={inline-flex items-center gap-2 rounded-full px-3 py-1 text-sm font-semibold ${tone}}><AlertTriangle className="h-4 w-4" /> Score {score}</span>); }

function Row({ c, onOpen }: { c: ContratoCard; onOpen: (id: string) => void }) {
return (
<tr className="hover:bg-gray-50">
<td className="py-3 pl-4 pr-2 text-sm font-medium text-gray-900">{c.id}</td>
<td className="py-3 px-2 text-sm text-gray-600">{c.orgao}</td>
<td className="py-3 px-2 text-sm text-gray-900">{c.fornecedor_nome}</td>
<td className="py-3 px-2 text-sm text-gray-600 truncate max-w-[360px]" title={c.objeto}>{c.objeto}</td>
<td className="py-3 px-2 text-sm text-gray-900">R$ {c.valor_inicial.toLocaleString("pt-BR")}</td>
<td className="py-3 px-2"><RiskChip score={c.score} /></td>
<td className="py-3 pr-4 text-right">
<button onClick={() => onOpen(c.id)} className="inline-flex items-center gap-1 rounded-xl border px-3 py-1.5 text-sm hover:bg-gray-50">Detalhar <ChevronRight className="h-4 w-4" /></button>
</td>
</tr>
);
}

export default function PainelRBAC() {
const { token, roles, logout } = useAuth();
const [query, setQuery] = useState("");
const [orgao, setOrgao] = useState("Todos");
const [minScore, setMinScore] = useState(0);
const [page, setPage] = useState(1);
const [data, setData] = useState<ContratoCard[]>([]);
const [total, setTotal] = useState(0);
const [loading, setLoading] = useState(false);
const [error, setError] = useState<string | null>(null);
const [open, setOpen] = useState(false);
const [current, setCurrent] = useState<ContratoDetalhe | null>(null);
const pageSize = 10;

useEffect(() => {
setLoading(true); setError(null);
listContratos({ orgao: orgao === "Todos" ? undefined : orgao, q: query, min_score: minScore, page, page_size: pageSize })
.then((res) => { setData(res.data); setTotal(res.pagination.total); })
.catch((e) => setError(e.message))
.finally(() => setLoading(false));
}, [query, orgao, minScore, page]);

const contratos = useMemo(() => data, [data]);
const handleOpen = async (id: string) => {
try { setLoading(true); const det = await getContrato(id); setCurrent(det); setOpen(true); }
catch (e: any) { setError(e.message); }
finally { setLoading(false); }
};

return (
<div className="min-h-screen bg-gray-100 p-6">
<div className="mx-auto max-w-7xl space-y-6">
<header className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
<div>
<h1 className="text-2xl font-bold">IA Fiscalizadora – Painel (RBAC)</h1>
<p className="text-gray-600">API: {API_BASE}</p>
</div>
<div className="flex items-center gap-2">
<RoleGate roles={["ADMIN"]}><a href="/users" className="rounded-xl border px-3 py-2 text-sm bg-white">Usuários</a></RoleGate>
<RoleGate roles={["ADMIN"]}><a href="/config/fontes" className="rounded-xl border px-3 py-2 text-sm bg-white">Configurações</a></RoleGate>
<div className="ml-2 inline-flex items-center gap-2 text-sm text-gray-700">
<span>{roles.length ? roles.join(", ") : "sem papéis"}</span>
{token && <button onClick={logout} className="inline-flex items-center gap-1 rounded-xl border px-2 py-1"><LogOut className="h-4 w-4"/>Sair</button>}
</div>
</div>
</header>
print("Seed concluído.")
'

Alembic basics

write_file "api/alembic.ini" '
[alembic]
script_location = alembic
sqlalchemy.url = postgresql+psycopg://app:app@db:5432/fiscalizadora
'

write_file "api/alembic/env.py" '
from logging.config import fileConfig
from sqlalchemy import engine_from_config, pool
from alembic import context

config = context.config
if config.config_file_name is not None:
fileConfig(config.config_file_name)

target_metadata = None

def run_migrations_offline():
url = config.get_main_option("sqlalchemy.url")
context.configure(url=url, literal_binds=True)
with context.begin_transaction():
context.run_migrations()

def run_migrations_online():
connectable = engine_from_config(
config.get_section(config.config_ini_section),
prefix="sqlalchemy.",
poolclass=pool.NullPool,
)
with connectable.connect() as connection:
context.configure(connection=connection)
with context.begin_transaction():
context.run_migrations()

if context.is_offline_mode():
run_migrations_offline()
else:
run_migrations_online()
'

write_file "api/alembic/versions/20250901_0001_init_auth.py" '
from alembic import op
import sqlalchemy as sa

revision = "20250901_0001_init_auth"
down_revision = None

def upgrade():
op.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto;")
op.execute("CREATE SCHEMA IF NOT EXISTS auth;")
op.create_table(
"users",
sa.Column("id", sa.UUID(), primary_key=True, server_default=sa.text("gen_random_uuid()")),
sa.Column("username", sa.Text(), nullable=False, unique=True),
sa.Column("password_hash", sa.Text(), nullable=False),
sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
sa.Column("created_at", sa.TIMESTAMP(), nullable=False, server_default=sa.text("now()")),
schema="auth",
)
op.create_table(
"roles",
sa.Column("id", sa.Integer(), primary_key=True),
sa.Column("name", sa.Text(), nullable=False, unique=True),
schema="auth",
)
op.create_table(
"user_roles",
sa.Column("user_id", sa.UUID(), sa.ForeignKey("auth.users.id", ondelete="CASCADE"), primary_key=True),
sa.Column("role_id", sa.Integer(), sa.ForeignKey("auth.roles.id", ondelete="CASCADE"), primary_key=True),
schema="auth",
)
op.create_index("idx_users_username", "users", ["username"], schema="auth")

def downgrade():
op.drop_index("idx_users_username", table_name="users", schema="auth")
op.drop_table("user_roles", schema="auth")
op.drop_table("roles", schema="auth")
op.drop_table("users", schema="auth")
'

write_file "api/alembic/versions/20250902_0002_fontes.py" '
from alembic import op
import sqlalchemy as sa

revision = "20250902_0002_fontes"
down_revision = "20250901_0001_init_auth"

def upgrade():
op.execute("CREATE SCHEMA IF NOT EXISTS config;")
op.create_table(
"fontes",
sa.Column("id", sa.Integer(), primary_key=True),
sa.Column("nome", sa.String(length=100), nullable=False),
sa.Column("url", sa.Text(), nullable=False),
sa.Column("ativo", sa.Boolean(), nullable=False, server_default=sa.text("true")),
sa.Column("criado_em", sa.TIMESTAMP(), nullable=False, server_default=sa.text("now()")),
schema="config",
)
op.create_unique_constraint("uq_fontes_nome", "fontes", ["nome"], schema="config")

def downgrade():
op.drop_constraint("uq_fontes_nome", "fontes", type_="unique", schema="config")
op.drop_table("fontes", schema="config")
'

---------------- WEB ----------------

write_file "web/Dockerfile" '
FROM node:20-alpine
WORKDIR /app
COPY package.json package-lock.json* pnpm-lock.yaml* yarn.lock* ./
RUN npm ci || yarn || pnpm i
COPY . .
EXPOSE 3000
CMD ["npm", "run", "dev"]
'

write_file "web/package.json" '
{
"name": "ia-fiscalizadora-web",
"private": true,
"version": "0.1.0",
"scripts": {
"dev": "next dev -p 3000",
"build": "next build",
"start": "next start -p 3000"
},
"dependencies": {
"next": "14.2.5",
"react": "18.3.1",
"react-dom": "18.3.1",
"recharts": "2.12.7",
"lucide-react": "0.468.0"
},
"devDependencies": {
"typescript": "5.4.5",
"@types/react": "18.3.3",
"@types/node": "20.12.12"
}
}
'

write_file "web/next.config.js" 'module.exports = {}'

write_file "web/tsconfig.json" '
{
"compilerOptions": {
"target": "ES2020",
"lib": ["dom", "dom.iterable", "esnext"],
"allowJs": true,
"skipLibCheck": true,
"strict": false,
"forceConsistentCasingInFileNames": true,
"noEmit": true,
"esModuleInterop": true,
"module": "esnext",
"moduleResolution": "bundler",
"resolveJsonModule": true,
"isolatedModules": true,
"jsx": "preserve",
"incremental": true,
"types": ["node"]
},
"include": ["next-env.d.ts", "/*.ts", "/*.tsx"],
"exclude": ["node_modules"]
}
'

write_file "web/styles.css" '

{ box-sizing: border-box; }
body { margin: 0; font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Ubuntu, Cantarell, Helvetica, Arial; }
input, select, textarea, button { outline: none; }
table { border-collapse: collapse; width: 100%; }
th, td { padding: 0.5rem; }
'

write_file "web/context/AuthContext.tsx" '
import React, { createContext, useContext, useEffect, useState } from "react";

interface AuthCtx {
token: string | null;
roles: string[];
login: (u: string, p: string) => Promise<void>;
logout: () => void;
hasRole: (...r: string[]) => boolean;
}

const Ctx = createContext<AuthCtx>({ token: null, roles: [], login: async () => {}, logout: () => {}, hasRole: () => false });
const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000
";

export function AuthProvider({ children }: { children: React.ReactNode }) {
const [token, setToken] = useState<string | null>(null);
const [roles, setRoles] = useState<string[]>([]);

async function fetchMe(tok: string) {
try {
const res = await fetch(${API_BASE}/auth/me, { headers: { Authorization: Bearer ${tok} } });
if (res.ok) {
const js = await res.json();
setRoles(js.roles || []);
} else {
setRoles([]);
}
} catch { setRoles([]); }
}

useEffect(() => {
const t = localStorage.getItem("token");
if (t) { setToken(t); fetchMe(t); }
}, []);

const login = async (username: string, password: string) => {
const res = await fetch(${API_BASE}/auth/login, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ username, password }) });
if (!res.ok) throw new Error("Login falhou");
const js = await res.json();
localStorage.setItem("token", js.access_token);
setToken(js.access_token);
await fetchMe(js.access_token);
};
const logout = () => { localStorage.removeItem("token"); setToken(null); setRoles([]); };
const hasRole = (...r: string[]) => roles.some((x) => r.includes(x));

return <Ctx.Provider value={{ token, roles, login, logout, hasRole }}>{children}</Ctx.Provider>;
}

export function useAuth() { return useContext(Ctx); }
'

write_file "web/components/RequireAuth.tsx" '
import React, { useEffect } from "react";
import { useAuth } from "../context/AuthContext";
import { useRouter } from "next/router";

export default function RequireAuth({ children }: { children: React.ReactNode }) {
const { token } = useAuth();
const r = useRouter();
useEffect(() => { if (!token) r.replace("/login"); }, [token]);
if (!token) return null;
return <>{children}</>;
}
'

write_file "web/components/RoleGate.tsx" '
import React from "react";
import { useAuth } from "../context/AuthContext";

export default function RoleGate({ roles, children }: { roles: string[]; children: React.ReactNode }) {
const { hasRole } = useAuth();
if (!hasRole(...roles)) return null;
return <>{children}</>;
}
'

write_file "web/components/PainelRBAC.tsx" '
import React, { useEffect, useMemo, useState } from "react";
import { AlertTriangle, FileText, Search, Filter, ChevronRight, Download, LogOut } from "lucide-react";
import { LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer, Legend, BarChart, Bar, CartesianGrid } from "recharts";
import RoleGate from "../components/RoleGate";
import { useAuth } from "../context/AuthContext";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000
";

interface Alerta { regra: string; severidade: "Baixa" | "Média" | "Alta"; resumo: string; pagina?: number; fonte_url?: string }
interface TimelineItem { t: string; e: string }
interface ContratoCard { id: string; orgao: string; fornecedor_cnpj: string; fornecedor_nome: string; objeto: string; valor_inicial: number; dt_assinatura: string; score: number }
interface ContratoDetalhe extends ContratoCard { alertas: Alerta[]; timeline: TimelineItem[] }
interface Pagination { total: number; page: number; page_size: number }
interface ListaContratos { data: ContratoCard[]; pagination: Pagination }
interface ParticipacaoResponse { orgao: string; meses: number; dados: { cnpj: string; nome: string; participacao_percentual: number }[] }

async function listContratos(params: { orgao?: string; q?: string; min_score?: number; page?: number; page_size?: number } = {}): Promise<ListaContratos> {
const url = new URL(${API_BASE}/contratos);
Object.entries(params).forEach(([k, v]) => { if (v !== undefined && v !== null && v !== "") url.searchParams.set(k, String(v)); });
const res = await fetch(url.toString(), { cache: "no-store" }); if (!res.ok) throw new Error(Erro ao listar contratos: ${res.status}); return res.json();
}
async function getContrato(id: string): Promise<ContratoDetalhe> { const res = await fetch(${API_BASE}/contratos/${id}, { cache: "no-store" }); if (!res.ok) throw new Error("Contrato não encontrado"); return res.json(); }
async function getEmpenhos(id: string): Promise<{ id_contrato: string; serie_pagamentos: { mes: string; pago: number }[]; serie_producao: { mes: string; quantidade: number }[] }> { const res = await fetch(${API_BASE}/empenhos/${id}, { cache: "no-store" }); if (!res.ok) throw new Error("Falha ao carregar séries"); return res.json(); }
async function getParticipacao(orgao: string): Promise<ParticipacaoResponse> { const url = new URL(${API_BASE}/fornecedores/participacao); if (orgao && orgao !== "Todos") url.searchParams.set("orgao", orgao); const res = await fetch(url.toString(), { cache: "no-store" }); if (!res.ok) throw new Error("Falha ao carregar participação"); return res.json(); }
async function postDossie(contratos: string[]): Promise<{ relatorio_id: string; url_download: string }> { const res = await fetch(${API_BASE}/relatorios/dossie, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ contratos, incluir_evidencias: true, idioma: "pt-BR" }) }); if (!res.ok) throw new Error(Erro ao gerar dossiê: ${res.status}); return res.json(); }

function Badge({ children, tone = "default" }: { children: React.ReactNode; tone?: "default" | "high" | "medium" | "low" }) { const tones: Record<string, string> = { default: "bg-gray-100 text-gray-700", high: "bg-red-100 text-red-700", medium: "bg-amber-100 text-amber-700", low: "bg-blue-100 text-blue-700" }; return <span className={px-2 py-1 rounded-full text-xs font-medium ${tones[tone]}}>{children}</span>; }
function Card({ children }: { children: React.ReactNode }) { return <div className="rounded-2xl border p-4 shadow-sm bg-white">{children}</div>; }
function RiskChip({ score }: { score: number }) { const tone = score >= 80 ? "text-red-600 bg-red-50" : score >= 60 ? "text-amber-700 bg-amber-50" : "text-gray-700 bg-gray-50"; return (<span className={inline-flex items-center gap-2 rounded-full px-3 py-1 text-sm font-semibold ${tone}}><AlertTriangle className="h-4 w-4" /> Score {score}</span>); }

function Row({ c, onOpen }: { c: ContratoCard; onOpen: (id: string) => void }) {
return (
<tr className="hover:bg-gray-50">
<td className="py-3 pl-4 pr-2 text-sm font-medium text-gray-900">{c.id}</td>
<td className="py-3 px-2 text-sm text-gray-600">{c.orgao}</td>
<td className="py-3 px-2 text-sm text-gray-900">{c.fornecedor_nome}</td>
<td className="py-3 px-2 text-sm text-gray-600 truncate max-w-[360px]" title={c.objeto}>{c.objeto}</td>
<td className="py-3 px-2 text-sm text-gray-900">R$ {c.valor_inicial.toLocaleString("pt-BR")}</td>
<td className="py-3 px-2"><RiskChip score={c.score} /></td>
<td className="py-3 pr-4 text-right">
<button onClick={() => onOpen(c.id)} className="inline-flex items-center gap-1 rounded-xl border px-3 py-1.5 text-sm hover:bg-gray-50">Detalhar <ChevronRight className="h-4 w-4" /></button>
</td>
</tr>
);
}

export default function PainelRBAC() {
const { token, roles, logout } = useAuth();
const [query, setQuery] = useState("");
const [orgao, setOrgao] = useState("Todos");
const [minScore, setMinScore] = useState(0);
const [page, setPage] = useState(1);
const [data, setData] = useState<ContratoCard[]>([]);
const [total, setTotal] = useState(0);
const [loading, setLoading] = useState(false);
const [error, setError] = useState<string | null>(null);
const [open, setOpen] = useState(false);
const [current, setCurrent] = useState<ContratoDetalhe | null>(null);
const pageSize = 10;

useEffect(() => {
setLoading(true); setError(null);
listContratos({ orgao: orgao === "Todos" ? undefined : orgao, q: query, min_score: minScore, page, page_size: pageSize })
.then((res) => { setData(res.data); setTotal(res.pagination.total); })
.catch((e) => setError(e.message))
.finally(() => setLoading(false));
}, [query, orgao, minScore, page]);

const contratos = useMemo(() => data, [data]);
const handleOpen = async (id: string) => {
try { setLoading(true); const det = await getContrato(id); setCurrent(det); setOpen(true); }
catch (e: any) { setError(e.message); }
finally { setLoading(false); }
};

return (
<div className="min-h-screen bg-gray-100 p-6">
<div className="mx-auto max-w-7xl space-y-6">
<header className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
<div>
<h1 className="text-2xl font-bold">IA Fiscalizadora – Painel (RBAC)</h1>
<p className="text-gray-600">API: {API_BASE}</p>
</div>
<div className="flex items-center gap-2">
<RoleGate roles={["ADMIN"]}><a href="/users" className="rounded-xl border px-3 py-2 text-sm bg-white">Usuários</a></RoleGate>
<RoleGate roles={["ADMIN"]}><a href="/config/fontes" className="rounded-xl border px-3 py-2 text-sm bg-white">Configurações</a></RoleGate>
<div className="ml-2 inline-flex items-center gap-2 text-sm text-gray-700">
<span>{roles.length ? roles.join(", ") : "sem papéis"}</span>
{token && <button onClick={logout} className="inline-flex items-center gap-1 rounded-xl border px-2 py-1"><LogOut className="h-4 w-4"/>Sair</button>}
</div>
</div>
</header>
);
}
'

write_file "web/pages/_app.tsx" '
import type { AppProps } from "next/app";
import { AuthProvider } from "../context/AuthContext";
import "../styles.css";

export default function App({ Component, pageProps }: AppProps) {
return (
<AuthProvider>
<Component {...pageProps} />
</AuthProvider>
);
}
'

write_file "web/pages/index.tsx" '
import React from "react";
import RequireAuth from "../components/RequireAuth";
import PainelRBAC from "../components/PainelRBAC";

export default function Home() {
return (
<RequireAuth>
<PainelRBAC />
</RequireAuth>
);
}
'

write_file "web/pages/login.tsx" '
import React, { useState } from "react";
import { useAuth } from "../context/AuthContext";
import { useRouter } from "next/router";

export default function Login() {
const { login } = useAuth();
const router = useRouter();
const [u, setU] = useState("");
const [p, setP] = useState("");
const [err, setErr] = useState<string | null>(null);
const [loading, setLoading] = useState(false);

return (
<div className="min-h-screen flex items-center justify-center bg-gray-100 p-6">
<div className="w-full max-w-sm rounded-2xl border bg-white p-6 shadow-sm">
<h1 className="text-xl font-semibold">Entrar</h1>
<p className="text-sm text-gray-600">Use admin/analyst/viewer com senha <b>secret</b> (dev).</p>
{err && <div className="mt-3 rounded-md border border-red-200 bg-red-50 p-2 text-xs text-red-700">{err}</div>}
<div className="mt-4 space-y-3">
<input value={u} onChange={(e) => setU(e.target.value)} placeholder="Usuário" className="w-full rounded-xl border px-3 py-2 text-sm" />
<input value={p} onChange={(e) => setP(e.target.value)} placeholder="Senha" type="password" className="w-full rounded-xl border px-3 py-2 text-sm" />
<button onClick={async () => { try { setLoading(true); setErr(null); await login(u, p); router.push("/"); } catch (e: any) { setErr(e.message || "Falha no login"); } finally { setLoading(false); } }} className="w-full rounded-xl border px-3 py-2 text-sm bg-gray-900 text-white disabled:opacity-50" disabled={loading}>Entrar</button>
</div>
</div>
</div>
);
}
'

write_file "web/pages/config/fontes.tsx" '
import React, { useEffect, useState } from "react";
import RequireAuth from "../../components/RequireAuth";
import RoleGate from "../../components/RoleGate";
import { useAuth } from "../../context/AuthContext";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000
";

type Fonte = { id?: number; nome: string; url?: string; ativo: boolean };

function Toast({ type, text }: { type: "success" | "error" | "info"; text: string }) {
const color = type === "success" ? "bg-green-600" : type === "error" ? "bg-red-600" : "bg-gray-800";
return <div className={fixed top-4 right-4 z-[60] rounded-xl px-4 py-3 text-white shadow-lg ${color}}><span className="text-sm font-medium">{text}</span></div>;
}

export default function ConfigFontes() {
const { token } = useAuth();
const [fontes, setFontes] = useState<Fonte[]>([]);
const [loading, setLoading] = useState(false);
const [err, setErr] = useState<string | null>(null);
const [toast, setToast] = useState<{ type: "success" | "error" | "info"; text: string } | null>(null);
const [saving, setSaving] = useState(false);
const [busy, setBusy] = useState<number | null>(null);
const [nome, setNome] = useState("");
const [url, setUrl] = useState("https://pncp.gov.br
");

const showToast = (t: { type: "success" | "error" | "info"; text: string }) => { setToast(t); setTimeout(() => setToast(null), 3000); };

async function load() {
setLoading(true); setErr(null);
try {
const res = await fetch(${API_BASE}/config/fontes, { headers: token ? { Authorization: Bearer ${token} } : {} });
if (!res.ok) throw new Error(Erro ${res.status});
setFontes(await res.json());
} catch (e: any) { setErr(e.message); } finally { setLoading(false); }
}
useEffect(() => { load(); }, []);

async function createFonte() {
try {
setSaving(true);
const res = await fetch(${API_BASE}/config/fontes, { method: "POST", headers: { "Content-Type": "application/json", ...(token ? { Authorization: Bearer ${token} } : {}) }, body: JSON.stringify({ nome: nome.trim(), url }) });
if (!res.ok) throw new Error("Falha ao criar fonte");
await load();
setNome(""); setUrl("https://pncp.gov.br
");
showToast({ type: "success", text: "Fonte criada com sucesso" });
} catch (e: any) { showToast({ type: "error", text: e.message || "Erro ao criar fonte" }); }
finally { setSaving(false); }
}

async function toggleFonte(f: Fonte) {
if (f.id == null) return;
setBusy(f.id);
try {
const res = await fetch(${API_BASE}/config/fontes/${f.id}, { method: "PUT", headers: { "Content-Type": "application/json", ...(token ? { Authorization: Bearer ${token} } : {}) }, body: JSON.stringify({ ativo: !f.ativo }) });
if (!res.ok) throw new Error("Falha ao atualizar fonte");
await load();
showToast({ type: "success", text: ${f.nome} ${f.ativo ? "desativada" : "ativada"} });
} catch (e: any) { showToast({ type: "error", text: e.message || "Erro ao atualizar" }); }
finally { setBusy(null); }
}

async function removeFonte(f: Fonte) {
if (f.id == null) return;
if (!confirm(Remover fonte ${f.nome}?)) return;
setBusy(f.id);
try {
const res = await fetch(${API_BASE}/config/fontes/${f.id}, { method: "DELETE", headers: token ? { Authorization: Bearer ${token} } : {} });
if (res.status !== 204) throw new Error("Falha ao excluir fonte");
await load();
showToast({ type: "success", text: ${f.nome} removida });
} catch (e: any) { showToast({ type: "error", text: e.message || "Erro ao excluir" }); }
finally { setBusy(null); }
}

return (
<RequireAuth>
<RoleGate roles={["ADMIN"]}>
<div className="min-h-screen bg-gray-100 p-6">
<div className="mx-auto max-w-5xl space-y-6">
<header className="flex items-center justify-between">
<h1 className="text-2xl font-bold">Configurações · Fontes</h1>
<a href="/" className="rounded-xl border px-3 py-2 text-sm bg-white">Voltar ao painel</a>
</header>
);
}
'

write_file "web/pages/_app.tsx" '
import type { AppProps } from "next/app";
import { AuthProvider } from "../context/AuthContext";
import "../styles.css";

export default function App({ Component, pageProps }: AppProps) {
return (
<AuthProvider>
<Component {...pageProps} />
</AuthProvider>
);
}
'

write_file "web/pages/index.tsx" '
import React from "react";
import RequireAuth from "../components/RequireAuth";
import PainelRBAC from "../components/PainelRBAC";

export default function Home() {
return (
<RequireAuth>
<PainelRBAC />
</RequireAuth>
);
}
'

write_file "web/pages/login.tsx" '
import React, { useState } from "react";
import { useAuth } from "../context/AuthContext";
import { useRouter } from "next/router";

export default function Login() {
const { login } = useAuth();
const router = useRouter();
const [u, setU] = useState("");
const [p, setP] = useState("");
const [err, setErr] = useState<string | null>(null);
const [loading, setLoading] = useState(false);

return (
<div className="min-h-screen flex items-center justify-center bg-gray-100 p-6">
<div className="w-full max-w-sm rounded-2xl border bg-white p-6 shadow-sm">
<h1 className="text-xl font-semibold">Entrar</h1>
<p className="text-sm text-gray-600">Use admin/analyst/viewer com senha <b>secret</b> (dev).</p>
{err && <div className="mt-3 rounded-md border border-red-200 bg-red-50 p-2 text-xs text-red-700">{err}</div>}
<div className="mt-4 space-y-3">
<input value={u} onChange={(e) => setU(e.target.value)} placeholder="Usuário" className="w-full rounded-xl border px-3 py-2 text-sm" />
<input value={p} onChange={(e) => setP(e.target.value)} placeholder="Senha" type="password" className="w-full rounded-xl border px-3 py-2 text-sm" />
<button onClick={async () => { try { setLoading(true); setErr(null); await login(u, p); router.push("/"); } catch (e: any) { setErr(e.message || "Falha no login"); } finally { setLoading(false); } }} className="w-full rounded-xl border px-3 py-2 text-sm bg-gray-900 text-white disabled:opacity-50" disabled={loading}>Entrar</button>
</div>
</div>
</div>
);
}
'

write_file "web/pages/config/fontes.tsx" '
import React, { useEffect, useState } from "react";
import RequireAuth from "../../components/RequireAuth";
import RoleGate from "../../components/RoleGate";
import { useAuth } from "../../context/AuthContext";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000
";

type Fonte = { id?: number; nome: string; url?: string; ativo: boolean };

function Toast({ type, text }: { type: "success" | "error" | "info"; text: string }) {
const color = type === "success" ? "bg-green-600" : type === "error" ? "bg-red-600" : "bg-gray-800";
return <div className={fixed top-4 right-4 z-[60] rounded-xl px-4 py-3 text-white shadow-lg ${color}}><span className="text-sm font-medium">{text}</span></div>;
}

export default function ConfigFontes() {
const { token } = useAuth();
const [fontes, setFontes] = useState<Fonte[]>([]);
const [loading, setLoading] = useState(false);
const [err, setErr] = useState<string | null>(null);
const [toast, setToast] = useState<{ type: "success" | "error" | "info"; text: string } | null>(null);
const [saving, setSaving] = useState(false);
const [busy, setBusy] = useState<number | null>(null);
const [nome, setNome] = useState("");
const [url, setUrl] = useState("https://pncp.gov.br
");

const showToast = (t: { type: "success" | "error" | "info"; text: string }) => { setToast(t); setTimeout(() => setToast(null), 3000); };

async function load() {
setLoading(true); setErr(null);
try {
const res = await fetch(${API_BASE}/config/fontes, { headers: token ? { Authorization: Bearer ${token} } : {} });
if (!res.ok) throw new Error(Erro ${res.status});
setFontes(await res.json());
} catch (e: any) { setErr(e.message); } finally { setLoading(false); }
}
useEffect(() => { load(); }, []);

async function createFonte() {
try {
setSaving(true);
const res = await fetch(${API_BASE}/config/fontes, { method: "POST", headers: { "Content-Type": "application/json", ...(token ? { Authorization: Bearer ${token} } : {}) }, body: JSON.stringify({ nome: nome.trim(), url }) });
if (!res.ok) throw new Error("Falha ao criar fonte");
await load();
setNome(""); setUrl("https://pncp.gov.br
");
showToast({ type: "success", text: "Fonte criada com sucesso" });
} catch (e: any) { showToast({ type: "error", text: e.message || "Erro ao criar fonte" }); }
finally { setSaving(false); }
}

async function toggleFonte(f: Fonte) {
if (f.id == null) return;
setBusy(f.id);
try {
const res = await fetch(${API_BASE}/config/fontes/${f.id}, { method: "PUT", headers: { "Content-Type": "application/json", ...(token ? { Authorization: Bearer ${token} } : {}) }, body: JSON.stringify({ ativo: !f.ativo }) });
if (!res.ok) throw new Error("Falha ao atualizar fonte");
await load();
showToast({ type: "success", text: ${f.nome} ${f.ativo ? "desativada" : "ativada"} });
} catch (e: any) { showToast({ type: "error", text: e.message || "Erro ao atualizar" }); }
finally { setBusy(null); }
}

async function removeFonte(f: Fonte) {
if (f.id == null) return;
if (!confirm(Remover fonte ${f.nome}?)) return;
setBusy(f.id);
try {
const res = await fetch(${API_BASE}/config/fontes/${f.id}, { method: "DELETE", headers: token ? { Authorization: Bearer ${token} } : {} });
if (res.status !== 204) throw new Error("Falha ao excluir fonte");
await load();
showToast({ type: "success", text: ${f.nome} removida });
} catch (e: any) { showToast({ type: "error", text: e.message || "Erro ao excluir" }); }
finally { setBusy(null); }
}

return (
<RequireAuth>
<RoleGate roles={["ADMIN"]}>
<div className="min-h-screen bg-gray-100 p-6">
<div className="mx-auto max-w-5xl space-y-6">
<header className="flex items-center justify-between">
<h1 className="text-2xl font-bold">Configurações · Fontes</h1>
<a href="/" className="rounded-xl border px-3 py-2 text-sm bg-white">Voltar ao painel</a>
</header>
);
}
'

write_file "web/pages/users.tsx" '
import React, { useEffect, useState } from "react";
import RequireAuth from "../components/RequireAuth";
import RoleGate from "../components/RoleGate";
import { useAuth } from "../context/AuthContext";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000
";

interface UserRow { id: string; username: string; roles: string[]; is_active: boolean; created_at: string }

export default function UsersPage() {
const { token } = useAuth();
const [rows, setRows] = useState<UserRow[]>([]);
const [loading, setLoading] = useState(false);
const [err, setErr] = useState<string | null>(null);
const [form, setForm] = useState({ username: "", password: "", roles: ["VIEWER"] as string[] });

async function load() {
setLoading(true); setErr(null);
try {
const res = await fetch(${API_BASE}/users, { headers: { Authorization: Bearer ${token} } });
if (!res.ok) throw new Error(Erro ${res.status});
setRows(await res.json());
} catch (e: any) { setErr(e.message); } finally { setLoading(false); }
}
useEffect(() => { load(); }, []);

async function createUser() {
const res = await fetch(${API_BASE}/users, { method: "POST", headers: { "Content-Type": "application/json", Authorization: Bearer ${token} }, body: JSON.stringify(form) });
if (!res.ok) return alert("Falha ao criar usuário");
setForm({ username: "", password: "", roles: ["VIEWER"] });
await load();
}

async function updateRoles(id: string, roles: string[]) {
const res = await fetch(${API_BASE}/users/${id}, { method: "PUT", headers: { "Content-Type": "application/json", Authorization: Bearer ${token} }, body: JSON.stringify({ roles }) });
if (!res.ok) return alert("Falha ao atualizar roles");
await load();
}

async function resetPassword(id: string) {
const np = prompt("Nova senha para o usuário:");
if (!np) return;
const res = await fetch(${API_BASE}/users/${id}, { method: "PUT", headers: { "Content-Type": "application/json", Authorization: Bearer ${token} }, body: JSON.stringify({ password: np }) });
if (!res.ok) return alert("Falha ao resetar senha");
alert("Senha atualizada");
}

async function removeUser(id: string) {
if (!confirm("Remover usuário?")) return;
const res = await fetch(${API_BASE}/users/${id}, { method: "DELETE", headers: { Authorization: Bearer ${token} } });
if (res.status !== 204) return alert("Falha ao deletar");
await load();
}

return (
<RequireAuth>
<RoleGate roles={["ADMIN"]}>
<div className="min-h-screen bg-gray-100 p-6">
<div className="mx-auto max-w-4xl space-y-6">
<header className="flex items-center justify-between"><h1 className="text-2xl font-bold">Usuários</h1></header>
);
}
'

write_file "web/pages/users.tsx" '
import React, { useEffect, useState } from "react";
import RequireAuth from "../components/RequireAuth";
import RoleGate from "../components/RoleGate";
import { useAuth } from "../context/AuthContext";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000
";

interface UserRow { id: string; username: string; roles: string[]; is_active: boolean; created_at: string }

export default function UsersPage() {
const { token } = useAuth();
const [rows, setRows] = useState<UserRow[]>([]);
const [loading, setLoading] = useState(false);
const [err, setErr] = useState<string | null>(null);
const [form, setForm] = useState({ username: "", password: "", roles: ["VIEWER"] as string[] });

async function load() {
setLoading(true); setErr(null);
try {
const res = await fetch(${API_BASE}/users, { headers: { Authorization: Bearer ${token} } });
if (!res.ok) throw new Error(Erro ${res.status});
setRows(await res.json());
} catch (e: any) { setErr(e.message); } finally { setLoading(false); }
}
useEffect(() => { load(); }, []);

async function createUser() {
const res = await fetch(${API_BASE}/users, { method: "POST", headers: { "Content-Type": "application/json", Authorization: Bearer ${token} }, body: JSON.stringify(form) });
if (!res.ok) return alert("Falha ao criar usuário");
setForm({ username: "", password: "", roles: ["VIEWER"] });
await load();
}

async function updateRoles(id: string, roles: string[]) {
const res = await fetch(${API_BASE}/users/${id}, { method: "PUT", headers: { "Content-Type": "application/json", Authorization: Bearer ${token} }, body: JSON.stringify({ roles }) });
if (!res.ok) return alert("Falha ao atualizar roles");
await load();
}

async function resetPassword(id: string) {
const np = prompt("Nova senha para o usuário:");
if (!np) return;
const res = await fetch(${API_BASE}/users/${id}, { method: "PUT", headers: { "Content-Type": "application/json", Authorization: Bearer ${token} }, body: JSON.stringify({ password: np }) });
if (!res.ok) return alert("Falha ao resetar senha");
alert("Senha atualizada");
}

async function removeUser(id: string) {
if (!confirm("Remover usuário?")) return;
const res = await fetch(${API_BASE}/users/${id}, { method: "DELETE", headers: { Authorization: Bearer ${token} } });
if (res.status !== 204) return alert("Falha ao deletar");
await load();
}

return (
<RequireAuth>
<RoleGate roles={["ADMIN"]}>
<div className="min-h-screen bg-gray-100 p-6">
<div className="mx-auto max-w-4xl space-y-6">
<header className="flex items-center justify-between"><h1 className="text-2xl font-bold">Usuários</h1></header>
);
}
'

