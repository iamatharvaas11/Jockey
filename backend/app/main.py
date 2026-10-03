import sys
import os

# Ensure backend and root project directories are in sys.path
# Note: With proper package installation (pip install -e .) this is technically unnecessary, 
# but it is kept as a fallback since the backend package structure relies on relative imports.
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
BACKEND_DIR = os.path.dirname(CURRENT_DIR)
ROOT_DIR = os.path.dirname(BACKEND_DIR)

if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.core.config import settings
from app.api.v1.api import api_router
from app.db.session import engine
from app.db.base import Base

# Ensure storage directory exists
os.makedirs(settings.STORAGE_DIR, exist_ok=True)

TEMPLATES_DIR = os.path.join(CURRENT_DIR, "templates")
STATIC_DIR = os.path.join(CURRENT_DIR, "static")

os.makedirs(TEMPLATES_DIR, exist_ok=True)
os.makedirs(STATIC_DIR, exist_ok=True)

from app.db.migrations import init_database

@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_database(engine)
    try:
        from app.db.session import AsyncSessionLocal
        from app.services.investigation_ingestion import auto_ingest_latest_output
        async with AsyncSessionLocal() as session:
            await auto_ingest_latest_output(session)
    except Exception as e:
        print(f"[!] Startup ingestion note: {e}")
    yield

app = FastAPI(
    title=settings.PROJECT_NAME,
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router, prefix="/api/v1")

# Frontend routes via Jinja2
templates = Jinja2Templates(directory=TEMPLATES_DIR)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

@app.get("/")
async def root():
    return RedirectResponse(url="/dashboard")

@app.get("/login")
async def login_page(request: Request):
    return templates.TemplateResponse(request=request, name="login.html")

@app.get("/register")
async def register_page(request: Request):
    return templates.TemplateResponse(request=request, name="register.html")

@app.get("/dashboard")
async def dashboard_page(request: Request):
    return templates.TemplateResponse(request=request, name="dashboard.html")

@app.get("/investigations")
async def investigations_page(request: Request):
    return templates.TemplateResponse(request=request, name="investigations/list.html")

@app.get("/investigations/{id}")
async def investigation_detail_page(request: Request, id: str):
    return templates.TemplateResponse(request=request, name="investigations/detail.html", context={"id": id})

@app.get("/investigations/{id}/report")
async def investigation_summary_report_page(request: Request, id: str):
    return templates.TemplateResponse(request=request, name="investigations/summary_report.html", context={"id": id})

@app.get("/editor")
async def editor_page(request: Request):
    return templates.TemplateResponse(request=request, name="editor.html")

@app.get("/reports")
async def reports_page(request: Request):
    return templates.TemplateResponse(request=request, name="reports.html")

@app.get("/audit")
async def audit_page(request: Request):
    return templates.TemplateResponse(request=request, name="audit.html")

@app.get("/endpoints")
async def endpoints_page(request: Request):
    return templates.TemplateResponse(request=request, name="endpoints.html")

@app.get("/evidence")
async def evidence_page(request: Request):
    return templates.TemplateResponse(request=request, name="evidence.html")

@app.get("/iocs")
async def iocs_page(request: Request):
    return templates.TemplateResponse(request=request, name="iocs.html")

@app.get("/relationships")
async def relationships_page(request: Request):
    return templates.TemplateResponse(request=request, name="relationships.html")

@app.get("/timeline")
async def timeline_page(request: Request):
    return templates.TemplateResponse(request=request, name="timeline.html")

@app.get("/health")
async def health_page(request: Request):
    return templates.TemplateResponse(request=request, name="health.html")

@app.get("/settings")
async def settings_page(request: Request):
    return templates.TemplateResponse(request=request, name="settings.html")

@app.get('/security')
async def security_page(request: Request):
    return templates.TemplateResponse(request=request, name='security.html')


def run_server():
    """CLI entrypoint to start the JOCKY server."""
    import uvicorn
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8000"))
    uvicorn.run("backend.app.main:app", host=host, port=port, reload=False)


if __name__ == "__main__":
    run_server()
