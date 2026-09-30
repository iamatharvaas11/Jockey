from fastapi import APIRouter

from app.api.v1.endpoints import (
    auth, investigations, endpoints_api, artifacts, iocs, timeline,
    compiler_api, audit_logs, evidence_api, reports_api, relationships_api, stats_api,
    settings_api, health_api, security_api
)

api_router = APIRouter()
api_router.include_router(auth.router, prefix="/auth", tags=["auth"])
api_router.include_router(investigations.router, prefix="/investigations", tags=["investigations"])
api_router.include_router(endpoints_api.router, tags=["endpoints"])
api_router.include_router(artifacts.router, tags=["artifacts"])
api_router.include_router(iocs.router, tags=["iocs"])
api_router.include_router(timeline.router, tags=["timeline"])
api_router.include_router(compiler_api.router, tags=["compiler"])
api_router.include_router(audit_logs.router, prefix="/audit-logs", tags=["audit logs"])
api_router.include_router(audit_logs.router, prefix="/audit", tags=["audit logs"])
api_router.include_router(evidence_api.router)
api_router.include_router(reports_api.router)
api_router.include_router(relationships_api.router)
api_router.include_router(stats_api.router)
api_router.include_router(settings_api.router)
api_router.include_router(health_api.router)
api_router.include_router(security_api.router)

