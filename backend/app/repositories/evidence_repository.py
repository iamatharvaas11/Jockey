from typing import List, Optional
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.evidence import Evidence
from app.repositories.base_repository import BaseRepository


class EvidenceRepository(BaseRepository[Evidence]):
    def __init__(self, session: AsyncSession):
        super().__init__(Evidence, session)

    async def list_by_investigation(
        self,
        investigation_id: Optional[str] = None,
        evidence_type: Optional[str] = None,
        host: Optional[str] = None,
        skip: int = 0,
        limit: int = 100,
    ) -> List[Evidence]:
        stmt = select(Evidence)
        if investigation_id:
            stmt = stmt.filter(Evidence.investigation_id == investigation_id)
        if evidence_type:
            stmt = stmt.filter(Evidence.type == evidence_type.lower())
        if host:
            stmt = stmt.filter(Evidence.host == host)

        stmt = stmt.offset(skip).limit(limit)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

