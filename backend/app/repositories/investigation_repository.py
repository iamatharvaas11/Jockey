from typing import Optional, List
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.investigation import Investigation
from app.repositories.base_repository import BaseRepository


class InvestigationRepository(BaseRepository[Investigation]):
    def __init__(self, session: AsyncSession):
        super().__init__(Investigation, session)

    async def get_by_case_number(self, case_number: str) -> Optional[Investigation]:
        result = await self.session.execute(select(Investigation).filter(Investigation.case_number == case_number))
        return result.scalars().first()

    async def list_by_status(self, status: str) -> List[Investigation]:
        result = await self.session.execute(select(Investigation).filter(Investigation.status == status))
        return list(result.scalars().all())

