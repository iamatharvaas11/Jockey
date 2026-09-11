from datetime import datetime, timezone
from typing import List, Optional
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.endpoint import Endpoint
from app.repositories.base_repository import BaseRepository


class EndpointRepository(BaseRepository[Endpoint]):
    def __init__(self, session: AsyncSession):
        super().__init__(Endpoint, session)

    async def get_by_hostname(self, hostname: str) -> Optional[Endpoint]:
        result = await self.session.execute(select(Endpoint).filter(Endpoint.hostname == hostname))
        return result.scalars().first()

    async def update_heartbeat(self, endpoint_id: str, status: str = "ONLINE") -> Optional[Endpoint]:
        ep = await self.get(endpoint_id)
        if ep:
            ep.agent_status = status
            ep.last_seen = datetime.now(timezone.utc)
            await self.session.commit()
            await self.session.refresh(ep)
        return ep

