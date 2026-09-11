from typing import Optional
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.user import User
from app.repositories.base_repository import BaseRepository


class UserRepository(BaseRepository[User]):
    def __init__(self, session: AsyncSession):
        super().__init__(User, session)

    async def get_by_email(self, email: str) -> Optional[User]:
        result = await self.session.execute(select(User).filter(User.email == email))
        return result.scalars().first()

    async def count_users(self) -> int:
        result = await self.session.execute(select(func.count()).select_from(User))
        return result.scalar() or 0

