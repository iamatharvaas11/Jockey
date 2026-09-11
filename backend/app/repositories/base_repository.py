"""
Generic Async Repository base class for SQLAlchemy models.
"""
from typing import Any, Generic, List, Optional, Type, TypeVar
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete, func

ModelType = TypeVar("ModelType")


class BaseRepository(Generic[ModelType]):
    def __init__(self, model: Type[ModelType], session: AsyncSession):
        self.model = model
        self.session = session

    async def get(self, id: Any) -> Optional[ModelType]:
        result = await self.session.execute(select(self.model).filter(self.model.id == id))
        return result.scalars().first()

    async def list(self, skip: int = 0, limit: int = 100) -> List[ModelType]:
        result = await self.session.execute(select(self.model).offset(skip).limit(limit))
        return list(result.scalars().all())

    async def count(self) -> int:
        result = await self.session.execute(select(func.count()).select_from(self.model))
        return result.scalar() or 0

    async def create(self, entity: ModelType) -> ModelType:
        self.session.add(entity)
        await self.session.commit()
        await self.session.refresh(entity)
        return entity

    async def delete(self, id: Any) -> bool:
        result = await self.session.execute(delete(self.model).filter(self.model.id == id))
        await self.session.commit()
        return bool(result.rowcount > 0)

