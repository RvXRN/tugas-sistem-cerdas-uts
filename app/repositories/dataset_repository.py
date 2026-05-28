from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from app.models.attack import Attack
from app.models.cve import CVE
from app.models.ioc import IoC

class DatasetRepository:
    @staticmethod
    async def get_stats(db: AsyncSession) -> dict:
        attacks_count = await db.scalar(select(func.count(Attack.id)))
        cves_count = await db.scalar(select(func.count(CVE.id)))
        iocs_count = await db.scalar(select(func.count(IoC.id)))

        return {
            "threat_intel": attacks_count or 0,
            "cves": cves_count or 0,
            "iocs": iocs_count or 0
        }
