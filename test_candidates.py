import asyncio
from pulse.ecosystems.package_resolution import PackageResolutionService

async def test():
    s = PackageResolutionService()
    full_res = await s.resolve('Bootstrap', '4.5.2')
    print([c.ecosystem for c in full_res.candidates])
    print([c.ecosystem for c in full_res.alternative_candidates])

if __name__ == "__main__":
    asyncio.run(test())
