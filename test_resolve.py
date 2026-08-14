import httpx
import asyncio
from pulse.ecosystems.package_resolution import PackageResolutionService

async def test():
    async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
        s = PackageResolutionService()
        res = await s._check_npm(client, 'Bootstrap', '4.5.2')
        print(f"NPM CHECK: {res}")
        
        full_res = await s.resolve("Bootstrap", "4.5.2")
        print(f"FULL RESOLVE: {full_res}")

if __name__ == "__main__":
    asyncio.run(test())
