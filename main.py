from core.engine import Engine
from core.configuration import create_config
import asyncio

async def main():
    config = create_config()

    engine = Engine()

    result = await engine.run_scan([domain for domain in config["domains"]], config)

    return result

if __name__ == "__main__":
    asyncio.run(main())