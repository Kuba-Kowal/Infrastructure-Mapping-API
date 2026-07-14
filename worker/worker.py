from core.configuration import create_config
from core.engine import Engine
from persistence.db.connection import get_connection
from persistence.writers.db_update_scan_status import scan_pending, scan_completed, scan_failed
from persistence.readers.check_job_queue import check_job_queue
import asyncio

async def spawn_worker(scan_id, domain, sem):
    async with sem:
        try:
            connection = get_connection()
            config = create_config()
            engine = Engine()

            result = await engine.run_scan(domain, config, scan_id, connection)

            print(f"SCAN COMPLETED {domain}")

            scan_completed(connection, scan_id)

            connection.commit()

        except Exception as e:
            print(e)
            scan_failed(connection, scan_id)
        finally:
            connection.commit()

async def get_job():
    connection = get_connection()

    result = check_job_queue(connection)

    if result:
        scan_id, domain = result[0], result[1]

        scan_pending(connection, scan_id)
        return scan_id, domain
    
    await asyncio.sleep(15)
    return None, None

async def manage_workers():
    sem = asyncio.Semaphore(3) # Max concurrent tasks - 3 workers.
    found_job = False
    tasks = set()

    while True:
        while found_job == False:
            if len(tasks) >= 3:
                await asyncio.sleep(15)
                continue
            
            scan_id, domain = await get_job()
            if scan_id:
                found_job = True
        
        task = asyncio.create_task(spawn_worker(scan_id, domain, sem))

        print(f"CREATED WORKER FOR SCAN_ID {scan_id}")

        tasks.add(task)
        task.add_done_callback(tasks.discard)
        found_job = False

try:
    print("STARTING WORKERS")
    asyncio.run(manage_workers())
except Exception as e:
    print("ERROR: ", end="")
    print(e)