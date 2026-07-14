from persistence.db.connection import get_connection

def check_job_queue(connection):
    cursor = connection.cursor()

    query = """
    SELECT scan_id, query_domain FROM scans
    WHERE status = 'QUEUED'
    ORDER BY scan_id ASC
    LIMIT 1;
    """

    cursor.execute(query)

    return cursor.fetchone()