from persistence.db.connection import get_connection
from datetime import datetime

def check_last_scan(domain):
    connection = get_connection()

    cursor = connection.cursor()

    sql = """
    SELECT finished_at FROM scans
    WHERE apex_domain = %s
    ORDER BY finished_at DESC
    LIMIT 1
    """

    cursor.execute(sql, (domain,))

    try:
        current_date = datetime.now().replace(microsecond=0)
        last_scan = cursor.fetchone()[0]

        time_difference = current_date - last_scan

        return int(time_difference.total_seconds() // 3600)

    except:
        return None