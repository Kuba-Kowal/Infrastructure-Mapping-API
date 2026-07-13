from persistence.db.connection import *

def scan_pending(connection, scan_id):
    connection = get_connection()
        
    cursor = connection.cursor()

    query = """
    UPDATE scans
    SET status = "PROCESSING",
    started_at = NOW()
    WHERE scan_id = %s
    """

    cursor.execute(query, (scan_id,))

    connection.commit()


def scan_completed(connection, scan_id):
    cursor = connection.cursor()

    query = """
    UPDATE scans
    SET status = "COMPLETE",
    finished_at = NOW()
    WHERE scan_id = %s
    """

    cursor.execute(query, (scan_id,))

    connection.commit()

def scan_failed(connection, scan_id):      
    cursor = connection.cursor()

    query = """
    UPDATE scans
    SET status = "FAILED",
    finished_at = NOW()
    WHERE scan_id = %s
    """

    cursor.execute(query, (scan_id,))

    connection.commit()

