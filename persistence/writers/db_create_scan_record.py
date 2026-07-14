from persistence.db.connection import get_connection
from core.extract_apex import extract_apex

def create_scan_record(query_domain):
    apex_domain = extract_apex(query_domain)

    connection = get_connection()

    cursor = connection.cursor()

    # INSERT SCAN INTO THE DATABASE
    scans_query = """
    INSERT IGNORE INTO scans (apex_domain, status, query_domain)
    VALUES (%s, %s, %s)
    """

    cursor.execute(scans_query, (apex_domain, "QUEUED", query_domain))

    connection.commit()

    return cursor.lastrowid