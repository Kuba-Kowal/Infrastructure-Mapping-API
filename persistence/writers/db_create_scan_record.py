from persistence.db.connection import get_connection

def create_scan_record(apex_domain):
    connection = get_connection()

    cursor = connection.cursor()

    # INSERT SCAN INTO THE DATABASE
    scans_query = """
    INSERT IGNORE INTO scans (apex_domain, status)
    VALUES (%s, %s)
    """

    print(f"creating {apex_domain}")

    cursor.execute(scans_query, (apex_domain, "QUEUED"))

    connection.commit()

    return cursor.lastrowid