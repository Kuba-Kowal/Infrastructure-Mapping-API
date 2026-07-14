from persistence.db.connection import get_connection
import json

def read_full_graph(apex_domain, ):
    connection = get_connection()

    cursor = connection.cursor()

    sql = """
    SELECT n_source.data, n_source.type, COALESCE(n_source.properties, '{}'), n_target.data, n_target.type, COALESCE(n_target.properties, '{}'), r.relationship_type, s.finished_at
    FROM scan_relationships sr

    JOIN scans s
    ON s.scan_id = sr.scan_id

    JOIN relationships r
    ON sr.relationship_id = r.relationship_id

    JOIN nodes n_source
    ON r.source_hash = n_source.node_hash

    JOIN nodes n_target
    ON r.target_hash = n_target.node_hash

    WHERE s.apex_domain = %s
    """

    cursor.execute(sql, (apex_domain,))

    results = {}
    row_number = 1

    for row in cursor:
        results[f"row_{row_number}"] = {
            "source": {
                "data": row[0],
                "type": row[1],
                "properties": json.loads(row[2]) 
            },
            "target": {
                "data": row[3],
                "type": row[4],
                "properties": json.loads(row[5]) 
            },
            "relationship": {
                "type": str(row[6]),
                "finished_at": str(row[7]),
            }
        }

        row_number += 1

    return results