from persistence.writers.db_write_node import write_nodes
from persistence.writers.db_write_edge import write_edges
from persistence.writers.db_write_scan_relationship import write_scan_relationship
import time

def persistence_pipeline(graph, start_scan):
    start_write_db = time.perf_counter()

    write_nodes(graph)
    edge_ids = write_edges(graph)

    print(start_scan)

    write_scan_relationship(graph, edge_ids, start_scan)

    end_write_db = time.perf_counter()

    print(f"\nTotal Databse Write Time: {end_write_db - start_write_db:.2f} seconds")
