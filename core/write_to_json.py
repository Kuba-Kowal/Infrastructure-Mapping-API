import json

def write_to_json(graph: Graph, config: [dict]):
        if not config["output"]:
            output_location = "graph.json"
        else:
            output_location = config["output"]

        with open(output_location, "w") as f:
            json.dump(graph.to_dict(), f, indent=4, default=str)