import json

def write_to_json(graph: Graph, config: [dict]):
        if not config["output"]:
            output_location = "graph.json"
        else:
            output_location = config["output"]

        try:
            with open(output_location, "w") as f:
                json.dump(graph.json_to_dict(), f, indent=4, default=str)
        except:
            print(f"Error writing to {output_location}. Defaulting ./graph.json")
            with open("graph.json", "w") as f:
                json.dump(graph.to_dict(), f, indent=4, default=str)