from dotenv import load_dotenv
import json
import argparse
import os

def load_config_file(path="config.json"):
    load_dotenv()

    with open(path, "r") as file:
        config = json.load(file)

    if not os.getenv("VT_API_KEY"):
        config["virustotal"] = False
    if not os.getenv("CERT_SPOTTER_API"):
        config["certspotter"] = False

    return config

def parse_args():
    parser = argparse.ArgumentParser(
        prog="infra_mapper.py",
        usage="%(prog)s -d [DOMAIN ...] [options]",
        description="CT Log, pDNS, DNS graph orchestration tool"
    )
    parser.add_argument("-d", "--domains", nargs="+", metavar="DOMAIN", help="One or more domains to enumerate", required=True)
    parser.add_argument("-o", "--output", help="Write results to JSON file, default [./graph.json]", required=False)

    return parser.parse_args()

def create_config():
    config = load_config_file()

    for arg, value in vars(parse_args()).items():
        config[arg] = value

    return config
