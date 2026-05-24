import requests
import json
import time



# Original request logs
class RawCTLog:
    def __init__(self, asn, date, issuer):
        self.asn = asn
        self.date = date
        self.issuer = issuer
    
    def __repr__(self):
        return f"Domain(asn={self.asn}, date={self.date}, issuer={self.issuer})"

# Cleaned up logs
class CTLog():
    def __init__(self, asn, issuer, first_date, last_date):
        self.asn = asn
        self.first_date = first_date
        self.last_date = last_date
        self.issuer = issuer
    
    def __repr__(self):
        return (f"""{[asn for asn in self.asn]}
issuer={self.issuer.strip('"')} 
[{self.first_date},{self.last_date}]""")



# Extract issuer name
def clean_issuer_name(issuer):
    for i in issuer.split(','):
        i = i.strip()
        if i.startswith('O='):
            return i.replace("O=", "")
        else:
            return "Unkown"

# Remove time from DateTime
def clean_date(date):
    date = date.split("T")
    return date[0]

# Remove duplicate logs and sort by date added to repository descending
def dedup_request(logs: list):
    groups = {}
    new_queries = []

    # Create a dictionary of asn, issuer -> timestamp mappings
    for log in logs:
        key = (tuple(log.asn), log.issuer)

        if key not in groups:
            groups[key] = []

        groups[key].append(log.date)

    cleaned_logs = []

    # For every combination of asn <-> issuer. Any domains that are new, add them to the queue list. 
    for (asn, issuer), dates in groups.items():
        for domain in asn:
            domain = domain.strip(",() ")
            if domain in new_queries:
                continue
            new_queries.append(domain)

        # Create new object for duplicate ASNs including latest log and oldest log date.
        cleaned_logs.append(
            CTLog(asn, issuer, max(dates), min(dates))
        )

    cleaned_logs.sort(key=lambda x: x.first_date, reverse=True)

    return cleaned_logs, new_queries

# Make crt.sh request in json format
def make_crt_req(DOMAIN_NAME, RATE_LIMIT, MAX_RETRIES):
    session = requests.Session()

    session.headers.update({"User-Agent": "Mozilla/5.0"})

    url = f"https://crt.sh/?q={DOMAIN_NAME}&output=json"

    print(f"[+] CRT.SH QUERY -> {DOMAIN_NAME}")

    # Attempt connection to server
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            response = session.get(url, timeout=60)

            if response.status_code == 200:
                print("[+] SUCCESS")
                break

            else:
                pass

        except requests.exceptions.RequestException as e:
            print(f"[-] Request failed: {e}")

        time.sleep(RATE_LIMIT)

    else:
        print("[-] Failed after max retries")

        return None


    # Convert crt.sh data into objects
    raw_ct_log_list = []
    for item in response.json():
        if not item.get("entry_timestamp"):
            continue

        domain = RawCTLog(
            item['name_value'].split(),
            clean_date(item['entry_timestamp']),
            clean_issuer_name(item['issuer_name'])
            )

        raw_ct_log_list.append(domain)

    return raw_ct_log_list

def __main__(DOMAIN_NAME):
    RATE_LIMIT = 0.5
    MAX_RETRIES = 20

    queue = set()
    searched_queries = set()
    output = []

    queue.add(DOMAIN_NAME)
    while len(queue) != 0:
        # Take object out of queue
        current_query = queue.pop()
        searched_queries.add(current_query)

        # Make request with latest item removed from queue
        request_output = make_crt_req(current_query, RATE_LIMIT, MAX_RETRIES)
        if request_output == None:
            continue
        
        # Dedupliacte, organise and append new queries 
        clean_logs, new_queries = dedup_request(request_output)

        for log in clean_logs:
            output.append(log)

        # Add new queries to queue
        if len(new_queries) > 0:
            for query in new_queries:
                if query in searched_queries:
                    continue
                queue.add(query)

    print("\n[+] Queue Finished")
    time.sleep(3)

    return output

DOMAIN_NAME = "example.com"
output = __main__(DOMAIN_NAME)

# Print logs
for result in output:
    print(result)
    print(type(result.asn))

