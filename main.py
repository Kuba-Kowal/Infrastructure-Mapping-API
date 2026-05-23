import requests
import json
import time

DOMAIN_NAME = "example.com"
RATE_LIMIT = 0.5

class RawCTLog:
    def __init__(self, asn, date, issuer):
        self.asn = asn
        self.date = date
        self.issuer = issuer
    
    def __repr__(self):
        return f"Domain(asn={self.asn}, date={self.date}, issuer={self.issuer})"

class CTLog():
    def __init__(self, asn, issuer, first_date, last_date):
        self.asn = asn
        self.first_date = first_date
        self.last_date = last_date
        self.issuer = issuer
    
    def __repr__(self):
        return f"""{[asn for asn in self.asn]}
issuer={self.issuer.strip('"')} 
[{self.first_date},{self.last_date}]
"""

# Extract issuer name
def clean_issuer_name(issuer):
    for i in issuer.split(','):
        i = i.strip()
        if i.startswith('O='):
            return i.replace("O=", "")

# Remove time from DateTime
def clean_date(date):
    date = date.split("T")
    return date[0]

# Remove duplicate logs and sort by date added to repository descending
def deduplicate_logs(logs: list):
    groups = {}

    for log in logs:
        key = (tuple(log.asn), log.issuer)

        if key not in groups:
            groups[key] = []

        groups[key].append(log.date)

    cleaned_logs = []

    for (asn, issuer), dates in groups.items():
        cleaned_logs.append(
            CTLog(asn, issuer, max(dates), min(dates))
        )

    cleaned_logs.sort(key=lambda x: x.first_date, reverse=True)
    return cleaned_logs

request_success = False

# Make crt.sh request in json format
while request_success != True:
    req = requests.get(f"https://crt.sh/?q={DOMAIN_NAME}&output=json")

    if req.status_code == 200:
        request_success = True

    time.sleep(RATE_LIMIT)

raw_ct_log_list: list[object] = []

# Convert crt.sh data into objects
for item in req.json():
    if not item.get("entry_timestamp"):
        continue

    domain = RawCTLog(
        item['name_value'].split(),
        clean_date(item['entry_timestamp']),
        clean_issuer_name(item['issuer_name'])
        )

    raw_ct_log_list.append(domain)

clean_logs = deduplicate_logs(raw_ct_log_list)

# Print logs
for log in clean_logs:
    print(log)
