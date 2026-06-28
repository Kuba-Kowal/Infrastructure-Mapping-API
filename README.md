# Overview

An asynchronous passive reconnaissance graphing tool for infrastructural mapping across ASN, pDNS, DNS and CT log data.

Capable of automatically and cleanly displaying (to be implemented) relationships between infrastructure for educated defensive and offensive decision making and asset discovery.

Designed to save time and effort for penetration testers, bug bounty hunters and security specialists.

```
Sources (crt.sh / Virustotal / CertSpotter / Cymru ASN)
		↓
Semi-Asynchronous Orchestration Pipeline (Re-query System)
		↓
Asynchronous Fetching Layer
		↓
Scope Expansion Layer
		↓
Processing Layer (Normalisation + Deduplication + Graph Store)
		↓
Export Layer (JSON Normalisation)
```

**Usage**
```
infra_mapper.py -d [DOMAIN ...] [options]

CT Log, pDNS, DNS, and ASN graph orchestration tool

options:
  -h, --help            show this help message and exit
  -d, --domains DOMAIN [DOMAIN ...]
                        One or more domains to enumerate
  -o, --output OUTPUT   Write results to JSON file, default [./graph.json]
```

---

# System Design

**Data Model Evolution**

- Initially used nested dictionaries for edge relationship mappings.
- This became inefficient due to nested lookups and model expansion.
- Transitioned to a graph model to better represent many-to-many relationships.
- SHA256 edge referencing for one way lookup-tables and reduced data size.

**Pipeline Architecture**

- Clear separation of responsibilities; ingestion, expansion, processing and orchestration.
- Hybrid asynchronous design to adhere to rate limits and tackle ingestion bottlenecks.
- Centralised graph for direct graph insertion and single source of truth.

**Future Implementation**

- Front-end UI: Clear graph expansion, relationship visibility, and filter application.
- Database: Store results with dates to convert from data ingestion to data monitoring.
- Potential for AI result result inference such as automated infrastructure / operational clustering or confidence assignment based on shared ASN / DNS / CT relationships

---

# Engineering Decisions & Trade-offs

> **Trade-off: Queue isolation vs global coordination**
> 
> A global queue introduced race conditions and missing entries due to concurrent mutation. I replaced this with isolated pipeline-level queues, improving the stability at the cost of missed, per-source data. I was happy to make this trade-off as the lost data is compensated through the use of several sources

> **Trade-off: Hashing Strategy vs Sequential IDs**
>
> Selecting a referencing system for edges to reduce export dataset size: Hashing provided direct hashing tables without the requirement of reverse-lookup tables, although more complex, entries could be re-hashed rather than correlated to a table resulting in O(1) searches. Sequential IDs require reverse-lookups or O(n) searches.

> **Trade-off: Graph vs Dictionaries**
> 
> Dictionaries resulted in complex search and unpacking operations with unclear naming conventions and messy code. A graph allowed for a centralised knowledge-base without the need of passing around lists - furthermore, interacting with the graph can be done directly within it reducing additional functionality outside of it, resulting in cleaner pipelines.

> **Trade-off: Synchronous vs Asynchronous Fetching**
> 
> Synchronous orchestration results in higher stability, with ~10% higher connection success rates to unstable APIs (crt.sh) at the cost of speed ~30-45% slower. Hybrid asynchronous fetching allowed me to maintain the stability of DNS and BGP (TXT records) fetching due to its already fast, and typically larger ingestion size. While substantially increasing the speed of pDNS + CT log reconnaissance. I am happy to lose connection success rate, due to the usage of several sources and a fail-safe in case the first connection fails and the scope is not expanded.

---
# Example Output

```
[⋆] QUERY VIRUSTOTAL | hackerone.com
[+] SUCCESS VIRUSTOTAL | hackerone.com

[⋆] QUERY CERT SPOTTER | mta-sts.managed.hackerone.com
[+] SUCCESS CERTSPOTTER | mta-sts.managed.hackerone.com

[⋆] QUERY DNS - A | support.hackerone.com

[⋆] QUERY ASN ORIGIN | 13.226.22.7

[⋆] QUERY ASN ORGANISATION | 54113

Total runtime: 155.85 seconds

-> ./hackerone.json
```

# Dependencies

```
aiohttp==3.14.1
dnspython==2.8.0
python-dotenv==1.2.2
```

