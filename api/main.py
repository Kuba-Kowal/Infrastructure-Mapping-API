from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from core.extract_apex import extract_apex
from persistence.writers.db_create_scan_record import create_scan_record
from persistence.readers.check_last_scan import check_last_scan
from persistence.readers.read_full_graph import read_full_graph

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "null",
        "http://localhost:8080",
        "http://192.168.0.52:8080"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

def unprocessable_exception():
    raise HTTPException(
        status_code=422,
        detail="Failed, A valid domain is required."
    )

def recently_scanned_exception():
    raise HTTPException(
        status_code=409,
        detail="Failed, This domain was recently scanned."
    )

def no_data_exception():
    raise HTTPException(
        status_code=404,
        detail="Failed, No data available for this domain."
    )

@app.post("/api/v1/scan")
def start_scan(domain: str):
    apex_domain = extract_apex(domain)

    if not apex_domain:
        unprocessable_exception()

    last_scanned = check_last_scan(apex_domain)

    if not last_scanned or last_scanned > 24:
        create_scan_record(apex_domain)
        return {"message": "SUCCESS"}
    else:
        recently_scanned_exception()

@app.get("/api/v1/view")
def retrieve_data(domain: str):
    apex_domain = extract_apex(domain)

    if not apex_domain:
        unprocessable_exception()

    data = read_full_graph(apex_domain)

    if data == {}:
        no_data_exception()

    return data