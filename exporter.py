import json
import time
import os
from prometheus_client import start_http_server, Gauge

JSONL_FILE = "/data/connections.jsonl"

# Define metrics
total_attempts = Gauge('honeypot_total_attempts', 'Total number of connection attempts')
unique_ips = Gauge('honeypot_unique_ips', 'Number of unique attacker IPs')
total_credentials = Gauge('honeypot_total_credentials', 'Total number of credential attempts')

def parse_logs():
    if not os.path.exists(JSONL_FILE):
        return []
    with open(JSONL_FILE, 'r') as f:
        return [json.loads(line) for line in f if line.strip()]

def update_metrics():
    records = parse_logs()
    ips = set()
    cred_count = 0
    for r in records:
        ips.add(r['ip'])
        cred_count += len(r['credentials'])
    total_attempts.set(len(records))
    unique_ips.set(len(ips))
    total_credentials.set(cred_count)

if __name__ == "__main__":
    start_http_server(8000)
    print("Exporter running on port 8000")
    while True:
        update_metrics()
        time.sleep(15)