import json
import requests
from requests.auth import HTTPBasicAuth
import urllib3

# Suppress SSL warnings if your ELK uses self-signed certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- Configuration ---
ELASTIC_URL = "https://wa-kibana.cyberrangepoulsbo.com/api/console/proxy?path=/suricata-*/_search&method=POST"
USER = "username" #enter username here
PASS = "password" #enter password here

# Your Exact Postman JSON Body
query_payload = {
  "size": 5,
  "_source": [
    "@timestamp", "timestamp", "src_ip", "dest_ip", "src_port", "dest_port",
    "proto", "app_proto", "traffic_type", "in_iface", "geoip.src_country.*",
    "geoip.dest_country.*", "geoip.src.*", "geoip.dest.*", "frame.length",
    "frame.direction", "frame.stream_offset", "frame.payload",
    "frame.payload_printable", "host.hostname", "host.os.*",
    "host.architecture", "host.containerized", "host.ip", "flow_id",
    "community_id", "flow.pkts_toserver", "flow.pkts_toclient",
    "flow.bytes_toserver", "flow.bytes_toclient", "dns.query.*",
    "suricata.eve.alert.*", "alert.*", "log.file.path", "tags", "message"
  ],
  "query": {
    "bool": {
      "should": [
        { "exists": { "field": "suricata.eve.alert.signature" } }
      ]
    }
  },
  "sort": [ { "@timestamp": { "order": "desc" } } ]
}

def get_suricata_logs():
    try:
        headers = {
            "kbn-xsrf": "true",
            "Content-Type": "application/json",
        }
        # Mimicking Postman POST request with Basic Auth
        response = requests.post(
            ELASTIC_URL,
            json=query_payload,
            auth=HTTPBasicAuth(USER, PASS),
            headers=headers,
            verify=False # Equivalent to turning off SSL verification in Postman
        )

        response.raise_for_status()
        data = response.json()
        
        # Accessing the list of logs (hits)
        hits = data.get('hits', {}).get('hits', [])
        print(f"[*] Successfully retrieved {len(hits)} logs from Suricata.")
        return hits

    except Exception as e:
        print(f"[!] Error: {e}")
        return []

# Execute and view results
logs = get_suricata_logs()
if logs:
    for idx, hit in enumerate(logs, start=1):
        source = hit.get("_source", {})
        print(f"\n--- Match {idx} ---")
        print(json.dumps(source, indent=2, sort_keys=True))