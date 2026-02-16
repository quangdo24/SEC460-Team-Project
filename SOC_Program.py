import json
import os
import argparse

import ipaddress
import sys
from pathlib import Path

import requests
from requests.auth import HTTPBasicAuth
import urllib3

# Suppress SSL warnings if your ELK uses self-signed certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BANNER = r"""
  _  ___ _                                    _    ____  _   _ ____  _____ ___ ____  ____  ____   
 | |/ (_) |__   __ _ _ __   __ _     _       / \  | __ )| | | / ___|| ____|_ _|  _ \|  _ \| __ )  
 | ' /| | '_ \ / _` | '_ \ / _` |  _| |_    / _ \ |  _ \| | | \___ \|  _|  | || |_) | | | |  _ \  
 | . \| | |_) | (_| | | | | (_| | |_   _|  / ___ \| |_) | |_| |___) | |___ | ||  __/| |_| | |_) | 
 |_|\_\_|_.__/ \__,_|_| |_|\__,_|   |_|   /_/   \_\____/ \___/|____/|_____|___|_|   |____/|____/  
                                                                                                  
"""

# --- Configuration ---
ELASTIC_URL = "https://wa-kibana.cyberrangepoulsbo.com/api/console/proxy?path=/suricata-*/_search&method=POST"
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
ABUSEIPDB_MAX_AGE_DAYS = 90

SECRETS_DIR = Path(__file__).resolve().parent / "secrets"
WA_KIBANA_CRED_PATH = Path(
    os.getenv("WA_KIBANA_CRED_PATH", SECRETS_DIR / "wa_kibana.json")
)
ABUSEIPDB_KEY_PATH = Path(
    os.getenv("ABUSEIPDB_KEY_PATH", SECRETS_DIR / "abuseipdb.json")
)


DEBUG_PRINT_KIBANA_REQUEST = os.getenv("DEBUG_PRINT_KIBANA_REQUEST", "0") == "1"


def load_json_file(path: Path, required_keys: set, example_name: str):
    """Load a JSON secrets file and validate required keys exist."""
    if not path.exists():
        raise FileNotFoundError(
            f"Missing secrets file: {path}. "
            f"Create it from secrets/{example_name}."
        )
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    missing = required_keys - set(data.keys())
    if missing:
        raise ValueError(f"Missing keys in {path}: {', '.join(sorted(missing))}")
    return data


def print_kibana_request(url: str, headers: dict, payload: dict, username: str):
    """
    Pretty-print the Kibana request for debugging without leaking secrets.
    """
    print("\n=== Kibana Request (sanitized) ===")
    print(f"URL: {url}")
    print(f"Auth: Basic (username={username}, password=<redacted>)")
    print("Headers:")
    print(json.dumps(headers, indent=2, sort_keys=True))
    print("JSON Body:")
    print(json.dumps(payload, indent=2, sort_keys=True))
    print("=== End Kibana Request ===\n")


def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description=(
            "Query Suricata alerts from Kibana/Elasticsearch and check IPs via AbuseIPDB, "
            "or manually check IPs in AbuseIPDB."
        )
    )
    parser.add_argument(
        "--ip",
        action="append",
        default=[],
        help=(
            "Manually check an IP in AbuseIPDB (skips Kibana query). "
            "Can be repeated, or pass comma-separated values."
        ),
    )
    parser.add_argument(
        "--max-age-days",
        type=int,
        default=ABUSEIPDB_MAX_AGE_DAYS,
        help="AbuseIPDB maxAgeInDays parameter (default: 90).",
    )
    parser.add_argument(
        "--abuse-verbose",
        action="store_true",
        help="Request verbose AbuseIPDB output (includes extra fields when available).",
    )
    return parser.parse_args()


def normalize_ips(ip_args):
    """Normalize/validate IPs from CLI/prompt input and de-dupe while preserving order."""
    raw = []
    for item in ip_args or []:
        raw.extend([x.strip() for x in str(item).split(",") if x.strip()])

    ips = []
    for ip_str in raw:
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if ip_obj.is_private:
                print(f"[!] Skipping private IP: {ip_str}")
                continue
            ips.append(str(ip_obj))
        except ValueError:
            print(f"[!] Skipping invalid IP: {ip_str}")

    # de-dupe while preserving order
    return list(dict.fromkeys(ips))


def prompt_user_mode_and_inputs():


    """


    Interactive prompt to choose between modes.


    Returns: (mode, manual_ips)


    """


    print("\nSelect mode:")


    print("  1) Query Kibana / Elasticsearch (Full Details)")


    print("  2) Manual AbuseIPDB lookup (enter IP address(es))")


    print("  3) Query Kibana / Elasticsearch (Compact Details)")


    print("  4) Custom Query (Specific Fields)")





    while True:


        choice = input("Enter 1, 2, 3, or 4: ").strip()


        if choice in {"1", "2", "3", "4"}:


            break


        print("[!] Please enter 1, 2, 3, or 4.")





    if choice == "1":


        return "kibana", []


    if choice == "3":


        return "kibana_compact", []


    if choice == "4":


        return "kibana_option4", []





    # Option 2: force valid IP input


    while True:


        ip_text = input("Enter IP(s) (comma-separated): ").strip()


        manual_ips = normalize_ips([ip_text])


        if manual_ips:


            return "manual", manual_ips


        print("[!] No valid IPs entered. Try again (or press Ctrl+C to cancel).")





# Default query payload for options 1 and 3


query_payload = {


  "size": 1000,


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


      "must": [


        {


          "range": {


            "@timestamp": {


              "gte": "now-24h",


              "lte": "now"


            }


          }


        },


        {


          "bool": {


            "should": [


              { "match": { "suricata.eve.alert.severity": 1 } },


              { "match": { "alert.severity": 1 } }


            ]


          }


        }


      ],


      "should": [


        { "exists": { "field": "suricata.eve.alert.signature" } }


      ],


      "must_not": [


        { "range": { "src_ip": { "gte": "192.168.0.0", "lte": "192.168.255.255" }}},


        { "range": { "src_ip": { "gte": "10.0.0.0", "lte": "10.255.255.255" }}},


        { "range": { "src_ip": { "gte": "172.16.0.0", "lte": "172.31.255.255" }}}


      ]


    }


  },


  "sort": [ { "@timestamp": { "order": "desc" } } ]


}





# New query payload for option 4


option4_query_payload = {


  "track_total_hits": False,


  "sort": [{"@timestamp": {"order": "desc", "unmapped_type": "boolean"}}],


  "fields": [


    {"field": "*", "include_unmapped": "true"},


    {"field": "@timestamp", "format": "strict_date_optional_time"},


    {"field": "suricata.eve.@timestamp", "format": "strict_date_optional_time"},


    {"field": "suricata.eve.flow.end", "format": "strict_date_optional_time"},


    {"field": "suricata.eve.flow.start", "format": "strict_date_optional_time"},


    {"field": "suricata.eve.tls.notafter", "format": "strict_date_optional_time"},


    {"field": "suricata.eve.tls.notbefore", "format": "strict_date_optional_time"},


    {"field": "timestamp", "format": "strict_date_optional_time"}


  ],


  "size": 500,


  "version": True,


  "script_fields": {},


  "stored_fields": ["*"],


  "runtime_mappings": {


    "dns.rrname_length": {


      "type": "long",


      "script": {


        "source": "if (doc.containsKey('dns.rrname.keyword') && !doc['dns.rrname.keyword'].empty) {\r\n  emit(doc['dns.rrname.keyword'].value.length());\r\n}\r\n"


      }


    }


  },


  "_source": False,


  "query": {


    "bool": {


      "must": [],


      "filter": [


        {


          "range": {


            "@timestamp": {


              "format": "strict_date_optional_time",


              "gte": "now-24h",


              "lte": "now"


            }


          }


        },


        {"match_phrase": {"alert.severity": 1}}


      ],


      "should": [],


      "must_not": [


        {"range": {"src_ip": {"lt": "192.168.255.255", "gte": "192.168.0.0"}}},


        {"range": {"src_ip": {"lt": "10.255.255.255", "gte": "10.0.0.0"}}},


        {"range": {"src_ip": {"lt": "172.31.255.255", "gte": "172.16.0.0"}}}


      ]


    }


  },


  "highlight": {


    "pre_tags": ["@kibana-highlighted-field@"],


    "post_tags": ["@/kibana-highlighted-field@"],


    "fields": {"*": {}},


    "fragment_size": 2147483647


  }


}





def get_suricata_logs(username: str, password: str, payload: dict):


    """Query Kibana/Elasticsearch for the latest Suricata alert hits and return the hits list."""


    try:


        headers = {


            "kbn-xsrf": "true",


            "Content-Type": "application/json",


        }


        print("[*] Querying Kibana / Elasticsearch for latest Suricata alerts...")


        if DEBUG_PRINT_KIBANA_REQUEST:


            print_kibana_request(ELASTIC_URL, headers, payload, username)





        response = requests.post(


            ELASTIC_URL,


            json=payload,


            auth=HTTPBasicAuth(username, password),


            headers=headers,


            verify=False


        )


        response.raise_for_status()


        data = response.json()


        hits = data.get('hits', {}).get('hits', [])


        print(f"[*] Successfully retrieved {len(hits)} logs from Suricata.")


        return hits


    except Exception as e:


        print(f"[!] Error: {e}")


        return []





def extract_ips(logs):





    """Extract unique source IPs (src_ip) from Kibana hit sources."""





    ips = set()





    for hit in logs:





        source = hit.get("_source", {})





        ip_value = source.get("src_ip")





        if not ip_value:





            continue





        try:





            ip_obj = ipaddress.ip_address(ip_value)





            if not ip_obj.is_private:





                ips.add(str(ip_obj))





        except ValueError:





            continue





    return sorted(ips)











def extract_ips_from_fields(logs):





    """Extract unique source IPs from Kibana hits that use the 'fields' structure."""





    ips = set()





    for hit in logs:





        fields = hit.get("fields", {})





        ip_value = None





        # Try 'src_ip' first, then 'source.ip'





        if 'src_ip' in fields and fields['src_ip']:





            ip_value = fields['src_ip'][0]





        elif 'source.ip' in fields and fields['source.ip']:





            ip_value = fields['source.ip'][0]











        if not ip_value:





            continue





        try:





            # The query for option 4 already filters for public IPs, but an extra check is good practice.





            ip_obj = ipaddress.ip_address(ip_value)





            if not ip_obj.is_private:





                ips.add(str(ip_obj))





        except ValueError:





            continue





    return sorted(list(ips))

















def check_ip_abuse(ip_address: str, api_key: str, max_age_days: int, verbose: bool):





    """Call AbuseIPDB 'check' API for one IP and return the response 'data' dict."""





    headers = {"Key": api_key, "Accept": "application/json"}





    params = {"ipAddress": ip_address, "maxAgeInDays": max_age_days, "verbose": "true" if verbose else "false"}





    response = requests.get(ABUSEIPDB_URL, headers=headers, params=params, timeout=30)





    response.raise_for_status()





    return response.json().get("data", {})











def print_abuseipdb_report(ip_address: str, data: dict, match_indices=None):





    """Print a compact AbuseIPDB report for one IP."""





    print(f"\n\n\n--- AbuseIPDB Report for {ip_address} ---")





    if match_indices:





        print(f"  Matches in Kibana query: {', '.join(str(idx) for idx in sorted(set(match_indices)))}")





    





    def print_kv(key, value, indent=2):





        print(f"{' ' * indent}{key:<24}: {value if value is not None else 'N/A'}")











    print("\n  Location:")





    print_kv("Country", data.get("countryName"))





    print_kv("Country Code", data.get("countryCode"))





    print_kv("Region", data.get("region"))





    print("\n  Abuse Metrics:")





    print_kv("Abuse Confidence Score", data.get("abuseConfidenceScore"))





    print_kv("Total Reports", data.get("totalReports"))





    print_kv("Last Reported At", data.get("lastReportedAt"))





    print_kv("Whitelisted", "Yes" if data.get("isWhitelisted") else "No")





    print("\n  Network:")





    print_kv("ISP", data.get("isp"))





    print_kv("Domain", data.get("domain"))





    print_kv("Usage Type", data.get("usageType"))





    print("-" * (30 + len(ip_address)))











def print_suricata_hit(idx: int, source: dict, show_full_details: bool = True):





    """Nicely print a Suricata/Kibana hit in a readable, non-JSON format."""





    ts = source.get("@timestamp") or source.get("timestamp")





    src_ip = source.get("src_ip")





    dest_ip = source.get("dest_ip")





    src_port = source.get("src_port")





    dest_port = source.get("dest_port")





    proto = source.get("proto")





    app_proto = source.get("app_proto")





    alert = source.get("alert") or {}





    suricata_alert = (((source.get("suricata") or {}).get("eve") or {}).get("alert")) or {}





    signature = suricata_alert.get("signature") or alert.get("signature") or source.get("suricata.eve.alert.signature")





    category = suricata_alert.get("category") or alert.get("category")





    severity = suricata_alert.get("severity") or alert.get("severity")





    signature_id = suricata_alert.get("signature_id") or alert.get("signature_id")





    geoip = source.get("geoip") or {}





    src_country = ((geoip.get("src_country") or {}).get("name")) or ((geoip.get("src_country") or {}).get("iso_code"))





    dest_country = ((geoip.get("dest_country") or {}).get("name")) or ((geoip.get("dest_country") or {}).get("iso_code"))











    print("\n" + "="*80)





    print(f"|  Suricata Alert #{idx}".ljust(79) + "|")





    print("="*80)





    





    def print_kv(key, value, indent=2):





        print(f"|{' ' * indent}{key:<15}: {value if value is not None else 'N/A'}".ljust(79) + "|")











    print_kv("Timestamp", ts)





    print("|" + "-"*78 + "|")





    print("|  Flow Details".ljust(79) + "|")





    print("|" + "-"*78 + "|")





    print_kv("Source IP", src_ip)





    print_kv("Source Port", src_port)





    print_kv("Destination IP", dest_ip)





    print_kv("Destination Port", dest_port)





    print_kv("Protocol", proto)





    print_kv("Application", app_proto)











    if src_country or dest_country:





        print("|" + "-"*78 + "|")





        print("|  GeoIP Information".ljust(79) + "|")





        print("|" + "-"*78 + "|")





        print_kv("Source Country", src_country or "?")





        print_kv("Dest. Country", dest_country or "?")











    if signature or category or severity is not None:





        print("|" + "-"*78 + "|")





        print("|  Alert Information".ljust(79) + "|")





        print("|" + "-"*78 + "|")





        if signature:





            print(f"|   Signature: {signature}".ljust(79) + "|")





        if signature_id is not None:





            print_kv("Signature ID", signature_id)





        if category:





            print_kv("Category", category)





        if severity is not None:





            print_kv("Severity", severity)











    if show_full_details:





        print("|" + "-"*78 + "|")





        print("|  Full Details".ljust(79) + "|")





        print("|" + "-"*78 + "|")





        flat = {k: v for k, v in _flatten(source).items() if v is not None and not (isinstance(v, str) and v.strip() == "")}





        for key in sorted(flat.keys()):





            value = flat[key]





            suffix = ""





            if "bytes" in key and isinstance(value, (int, float)):





                gb = float(value) / 1_000_000_000





                if gb is not None:





                    suffix = f" ({gb:.2f} GB)"





            line = f"- {key} = {value}{suffix}"





            if len(line) > 74:





                line = line[:71] + "..."





            print(f"|   {line}".ljust(79) + "|")





    print("="*80 + "\n")











def print_option4_hit(idx: int, hit: dict, similar_count: int = 0):











    """Prints a custom list of fields from a Kibana hit that uses the 'fields' property."""











    print(f"\n==================== ALERT {idx} ====================")











    











    fields_data = hit.get("fields", {})























    def get_field_value(field_key_or_synonyms):











        if isinstance(field_key_or_synonyms, list):











            for key in field_key_or_synonyms:











                if key in fields_data:











                    val = fields_data[key]











                    if isinstance(val, list) and val:











                        return val[0]











                    elif not isinstance(val, list): # handle if it's not a list for some reason











                        return val











            return "N/A"











        else: # Single field key











            if field_key_or_synonyms in fields_data:











                val = fields_data[field_key_or_synonyms]











                if isinstance(val, list) and val:











                    return val[0]











                elif not isinstance(val, list):











                    return val











            return "N/A"























    print("\n--- Source IP Information ---")











    print(f"  {'Source IP':<35}: {get_field_value(['src_ip'])}")











    print(f"  {'Source.IP (alias)':<35}: {get_field_value(['source.ip'])}")











    print(f"  {'Source Port':<35}: {get_field_value(['src_port'])}")











    print(f"  {'Source Country Name':<35}: {get_field_value('geoip.src.country_name')}")























    print("\n--- Destination IP Information ---")











    print(f"  {'Destination IP':<35}: {get_field_value(['dest_ip'])}")











    print(f"  {'Destination.IP (alias)':<35}: {get_field_value(['destination.ip'])}")











    print(f"  {'Destination Port':<35}: {get_field_value(['dest_port', 'dest port'])}") # Assuming "dest port" means dest_port























    print("\n--- Flow & Connection Details ---")











    print(f"  {'Flow Bytes To Client':<35}: {get_field_value(['flow.bytes_toclient'])}")











    print(f"  {'Flow Bytes To Server':<35}: {get_field_value(['flow.bytes_toserver'])}")











    print(f"  {'Community ID (clientiD)':<35}: {get_field_value(['community_id', 'clientiD'])}") # Assuming clientID typo for community_id























    print("\n--- Alert Classification ---")











    print(f"  {'Alert Severity':<35}: {get_field_value(['alert.severity'])}")











    print(f"  {'Suricata Alert Severity (Alias)':<35}: {get_field_value(['suricata.eve.alert.severity'])}") # Displaying both if user requested both











    print(f"  {'Alert GID':<35}: {get_field_value(['alert.gid'])}")











    print(f"  {'Alert Signature':<35}: {get_field_value(['alert.signature'])}")











    print(f"  {'Alert Signature (Alias)':<35}: {get_field_value(['Alert Signature'])}") # Displaying both if user requested both











    print(f"  {'Alert Category':<35}: {get_field_value(['alert.category'])}")











    print(f"  {'Suricata Alert Category (Alias)':<35}: {get_field_value(['suricata.eve.alert.category'])}") # Displaying both if user requested both











    print(f"  {'Signature Severity Meta':<35}: {get_field_value(['alert.metadata.signature_severity'])}")











    print(f"  {'Confidence Meta':<35}: {get_field_value(['alert.metadata.confidence'])}")























    print("\n--- Timestamp ---")











    print(f"  {'Timestamp':<35}: {get_field_value(['@timestamp', 'timestamp'])}")











    











    if similar_count > 0:











        print(f"\n[+ {similar_count} similar consecutive result(s) suppressed]")











        











    print("==================================================")



































def _get_hit_key_for_option4(hit: dict):











    """Generate a tuple of key fields to identify similar hits."""











    fields = hit.get("fields", {})























    def _get(keys):











        for key in keys:











            if key in fields and fields[key]:











                # Ensure value is a list and not empty before accessing index 0











                if isinstance(fields[key], list) and fields[key]:











                    return fields[key][0]











        return None























    src_ip = _get(['src_ip', 'source.ip'])











    dest_ip = _get(['dest_ip', 'destination.ip'])











    dest_port = _get(['dest_port'])











    signature = _get(['alert.signature'])











    category = _get(['alert.category'])











    return (src_ip, dest_ip, dest_port, signature, category)























def main():























    """Program entrypoint: interactive mode selection, Kibana query, and/or AbuseIPDB checks."""























    print(BANNER)























    args = parse_args()























    manual_ips = normalize_ips(args.ip)























    























    mode = ""























    show_full_details = True















































    # If not using CLI args, enter interactive mode























    if not manual_ips and len(sys.argv) == 1 and sys.stdin.isatty():























        try:























            mode, manual_ips = prompt_user_mode_and_inputs()























            if mode == "kibana_compact":























                show_full_details = False























        except (EOFError, KeyboardInterrupt):























            print("\n[*] Cancelled.")























            return















































    # Mode 2: Manual IP check























    if manual_ips:























        abuseipdb = load_json_file(ABUSEIPDB_KEY_PATH, {"api_key"}, "abuseipdb.example.json")























        print(f"[*] Checking {len(manual_ips)} manual IP(s) against AbuseIPDB...")























        for ip_address in manual_ips:























            try:























                data = check_ip_abuse(ip_address, abuseipdb["api_key"], args.max_age_days, args.abuse_verbose)























                print_abuseipdb_report(ip_address, data)























            except Exception as exc:























                print(f"[!] AbuseIPDB error for {ip_address}: {exc}")























        return















































    # --- Kibana Query Modes (1, 3, 4) ---























    wa_kibana = load_json_file(WA_KIBANA_CRED_PATH, {"username", "password"}, "wa_kibana.example.json")























    























    # Mode 4: Custom Query























    if mode == "kibana_option4":























        logs = get_suricata_logs(wa_kibana["username"], wa_kibana["password"], option4_query_payload)























        if logs:























            # Group similar consecutive logs to de-clutter the view























            grouped_logs = []























            current_group_head = logs[0]























            current_group_head['original_index'] = 1























            similar_count = 0















































            for i in range(1, len(logs)):























                key_current = _get_hit_key_for_option4(logs[i])























                key_group_head = _get_hit_key_for_option4(current_group_head)















































                if key_current == key_group_head and key_current != (None, None, None, None, None):























                    similar_count += 1























                else:























                    grouped_logs.append((current_group_head, similar_count))























                    current_group_head = logs[i]























                    current_group_head['original_index'] = i + 1























                    similar_count = 0























            























            grouped_logs.append((current_group_head, similar_count))















































            for hit, count in grouped_logs:























                print_option4_hit(hit['original_index'], hit, similar_count=count)























            























            unique_ips = extract_ips_from_fields(logs)























            if unique_ips:























                abuseipdb = load_json_file(ABUSEIPDB_KEY_PATH, {"api_key"}, "abuseipdb.example.json")























                print(f"\n[*] Checking {len(unique_ips)} unique public source IP(s) against AbuseIPDB...")























                for ip_address in unique_ips:























                    try:























                        data = check_ip_abuse(ip_address, abuseipdb["api_key"], args.max_age_days, args.abuse_verbose)























                        print_abuseipdb_report(ip_address, data, match_indices=None)























                    except Exception as exc:























                        print(f"[!] AbuseIPDB error for {ip_address}: {exc}")























            else:























                print("\n[*] No public source IPs found in results to check against AbuseIPDB.")























        return















































    # Modes 1 & 3: Default Kibana Query























    logs = get_suricata_logs(wa_kibana["username"], wa_kibana["password"], query_payload)























    if logs:























        ip_to_matches = {}























        for idx, hit in enumerate(logs, 1):























            source = hit.get("_source", {})























            print_suricata_hit(idx, source, show_full_details)























            src_ip = source.get("src_ip")























            if src_ip:























                ip_to_matches.setdefault(src_ip, []).append(idx)























        























        unique_ips = extract_ips(logs)























        if unique_ips:























            abuseipdb = load_json_file(ABUSEIPDB_KEY_PATH, {"api_key"}, "abuseipdb.example.json")























            print(f"\n[*] Checking {len(unique_ips)} IPs against AbuseIPDB...")























            for ip_address in unique_ips:























                try:























                    data = check_ip_abuse(ip_address, abuseipdb["api_key"], args.max_age_days, args.abuse_verbose)























                    print_abuseipdb_report(ip_address, data, match_indices=ip_to_matches.get(ip_address))























                except Exception as exc:























                    print(f"[!] AbuseIPDB error for {ip_address}: {exc}")























        else:























            print("[*] No IPs found in logs to check.")







































































if __name__ == "__main__":























    main()































