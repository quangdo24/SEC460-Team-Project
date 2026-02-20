import json
import os
import argparse
import urllib.parse

import ipaddress
import sys
from pathlib import Path

import requests
from requests.auth import HTTPBasicAuth
import urllib3

# Suppress SSL warnings if your ELK uses self-signed certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ── ANSI Color Helpers ────────────────────────────────────────────────────────
# Enable ANSI escape codes on Windows 10+ terminals
if sys.platform == "win32":
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
    except Exception:
        pass

class C:
    """ANSI color codes for terminal output."""
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    BG_RED  = "\033[41m"
    BG_YEL  = "\033[43m"
    BG_GRN  = "\033[42m"


def severity_color(sev) -> str:
    """Return an ANSI color based on Suricata severity (1 = highest)."""
    try:
        sev = int(sev)
    except (TypeError, ValueError):
        return C.WHITE
    if sev <= 1:
        return C.RED
    if sev == 2:
        return C.YELLOW
    return C.GREEN


def abuse_score_color(score) -> str:
    """Return an ANSI color based on AbuseIPDB confidence score (0-100)."""
    try:
        score = int(score)
    except (TypeError, ValueError):
        return C.WHITE
    if score >= 75:
        return C.RED
    if score >= 40:
        return C.YELLOW
    if score >= 10:
        return C.BLUE
    return C.GREEN

BANNER = (
    f"\n{C.BOLD}{C.CYAN}"
    r"  _  ___ _                                    _    ____  _   _ ____  _____ ___ ____  ____  ____   " "\n"
    r" | |/ (_) |__   __ _ _ __   __ _     _       / \  | __ )| | | / ___|| ____|_ _|  _ \|  _ \| __ )  " "\n"
    r" | ' /| | '_ \ / _` | '_ \ / _` |  _| |_    / _ \ |  _ \| | | \___ \|  _|  | || |_) | | | |  _ \  " "\n"
    r" | . \| | |_) | (_| | | | | (_| | |_   _|  / ___ \| |_) | |_| |___) | |___ | ||  __/| |_| | |_) | " "\n"
    r" |_|\_\_|_.__/ \__,_|_| |_|\__,_|   |_|   /_/   \_\____/ \___/|____/|_____|___|_|   |____/|____/  " "\n"
    f"{C.RESET}"
    f"{C.DIM}  Suricata Alert Query + AbuseIPDB Enrichment Tool{C.RESET}\n"
)

# --- Configuration ---
KIBANA_BASE_URL = "https://wa-kibana.cyberrangepoulsbo.com"
ELASTIC_URL = f"{KIBANA_BASE_URL}/api/console/proxy?path=/suricata-*/_search&method=POST"
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
ABUSEIPDB_MAX_AGE_DAYS = 90
DEFAULT_QUERY = 'event_type:"alert" AND alert.signature:ET*'
DEFAULT_RESULT_COUNT = 10
DEFAULT_TIME_RANGE = "now-48h"

SECRETS_DIR = Path(__file__).resolve().parent / "secrets"
WA_KIBANA_CRED_PATH = Path(
    os.getenv("WA_KIBANA_CRED_PATH", SECRETS_DIR / "wa_kibana.json")
)
ABUSEIPDB_KEY_PATH = Path(
    os.getenv("ABUSEIPDB_KEY_PATH", SECRETS_DIR / "abuseipdb.json")
)


DEBUG_PRINT_KIBANA_REQUEST = os.getenv("DEBUG_PRINT_KIBANA_REQUEST", "0") == "1"


# Load secrets JSON from disk and validate required keys exist.
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

    
# Parse CLI flags like --ip and --abuse-verbose.
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


# Normalize and validate IPs from user input; skip invalid/private ranges.
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
                print(f"{C.YELLOW}[!] Skipping private IP: {ip_str}{C.RESET}")
                continue
            ips.append(str(ip_obj))
        except ValueError:
            print(f"{C.YELLOW}[!] Skipping invalid IP: {ip_str}{C.RESET}")

    # de-dupe while preserving order
    return list(dict.fromkeys(ips))


# Interactive menu: choose Kibana mode or manual AbuseIPDB lookup.
def prompt_user_mode_and_inputs():
    """Prompt user to choose Kibana mode or manual AbuseIPDB lookup and collect inputs."""
    print(f"\n{C.BOLD}{C.WHITE}Select mode:{C.RESET}")
    print(f"  {C.CYAN}1){C.RESET} Query Kibana / Elasticsearch (then check IPs in AbuseIPDB)")
    print(f"  {C.CYAN}2){C.RESET} Manual AbuseIPDB lookup (enter IP address(es))")

    while True:
        choice = input(f"{C.BOLD}Enter 1 or 2: {C.RESET}").strip()
        if choice in {"1", "2"}:
            break
        print(f"{C.YELLOW}[!] Please enter 1 or 2.{C.RESET}")

    if choice == "1":
        return "kibana", []

    # Option 2: force valid IP input so we never accidentally fall through to Kibana mode
    while True:
        ip_text = input(f"{C.BOLD}Enter IP(s) (comma-separated): {C.RESET}").strip()
        manual_ips = normalize_ips([ip_text])
        if manual_ips:
            return "manual", manual_ips
        print(f"{C.YELLOW}[!] No valid IPs entered. Try again (or press Ctrl+C to cancel).{C.RESET}")


# Prompt user for custom query and result count when in Kibana mode.
def prompt_kibana_options():
    """Prompt the user for a custom Lucene query, timeframe, and how many results to return."""
    print(f"\n{C.BOLD}{C.WHITE}Query Configuration{C.RESET}")
    print(f"{C.CYAN}{'─' * 70}{C.RESET}")
    print(f"  {C.DIM}Default query:{C.RESET} {C.YELLOW}{DEFAULT_QUERY}{C.RESET}")
    print(f"  {C.DIM}Default time range:{C.RESET} {DEFAULT_TIME_RANGE} to now")

    print(f"\n  {C.BOLD}{C.WHITE}Example queries (Lucene syntax):{C.RESET}")
    print(f"  {C.DIM}─────────────────────────────────────────────────────────────{C.RESET}")
    print(f"  {C.YELLOW}event_type:\"alert\"{C.RESET}")
    print(f"    {C.DIM}All alerts{C.RESET}")
    print(f"  {C.YELLOW}event_type:\"alert\" AND alert.severity:[0 TO 1]{C.RESET}")
    print(f"    {C.DIM}High severity alerts only (severity 0 or 1){C.RESET}")
    print(f"  {C.YELLOW}event_type:\"alert\" AND alert.signature:ET*{C.RESET}")
    print(f"    {C.DIM}Emerging Threats alerts{C.RESET}")
    print(f"  {C.YELLOW}event_type:\"alert\" AND alert.signature:(*MALWARE* OR *TROJAN*){C.RESET}")
    print(f"    {C.DIM}Malware / Trojan related alerts{C.RESET}")
    print(f"  {C.YELLOW}src_ip:\"192.168.1.100\" AND event_type:\"alert\"{C.RESET}")
    print(f"    {C.DIM}Alerts from a specific source IP{C.RESET}")
    print(f"  {C.YELLOW}dest_ip:\"10.0.0.5\" AND alert.severity:1{C.RESET}")
    print(f"    {C.DIM}Severity 1 alerts targeting a specific dest IP{C.RESET}")
    print(f"  {C.YELLOW}event_type:\"alert\" AND alert.signature:(*C2* OR *BOTNET* OR *EXPLOIT*){C.RESET}")
    print(f"    {C.DIM}C2, botnet, or exploit activity{C.RESET}")
    print(f"  {C.YELLOW}event_type:\"dns\" AND dns.query.rrname:*.ru{C.RESET}")
    print(f"    {C.DIM}DNS queries to .ru domains{C.RESET}")
    print(f"  {C.DIM}─────────────────────────────────────────────────────────────{C.RESET}")

    # Timeframe selection (standard presets + custom)
    presets = [
        ("15m", "Last 15 minutes"),
        ("1h", "Last 1 hour"),
        ("6h", "Last 6 hours"),
        ("24h", "Last 24 hours"),
        ("48h", "Last 48 hours"),
        ("7d", "Last 7 days"),
        ("30d", "Last 30 days"),
        ("custom", "Custom (e.g., 2h, 12h, 3d)"),
    ]
    print(f"\n  {C.BOLD}{C.WHITE}Time range presets:{C.RESET}")
    for i, (key, desc) in enumerate(presets, start=1):
        default_tag = f"{C.DIM} (default){C.RESET}" if key == DEFAULT_TIME_RANGE.replace("now-", "") else ""
        print(f"    {C.CYAN}{i}){C.RESET} {C.YELLOW}{key}{C.RESET} - {C.DIM}{desc}{C.RESET}{default_tag}")

    choice = input(
        f"\n{C.BOLD}Select a time range{C.RESET} {C.DIM}(1-{len(presets)}, Enter for default){C.RESET}: "
    ).strip()
    selected = None
    if choice:
        try:
            idx = int(choice)
            if 1 <= idx <= len(presets):
                selected = presets[idx - 1][0]
        except ValueError:
            selected = None

    if not selected:
        # DEFAULT_TIME_RANGE is like "now-48h" → keep as-is
        time_gte = DEFAULT_TIME_RANGE
    elif selected == "custom":
        custom_tf = input(
            f"{C.BOLD}Enter custom time window{C.RESET} {C.DIM}(examples: 2h, 12h, 3d){C.RESET}: "
        ).strip()
        custom_tf = custom_tf if custom_tf else DEFAULT_TIME_RANGE.replace("now-", "")
        time_gte = f"now-{custom_tf}"
    else:
        time_gte = f"now-{selected}"

    custom = input(
        f"\n{C.BOLD}Enter a custom Lucene query{C.RESET} "
        f"{C.DIM}(or press Enter for default){C.RESET}: "
    ).strip()
    query = custom if custom else DEFAULT_QUERY

    count_input = input(
        f"{C.BOLD}How many results?{C.RESET} "
        f"{C.DIM}(default {DEFAULT_RESULT_COUNT}){C.RESET}: "
    ).strip()
    try:
        count = int(count_input) if count_input else DEFAULT_RESULT_COUNT
        if count < 1:
            count = DEFAULT_RESULT_COUNT
    except ValueError:
        print(f"{C.YELLOW}[!] Invalid number, using default ({DEFAULT_RESULT_COUNT}).{C.RESET}")
        count = DEFAULT_RESULT_COUNT

    print(f"\n{C.GREEN}[✓] Query:{C.RESET}   {C.YELLOW}{query}{C.RESET}")
    print(f"{C.GREEN}[✓] Time:{C.RESET}    {time_gte} → now")
    print(f"{C.GREEN}[✓] Results:{C.RESET} {count}")
    return query, count, time_gte


# Build the Elasticsearch query payload dynamically.
def build_query_payload(query: str = DEFAULT_QUERY, size: int = DEFAULT_RESULT_COUNT, time_gte: str = DEFAULT_TIME_RANGE):
    """Build the Elasticsearch JSON query payload with the given Lucene query and result size."""
    return {
      "size": size,
      "_source": [
        "@timestamp", "timestamp", "src_ip", "dest_ip", "src_port", "dest_port",
        "proto", "app_proto", "traffic_type", "in_iface", "geoip.src_country.*",
        "geoip.dest_country.*", "geoip.src.*", "geoip.dest.*", "frame.length",
        "frame.direction", "frame.stream_offset", "frame.payload",
        "frame.payload_printable", "host.hostname", "host.os.*",
        "host.architecture", "host.containerized", "host.ip", "flow_id",
        "community_id", "flow.pkts_toserver", "flow.pkts_toclient",
        "flow.bytes_toserver", "flow.bytes_toclient", "dns.query.*",
        "suricata.eve.alert.*", "alert.*", "log.file.path", "tags", "message",
        "event_type"
      ],
      "query": {
        "bool": {
          "must": [
            {
              "query_string": {
                "query": query
              }
            },
            { "range": { "@timestamp": { "gte": time_gte, "lte": "now" } } }
          ]
        }
      },
      "sort": [ { "@timestamp": { "order": "desc" } } ]
    }


# Query Kibana/Elasticsearch for recent Suricata alert hits.
def get_suricata_logs(username: str, password: str, payload: dict):
    """Query Kibana/Elasticsearch for the latest Suricata alert hits and return the hits list."""
    try:
        headers = {
            "kbn-xsrf": "true",
            "Content-Type": "application/json",
        }

        print(f"{C.CYAN}[*] Querying Kibana / Elasticsearch for latest Suricata alerts...{C.RESET}")
        if DEBUG_PRINT_KIBANA_REQUEST:
            print_kibana_request(ELASTIC_URL, headers, payload, username)

        # Mimicking Postman POST request with Basic Auth
        response = requests.post(
            ELASTIC_URL,
            json=payload,
            auth=HTTPBasicAuth(username, password),
            headers=headers,
            verify=False # Equivalent to turning off SSL verification in Postman
        )

        response.raise_for_status()
        data = response.json()
        
        # Accessing the list of logs (hits)
        hits = data.get('hits', {}).get('hits', [])
        print(f"{C.GREEN}[✓] Successfully retrieved {len(hits)} alert(s) from Suricata.{C.RESET}")
        return hits

    except Exception as e:
        print(f"{C.RED}[!] Error: {e}{C.RESET}")
        return []


# Extract unique public source IPs (src_ip) from Kibana hits.
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
        except ValueError:
            continue
        if ip_obj.is_private:
            continue
        ips.add(str(ip_obj))
    return sorted(ips)


# Call AbuseIPDB "check" API for a single IP.
def check_ip_abuse(ip_address: str, api_key: str, max_age_days: int, verbose: bool):
    """Call AbuseIPDB 'check' API for one IP and return the response 'data' dict."""
    headers = {
        "Key": api_key,
        "Accept": "application/json",
    }
    params = {
        "ipAddress": ip_address,
        "maxAgeInDays": max_age_days,
        "verbose": "true" if verbose else "false",
    }
    response = requests.get(ABUSEIPDB_URL, headers=headers, params=params, timeout=30)
    response.raise_for_status()
    return response.json().get("data", {})


# Print a clean, color-coded AbuseIPDB report.
def print_abuseipdb_report(ip_address: str, data: dict, match_context=None):
    """Print a clean, color-coded AbuseIPDB report for one IP.

    match_context: list of dicts with keys: idx, signature, severity, timestamp
    """
    score = data.get("abuseConfidenceScore", 0)
    sc = abuse_score_color(score)

    # Header
    print(f"\n{C.BOLD}{C.MAGENTA}{'═' * 70}{C.RESET}")
    print(f"  {C.BOLD}{C.WHITE}AbuseIPDB Report:{C.RESET}  {C.CYAN}{ip_address}{C.RESET}")

    if match_context:
        print(f"\n  {C.BOLD}{C.WHITE}Triggered by:{C.RESET}")
        for m in match_context:
            sev = m.get("severity")
            sev_col = severity_color(sev)
            sev_tag = f"{sev_col}SEV {sev}{C.RESET}" if sev is not None else f"{C.DIM}SEV ?{C.RESET}"
            sig = m.get("signature") or "Unknown signature"
            ts = m.get("timestamp") or ""
            print(f"    {C.BOLD}Match {m['idx']}{C.RESET}  {sev_tag}  {C.YELLOW}{sig}{C.RESET}")
            if ts:
                print(f"             {C.DIM}{ts}{C.RESET}")
    print(f"{C.MAGENTA}{'─' * 70}{C.RESET}")

    # Abuse score (prominent)
    score_bar = "█" * (score // 5) + "░" * (20 - score // 5)
    risk_label = "CRITICAL" if score >= 75 else "HIGH" if score >= 40 else "MODERATE" if score >= 10 else "LOW"
    print(f"  {C.BOLD}Abuse Score:{C.RESET}  {sc}{C.BOLD}{score}%{C.RESET}  {sc}{score_bar}{C.RESET}  {sc}{C.BOLD}[{risk_label}]{C.RESET}")

    # Whitelisted?
    wl = data.get("isWhitelisted")
    if wl:
        print(f"  {C.GREEN}{C.BOLD}✓ WHITELISTED{C.RESET}")

    # Location
    country = data.get("countryName") or data.get("countryCode")
    region = data.get("region")
    if country:
        loc_parts = [country]
        if region:
            loc_parts.append(region)
        print(f"\n  {C.BOLD}{C.WHITE}Location{C.RESET}     {', '.join(loc_parts)}")

    # Network info
    isp = data.get("isp")
    domain = data.get("domain")
    usage = data.get("usageType")
    if isp:
        print(f"  {C.BOLD}{C.WHITE}ISP{C.RESET}          {isp}")
    if domain:
        print(f"  {C.BOLD}{C.WHITE}Domain{C.RESET}       {C.YELLOW}{domain}{C.RESET}")
    if usage:
        print(f"  {C.BOLD}{C.WHITE}Usage Type{C.RESET}   {usage}")

    # Reports
    total = data.get("totalReports", 0)
    last_reported = data.get("lastReportedAt")
    report_color = C.RED if total >= 50 else C.YELLOW if total >= 10 else C.GREEN
    print(f"\n  {C.BOLD}{C.WHITE}Reports{C.RESET}      {report_color}{total}{C.RESET} total")
    if last_reported:
        print(f"  {C.BOLD}{C.WHITE}Last Seen{C.RESET}    {last_reported}")

    print(f"{C.MAGENTA}{'─' * 70}{C.RESET}")


# Flatten nested dict/list structures into dotted keys for readable printing.
def _flatten(obj, prefix=""):
    """Flatten nested dict/list structures into dotted keys for readable printing."""
    flat = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = f"{prefix}.{k}" if prefix else str(k)
            flat.update(_flatten(v, key))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            key = f"{prefix}[{i}]"
            flat.update(_flatten(v, key))
    else:
        flat[prefix] = obj
    return flat


# Convert bytes to a human-friendly string (B, KB, MB, GB).
def _bytes_human(value) -> str:
    """Convert bytes to a human-readable string."""
    try:
        b = float(value)
    except (TypeError, ValueError):
        return "0 B"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(b) < 1024:
            return f"{b:.1f} {unit}"
        b /= 1024
    return f"{b:.1f} PB"


# Build a clickable Kibana Discover URL that filters to a specific document.
def build_kibana_url(doc_id: str, index: str) -> str:
    """Build a Kibana Discover URL that links to the specific document."""
    # Uses Kibana's doc view: /app/discover#/doc/<index-pattern-id>/<index>?id=<doc_id>
    # The index pattern ID is the Kibana saved-object UUID for the suricata-* data view.
    index_pattern_id = "1e738c90-2c6a-11f0-bce4-7d11b23f0172"
    encoded_id = urllib.parse.quote(doc_id, safe="")
    encoded_index = urllib.parse.quote(index, safe="")
    return f"{KIBANA_BASE_URL}/app/discover#/doc/{index_pattern_id}/{encoded_index}?id={encoded_id}"


# Print a clean, color-coded summary of one Suricata/Kibana hit.
def print_suricata_hit(idx: int, hit: dict):
    """Print one Suricata/Kibana hit in a clean, color-coded format."""
    source = hit.get("_source", {})
    doc_id = hit.get("_id", "")
    doc_index = hit.get("_index", "")

    ts = source.get("@timestamp") or source.get("timestamp")
    src_ip = source.get("src_ip")
    dest_ip = source.get("dest_ip")
    src_port = source.get("src_port")
    dest_port = source.get("dest_port")
    proto = source.get("proto")
    app_proto = source.get("app_proto")

    # Suricata alert fields can appear in different places depending on pipeline
    alert = source.get("alert") or {}
    suricata_alert = (
        (((source.get("suricata") or {}).get("eve") or {}).get("alert")) or {}
    )
    signature = (
        suricata_alert.get("signature")
        or alert.get("signature")
        or source.get("suricata.eve.alert.signature")
    )
    category = suricata_alert.get("category") or alert.get("category")
    severity = suricata_alert.get("severity") or alert.get("severity")
    signature_id = suricata_alert.get("signature_id") or alert.get("signature_id")

    # GeoIP (best effort)
    geoip = source.get("geoip") or {}
    src_country = (
        ((geoip.get("src_country") or {}).get("name"))
        or ((geoip.get("src_country") or {}).get("iso_code"))
    )
    dest_country = (
        ((geoip.get("dest_country") or {}).get("name"))
        or ((geoip.get("dest_country") or {}).get("iso_code"))
    )

    # Flow traffic
    flow = source.get("flow") or {}
    pkts_to = flow.get("pkts_toserver")
    pkts_from = flow.get("pkts_toclient")
    bytes_to = flow.get("bytes_toserver")
    bytes_from = flow.get("bytes_toclient")

    # Severity tag
    sev_col = severity_color(severity)
    sev_label = f"{sev_col}{C.BOLD} SEV {severity} {C.RESET}" if severity is not None else ""

    # ── Header ──
    print(f"\n{C.BOLD}{C.CYAN}{'═' * 70}{C.RESET}")
    print(f"{C.BOLD}{C.WHITE}  MATCH {idx}{C.RESET}  {sev_label}  {C.DIM}{ts or ''}{C.RESET}")
    print(f"{C.CYAN}{'─' * 70}{C.RESET}")

    # ── Alert Signature (most important) ──
    if signature:
        print(f"  {C.BOLD}{C.RED}SIGNATURE{C.RESET}  {C.YELLOW}{signature}{C.RESET}")
    if signature_id is not None:
        print(f"  {C.DIM}SID{C.RESET}        {signature_id}")
    if category:
        print(f"  {C.BOLD}{C.MAGENTA}CATEGORY{C.RESET}   {category}")

    # ── Flow ID ──
    flow_id = source.get("flow_id")
    community_id = source.get("community_id")
    if flow_id:
        print(f"\n  {C.BOLD}{C.WHITE}FLOW ID{C.RESET}    {C.CYAN}{flow_id}{C.RESET}")
    if community_id:
        print(f"  {C.DIM}Community: {community_id}{C.RESET}")

    # ── Network Flow ──
    print(f"\n  {C.BOLD}{C.WHITE}FLOW{C.RESET}")
    src_geo = f"  ({src_country})" if src_country else ""
    dst_geo = f"  ({dest_country})" if dest_country else ""
    print(f"    {C.CYAN}{src_ip}:{src_port}{C.RESET}{C.DIM}{src_geo}{C.RESET}")
    print(f"      {C.BOLD}→{C.RESET}  {proto or '?'}/{app_proto or '?'}")
    print(f"    {C.CYAN}{dest_ip}:{dest_port}{C.RESET}{C.DIM}{dst_geo}{C.RESET}")

    # ── Traffic stats (if available) ──
    if any(v is not None for v in [pkts_to, pkts_from, bytes_to, bytes_from]):
        print(f"\n  {C.BOLD}{C.WHITE}TRAFFIC{C.RESET}")
        if pkts_to is not None or pkts_from is not None:
            print(f"    Packets:  {C.GREEN}→ {pkts_to or 0}{C.RESET}  /  {C.BLUE}← {pkts_from or 0}{C.RESET}")
        if bytes_to is not None or bytes_from is not None:
            b_to = _bytes_human(bytes_to)
            b_from = _bytes_human(bytes_from)
            print(f"    Bytes:    {C.GREEN}→ {b_to}{C.RESET}  /  {C.BLUE}← {b_from}{C.RESET}")

    # ── Host info (compact, if available) ──
    host = source.get("host") or {}
    hostname = host.get("hostname")
    host_ips = host.get("ip")
    if hostname:
        print(f"\n  {C.BOLD}{C.WHITE}HOST{C.RESET}       {hostname}")
    if host_ips:
        if isinstance(host_ips, list):
            host_ips = ", ".join(host_ips)
        print(f"    {C.DIM}IPs: {host_ips}{C.RESET}")

    # ── DNS (if available) ──
    dns = source.get("dns") or {}
    dns_query = dns.get("query")
    if dns_query:
        if isinstance(dns_query, list):
            for q in dns_query:
                qname = q.get("name") or q.get("rrname") if isinstance(q, dict) else q
                if qname:
                    print(f"\n  {C.BOLD}{C.WHITE}DNS{C.RESET}        {C.YELLOW}{qname}{C.RESET}")
        elif isinstance(dns_query, dict):
            qname = dns_query.get("name") or dns_query.get("rrname")
            if qname:
                print(f"\n  {C.BOLD}{C.WHITE}DNS{C.RESET}        {C.YELLOW}{qname}{C.RESET}")

    # ── Kibana Link ──
    if doc_id and doc_index:
        kibana_url = build_kibana_url(doc_id, doc_index)
        print(f"\n  {C.BOLD}{C.BLUE}KIBANA{C.RESET}     {C.DIM}{kibana_url}{C.RESET}")

    print(f"{C.CYAN}{'─' * 70}{C.RESET}")


# Entrypoint: interactive selection, Kibana query, and/or manual AbuseIPDB checks.
def main():
    """Program entrypoint: interactive mode selection, Kibana query, and/or AbuseIPDB checks."""
    print(BANNER)
    args = parse_args()
    manual_ips = normalize_ips(args.ip)

    # If user provided no CLI flags, prompt interactively (when possible)
    max_age_days = args.max_age_days
    abuse_verbose = args.abuse_verbose
    custom_query = DEFAULT_QUERY
    result_count = DEFAULT_RESULT_COUNT
    time_gte = DEFAULT_TIME_RANGE

    if not manual_ips and len(sys.argv) == 1 and sys.stdin.isatty():
        try:
            mode, manual_ips = prompt_user_mode_and_inputs()
            # In interactive mode, don't ask for max age; always use default.
            max_age_days = ABUSEIPDB_MAX_AGE_DAYS
            if mode == "kibana":
                manual_ips = []
                custom_query, result_count, time_gte = prompt_kibana_options()
        except (EOFError, KeyboardInterrupt):
            print(f"\n{C.YELLOW}[*] Cancelled.{C.RESET}")
            return

    # Manual AbuseIPDB mode (skips Kibana query)
    if manual_ips:
        abuseipdb = load_json_file(
            ABUSEIPDB_KEY_PATH, {"api_key"}, "abuseipdb.example.json"
        )
        print(f"{C.CYAN}[*] Checking {len(manual_ips)} manual IP(s) against AbuseIPDB...{C.RESET}")
        for ip_address in manual_ips:
            try:
                data = check_ip_abuse(
                    ip_address, abuseipdb["api_key"], max_age_days, abuse_verbose
                )
                print_abuseipdb_report(ip_address, data)
            except Exception as exc:
                print(f"{C.RED}[!] AbuseIPDB error for {ip_address}: {exc}{C.RESET}")
        return

    # Normal mode: Kibana query + AbuseIPDB checks for extracted IPs
    wa_kibana = load_json_file(
        WA_KIBANA_CRED_PATH, {"username", "password"}, "wa_kibana.example.json"
    )
    abuseipdb = load_json_file(
        ABUSEIPDB_KEY_PATH, {"api_key"}, "abuseipdb.example.json"
    )

    payload = build_query_payload(query=custom_query, size=result_count, time_gte=time_gte)
    logs = get_suricata_logs(wa_kibana["username"], wa_kibana["password"], payload)
    if logs:
        ip_to_context = {}  # {ip: [{idx, signature, severity, timestamp}, ...]}
        for idx, hit in enumerate(logs, start=1):
            print_suricata_hit(idx, hit)
            source = hit.get("_source", {})
            src_ip = source.get("src_ip")
            if src_ip:
                # Extract alert details for context
                alert = source.get("alert") or {}
                suricata_alert = (
                    (((source.get("suricata") or {}).get("eve") or {}).get("alert")) or {}
                )
                sig = (
                    suricata_alert.get("signature")
                    or alert.get("signature")
                    or source.get("suricata.eve.alert.signature")
                )
                sev = suricata_alert.get("severity") or alert.get("severity")
                ts = source.get("@timestamp") or source.get("timestamp")
                ip_to_context.setdefault(src_ip, []).append({
                    "idx": idx,
                    "signature": sig,
                    "severity": sev,
                    "timestamp": ts,
                })

        ips = extract_ips(logs)
        if ips:
            print(f"\n{C.CYAN}[*] Checking {len(ips)} unique public IP(s) against AbuseIPDB...{C.RESET}")
            for ip_address in ips:
                try:
                    data = check_ip_abuse(
                        ip_address, abuseipdb["api_key"], max_age_days, abuse_verbose
                    )
                    print_abuseipdb_report(
                        ip_address, data, match_context=ip_to_context.get(ip_address)
                    )
                except Exception as exc:
                    print(f"{C.RED}[!] AbuseIPDB error for {ip_address}: {exc}{C.RESET}")
        else:
            print(f"{C.YELLOW}[*] No public IPs found in results to check.{C.RESET}")


if __name__ == "__main__":
    main()