# This program uses the 'rich' library for formatted output.
# Install it with: pip install rich
import json
import os
import argparse
import ipaddress
import sys
from pathlib import Path
from typing import Any, Dict, List

import requests
from requests.auth import HTTPBasicAuth
import urllib3

# --- Rich Library Imports ---
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree
from rich.syntax import Syntax
from rich.style import Style

# Suppress SSL warnings if your ELK uses self-signed certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- Rich Console Initialization ---
console = Console()

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
    console.print("\n[bold cyan]=== Kibana Request (sanitized) ===[/bold cyan]")
    console.print(f"[bold]URL:[/bold] {url}")
    console.print(f"[bold]Auth:[/bold] Basic (username={username}, password=<redacted>)")
    console.print("[bold]Headers:[/bold]")
    console.print(Syntax(json.dumps(headers, indent=2), "json", theme="default"))
    console.print("[bold]JSON Body:[/bold]")
    console.print(Syntax(json.dumps(payload, indent=2), "json", theme="default"))
    console.print("[bold cyan]=== End Kibana Request ===[/bold cyan]\n")


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
                console.print(f"[yellow][!] Skipping private IP: {ip_str}[/yellow]")
                continue
            ips.append(str(ip_obj))
        except ValueError:
            console.print(f"[yellow][!] Skipping invalid IP: {ip_str}[/yellow]")

    # de-dupe while preserving order
    return list(dict.fromkeys(ips))


def prompt_user_mode_and_inputs():
    """
    Interactive prompt to choose between:
    1) Kibana query mode
    2) Manual AbuseIPDB IP lookup mode

    Returns: (mode, manual_ips)
      - mode: "kibana" or "manual"
    """
    console.print("\n[bold]Select mode:[/bold]")
    console.print("  [cyan]1)[/cyan] Query Kibana / Elasticsearch (then check IPs in AbuseIPDB)")
    console.print("  [cyan]2)[/cyan] Manual AbuseIPDB lookup (enter IP address(es))")

    while True:
        choice = console.input("Enter [cyan]1[/cyan] or [cyan]2[/cyan]: ").strip()
        if choice in {"1", "2"}:
            break
        console.print("[red][!] Please enter 1 or 2.[/red]")

    if choice == "1":
        return "kibana", []

    # Option 2: force valid IP input so we never accidentally fall through to Kibana mode
    while True:
        ip_text = console.input("Enter IP(s) (comma-separated): ").strip()
        manual_ips = normalize_ips([ip_text])
        if manual_ips:
            return "manual", manual_ips
        console.print("[red][!] No valid IPs entered. Try again (or press Ctrl+C to cancel).[/red]")

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

def get_suricata_logs(username: str, password: str):
    """Query Kibana/Elasticsearch for the latest Suricata alert hits and return the hits list."""
    try:
        headers = {
            "kbn-xsrf": "true",
            "Content-Type": "application/json",
        }

        console.print("[*] Querying Kibana / Elasticsearch for latest Suricata alerts...")
        if DEBUG_PRINT_KIBANA_REQUEST:
            print_kibana_request(ELASTIC_URL, headers, query_payload, username)

        response = requests.post(
            ELASTIC_URL,
            json=query_payload,
            auth=HTTPBasicAuth(username, password),
            headers=headers,
            verify=False
        )

        response.raise_for_status()
        data = response.json()
        
        hits = data.get('hits', {}).get('hits', [])
        console.print(f"[*] Successfully retrieved [bold green]{len(hits)}[/bold green] logs from Suricata.")
        return hits

    except Exception as e:
        console.print(f"[red][!] Error: {e}[/red]")
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
        except ValueError:
            continue
        if ip_obj.is_private:
            continue
        ips.add(str(ip_obj))
    return sorted(ips)


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


def get_abuse_score_style(score: int) -> Style:
    """Return a Rich Style based on the AbuseIPDB confidence score."""
    if score >= 90:
        return Style(color="red", bold=True)
    if score >= 50:
        return Style(color="yellow")
    if score > 0:
        return Style(color="cyan")
    return Style(color="green")


def print_abuseipdb_report(ip_address: str, data: dict, match_indices=None):
    """Print a compact, rich-formatted AbuseIPDB report for one IP."""
    
    report_url = f"https://www.abuseipdb.com/check/{ip_address}"
    title = f"AbuseIPDB Report for [bold blue link={report_url}]{ip_address}[/bold blue link]"
    
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Field", style="bold magenta")
    table.add_column("Value")

    # Location Info
    country = data.get("countryName")
    region = data.get("region")
    location = f"{country}, {region}" if country and region else country or region or "N/A"
    table.add_row("Location:", location)
    
    # Core Fields
    score = data.get("abuseConfidenceScore", 0)
    score_style = get_abuse_score_style(score)
    table.add_row("Abuse Score:", f"[{score_style.color}]{score}[/{score_style.color}]", style=score_style)
    table.add_row("ISP:", data.get("isp", "N/A"))
    table.add_row("Domain:", data.get("domain", "N/A"))
    table.add_row("Usage Type:", data.get("usageType", "N/A"))
    table.add_row("Total Reports:", str(data.get("totalReports", 0)))
    table.add_row("Last Reported:", data.get("lastReportedAt", "N/A"))
    table.add_row("Whitelisted:", "Yes" if data.get("isWhitelisted") else "No")

    if match_indices:
        match_list = ", ".join(f"[cyan]#{idx}[/cyan]" for idx in sorted(set(match_indices)))
        table.add_row("Kibana Matches:", match_list)

    console.print(Panel(table, title=title, border_style="blue", expand=False))


def add_to_tree(tree: Tree, data: Any, key: str = "data"):
    """Recursively add dictionary/list items to a rich Tree."""
    if isinstance(data, dict):
        branch = tree.add(f"[bold magenta]:book: {key}[/bold magenta]")
        for k, v in data.items():
            add_to_tree(branch, v, str(k))
    elif isinstance(data, list):
        branch = tree.add(f"[bold magenta]:list: {key}[/bold magenta]")
        for i, v in enumerate(data):
            add_to_tree(branch, v, f"[{i}]")
    else:
        tree.add(f"[bold green]{key}[/bold green]: [default]{data!r}[/default]")


def print_suricata_hit(idx: int, source: dict):
    """
    Nicely print a Suricata/Kibana hit using rich Panels, Tables, and a Tree.
    """
    ts = source.get("@timestamp") or source.get("timestamp")
    src_ip = source.get("src_ip")
    dest_ip = source.get("dest_ip")
    src_port = source.get("src_port")
    dest_port = source.get("dest_port")

    # Suricata alert fields
    alert = source.get("alert") or {}
    suricata_alert = source.get("suricata", {}).get("eve", {}).get("alert", {})
    signature = suricata_alert.get("signature") or alert.get("signature")
    category = suricata_alert.get("category") or alert.get("category")
    severity = suricata_alert.get("severity") or alert.get("severity")

    # GeoIP
    geoip = source.get("geoip", {})
    src_country = geoip.get("src_country", {}).get("name")
    dest_country = geoip.get("dest_country", {}).get("name")

    # Main Summary Table
    summary_table = Table(title="[bold]Summary[/bold]", show_header=False, box=None, padding=(0, 1))
    summary_table.add_column(style="bold cyan")
    summary_table.add_column()
    summary_table.add_row("Timestamp:", str(ts))
    summary_table.add_row("Flow:", f"{src_ip}:{src_port} -> {dest_ip}:{dest_port}")
    if src_country or dest_country:
        summary_table.add_row("Geo:", f"{src_country or '?'} -> {dest_country or '?'}")
    
    # Alert Details Table
    alert_table = Table(title="[bold]Alert[/bold]", show_header=False, box=None, padding=(0, 1))
    alert_table.add_column(style="bold red")
    alert_table.add_column()
    if signature:
        alert_table.add_row("Signature:", signature)
    if category:
        alert_table.add_row("Category:", category)
    if severity is not None:
        alert_table.add_row("Severity:", str(severity))

    # Full Data Tree
    tree = Tree("[bold]Full Event Data[/bold]", guide_style="cyan")
    add_to_tree(tree, source)

    # Combine into a single panel
    grid = Table.grid(expand=True)
    grid.add_column()
    grid.add_row(summary_table)
    if alert_table.row_count > 0:
        grid.add_row(alert_table)
    grid.add_row(tree)
    
    console.print(Panel(
        grid,
        title=f"[bold]Suricata Match #{idx}[/bold]",
        border_style="green",
        expand=False
    ))


def main():
    """Program entrypoint: interactive mode selection, Kibana query, and/or AbuseIPDB checks."""
    console.print(f"[bold cyan]{BANNER}[/bold cyan]")
    args = parse_args()
    manual_ips = normalize_ips(args.ip)

    max_age_days = args.max_age_days
    abuse_verbose = args.abuse_verbose
    if not manual_ips and len(sys.argv) == 1 and sys.stdin.isatty():
        try:
            mode, manual_ips = prompt_user_mode_and_inputs()
            max_age_days = ABUSEIPDB_MAX_AGE_DAYS
            if mode == "kibana":
                manual_ips = []
        except (EOFError, KeyboardInterrupt):
            console.print("\n[*] Cancelled.")
            return

    # Manual AbuseIPDB mode
    if manual_ips:
        abuseipdb = load_json_file(
            ABUSEIPDB_KEY_PATH, {"api_key"}, "abuseipdb.example.json"
        )
        console.print(f"[*] Checking [bold green]{len(manual_ips)}[/bold green] manual IP(s) against AbuseIPDB...")
        for ip_address in manual_ips:
            try:
                data = check_ip_abuse(
                    ip_address, abuseipdb["api_key"], max_age_days, abuse_verbose
                )
                print_abuseipdb_report(ip_address, data)
            except Exception as exc:
                console.print(f"[red][!] AbuseIPDB error for {ip_address}: {exc}[/red]")
        return

    # Normal mode: Kibana query + AbuseIPDB
    wa_kibana = load_json_file(
        WA_KIBANA_CRED_PATH, {"username", "password"}, "wa_kibana.example.json"
    )
    abuseipdb = load_json_file(
        ABUSEIPDB_KEY_PATH, {"api_key"}, "abuseipdb.example.json"
    )

    logs = get_suricata_logs(wa_kibana["username"], wa_kibana["password"])
    if not logs:
        return

    # Process and display Suricata hits
    ip_to_matches = {}
    for idx, hit in enumerate(logs, start=1):
        source = hit.get("_source", {})
        print_suricata_hit(idx, source)
        src_ip = source.get("src_ip")
        if src_ip:
            ip_to_matches.setdefault(src_ip, []).append(idx)

    # Check extracted IPs against AbuseIPDB
    ips = extract_ips(logs)
    if ips:
        console.print(f"\n[*] Checking [bold green]{len(ips)}[/bold green] IPs against AbuseIPDB...")
        for ip_address in ips:
            try:
                data = check_ip_abuse(
                    ip_address, abuseipdb["api_key"], max_age_days, abuse_verbose
                )
                print_abuseipdb_report(
                    ip_address, data, match_indices=ip_to_matches.get(ip_address)
                )
            except Exception as exc:
                console.print(f"[red][!] AbuseIPDB error for {ip_address}: {exc}[/red]")
    else:
        console.print("[*] No IPs found in logs to check.")


if __name__ == "__main__":
    main()