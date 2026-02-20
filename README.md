# Kibana + AbuseIPDB SOC Tool

A command-line SOC (Security Operations Center) tool that queries **Suricata alerts from Kibana/Elasticsearch** and enriches source IPs with **AbuseIPDB** threat intelligence — all from your terminal.

---

## What It Does

1. **Query Kibana/Elasticsearch** for recent Suricata IDS alerts (using Lucene syntax)
2. **Display color-coded alert details** — signature, severity, network flow, GeoIP, traffic stats, DNS, and a direct Kibana link
3. **Extract public source IPs** from the alerts
4. **Check each IP against AbuseIPDB** and display a threat report (abuse score, ISP, location, report count)
5. **Manual IP lookup mode** — skip Kibana and check any IP(s) directly in AbuseIPDB

---

## Project Structure

```
SOC_Program_SEC490/
├── SOC_Program.py                  # Main program
├── README.md                       # This file
└── secrets/
    ├── README.md                   # Setup instructions for secrets
    ├── wa_kibana.example.json      # Template for Kibana credentials
    ├── abuseipdb.example.json      # Template for AbuseIPDB API key
    ├── wa_kibana.json              # Your Kibana credentials (git-ignored)
    └── abuseipdb.json              # Your AbuseIPDB API key (git-ignored)
```

---

## Setup

### 1. Install Python Dependencies

```bash
pip install requests urllib3
```

### 2. Configure Secrets

Copy the example templates and fill in your real credentials:

```bash
cp secrets/wa_kibana.example.json secrets/wa_kibana.json
cp secrets/abuseipdb.example.json secrets/abuseipdb.json
```

Edit `secrets/wa_kibana.json`:
```json
{
  "username": "YOUR_KIBANA_USERNAME",
  "password": "YOUR_KIBANA_PASSWORD"
}
```

Edit `secrets/abuseipdb.json`:
```json
{
  "api_key": "YOUR_ABUSEIPDB_API_KEY"
}
```

> **Note:** The real `*.json` files are git-ignored so your credentials are never pushed to GitHub.

### 3. Get an AbuseIPDB API Key

1. Sign up at [abuseipdb.com](https://www.abuseipdb.com/)
2. Go to your account → API → Create Key
3. Paste it into `secrets/abuseipdb.json`

---

## Usage

### Interactive Mode (recommended)

```bash
python3 SOC_Program.py
```

You'll see a menu:
- **Option 1** — Query Kibana for Suricata alerts, then check extracted IPs in AbuseIPDB
- **Option 2** — Manually enter IP address(es) to check in AbuseIPDB

When using Option 1 (Kibana mode), the tool will prompt you to:
- Select a **time range** (15m, 1h, 6h, 24h, 48h, 7d, 30d, or custom)
- Enter a **custom Lucene query** (or use the default)
- Choose **how many results** to return

### CLI Mode

```bash
# Check specific IPs directly (skips Kibana)
python3 SOC_Program.py --ip 8.8.8.8
python3 SOC_Program.py --ip 1.2.3.4 --ip 5.6.7.8
python3 SOC_Program.py --ip "1.2.3.4,5.6.7.8,9.10.11.12"

# Change AbuseIPDB lookback window (default: 90 days)
python3 SOC_Program.py --ip 8.8.8.8 --max-age-days 30

# Verbose AbuseIPDB output
python3 SOC_Program.py --ip 8.8.8.8 --abuse-verbose
```

---

## Example Lucene Queries (Kibana Mode)

| Query | Description |
|-------|-------------|
| `event_type:"alert"` | All alerts |
| `event_type:"alert" AND alert.severity:[0 TO 1]` | High severity only |
| `event_type:"alert" AND alert.signature:ET*` | Emerging Threats alerts |
| `event_type:"alert" AND alert.signature:(*MALWARE* OR *TROJAN*)` | Malware / Trojan alerts |
| `src_ip:"192.168.1.100" AND event_type:"alert"` | Alerts from a specific source IP |
| `event_type:"alert" AND alert.signature:(*C2* OR *BOTNET* OR *EXPLOIT*)` | C2, botnet, or exploit activity |
| `event_type:"dns" AND dns.query.rrname:*.ru` | DNS queries to .ru domains |

---

## Output

### Suricata Alert Output Includes:
- Timestamp and severity (color-coded: red = critical, yellow = medium, green = low)
- Alert signature, SID, and category
- Network flow (source IP:port → dest IP:port)
- Protocol and application protocol
- GeoIP location (if available)
- Traffic stats (packets and bytes in each direction)
- Host info and DNS queries (if available)
- Direct clickable Kibana link to the document

### AbuseIPDB Report Includes:
- Abuse confidence score with visual bar (color-coded: red = critical, yellow = high, blue = moderate, green = low)
- Risk label (CRITICAL / HIGH / MODERATE / LOW)
- Country, ISP, domain, and usage type
- Total reports and last reported date
- Which Kibana alert(s) triggered the lookup

---

## How It Works (Architecture)

```
User runs SOC_Program.py
        │
        ├── Mode 1: Kibana Query
        │     │
        │     ├── Builds Elasticsearch query (Lucene + time range)
        │     ├── Sends POST to Kibana API (Basic Auth)
        │     ├── Displays color-coded Suricata alert hits
        │     ├── Extracts unique public source IPs
        │     └── Checks each IP against AbuseIPDB API
        │
        └── Mode 2: Manual IP Lookup
              │
              ├── Validates and de-dupes input IPs
              ├── Skips private/invalid IPs
              └── Checks each IP against AbuseIPDB API
```

---

## Technologies Used

- **Python 3** — main language
- **Kibana / Elasticsearch** — Suricata alert data source
- **Suricata IDS** — intrusion detection system generating the alerts
- **AbuseIPDB API** — IP threat intelligence enrichment
- **Lucene Query Syntax** — flexible alert filtering
- **ANSI Colors** — clean, readable terminal output

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `Missing secrets file` | Copy the example templates (see Setup step 2) |
| `NameResolutionError` for AbuseIPDB | Check your internet connection / DNS |
| `401 Unauthorized` from Kibana | Verify username/password in `secrets/wa_kibana.json` |
| `403` from AbuseIPDB | Verify your API key in `secrets/abuseipdb.json` |
| No alerts returned | Try a wider time range or broader query |
