You are a SOC analyst. Analyze this Suricata IDS alert and generate an incident report.

**Alert:**
{ALERT_MESSAGE}

Based on this data, fill out the following incident report. Return ONLY valid JSON (no markdown, no explanation) with this exact structure:

{
  "summary": "Brief incident title (e.g. ET MALWARE Emotet C2 Communication from 185.x.x.x)",
  "time_and_date": "timestamp from the alert",
  "destination_ip": "destination IP from the alert",
  "destination_port": "destination port",
  "destination_bytes": "bytes sent to server (from flow data)",
  "source_geo_country_name": "source country from GeoIP data or N/A",
  "source_ip": "source IP from the alert",
  "source_port": "source port",
  "source_bytes": "bytes from client (from flow data)",
  "network_protocol": "protocol/app_proto",
  "client_id": "community_id from the alert or N/A",
  "flow_id": "flow_id from the alert or N/A",
  "event": "Brief description of what attack was attempted (a few words)",
  "what_occurred": "Detailed description of what happened",
  "why_it_happened": "Analysis of why this happened",
  "the_result": "What was the result/impact",
  "key_details": "Important details to note",
  "target_asset": "The target system/asset",
  "security_action": "Recommended security action",
  "additional_information": "TL;DR summary of the scenario"
}

IMPORTANT: Return ONLY the JSON object. No markdown formatting, no code fences, no extra text.
