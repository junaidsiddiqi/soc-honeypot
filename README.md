# Azure SOC Honeypot Lab — Live Attack Monitoring with Microsoft Sentinel

## Overview

Within minutes of deployment, my Azure honeypot was under attack.

I built a Windows 11 VM in Azure, intentionally weakened its defenses by disabling the firewall and opening all inbound traffic, and connected it to Microsoft Sentinel for monitoring. The result: in just 18 hours online, the system was flooded with brute force attempts from real attackers across the globe. Every failed login, every IP address, and every attempt was captured in my logs.

## Goals

The goal of this project was to simulate the workflow of a SOC analyst responding to live threat activity:

- **Deploy and expose** a cloud-based honeypot to attract real-world attack traffic
- **Forward logs** to a Log Analytics Workspace via Sentinel connectors and the Azure Monitor Agent
- **Query and investigate** failed login activity using KQL to identify brute force patterns
- **Enrich attacker IPs** with GeoIP data to add geographic context to the attacks
- **Visualize threats** through a Sentinel Workbook that maps attacks in real time across a world map
- **Validate telemetry** locally in Event Viewer to confirm logs matched what Sentinel ingested

These were real attackers actively targeting my VM — and I lured them in and monitored their every move.

---

*Credit to [Josh Madakor](https://www.linkedin.com/in/joshmadakor/) for the project guidance and tutorial framework.*

---

## Architecture

> <img width="851" height="441" alt="image" src="https://github.com/user-attachments/assets/0d138367-b7b4-411b-b341-9d1169047bf0" />

| Component | Purpose |
|---|---|
| Windows 11 Pro N VM (Azure) | Honeypot — intentionally exposed to the internet |
| Network Security Group (NSG) | Configured to allow all inbound traffic |
| VNet-SOC-Lab | Virtual network hosting the honeypot VM |
| Log Analytics Workspace | Central log repository ingesting Windows Security Events |
| Microsoft Sentinel | SIEM — KQL querying, watchlist management, workbook visualization |
| GeoIP Watchlist (55K rows) | IP-to-location enrichment for attack mapping |
| Honeypot Attack Map Workbook | Real-time geographic visualization of failed login attempts |

---

## Tools & Technologies

- Microsoft Azure (VM, VNet, NSG, Log Analytics Workspace)
- Microsoft Sentinel (Defender Portal)
- Windows 11 Pro N
- KQL (Kusto Query Language)
- Azure Monitor / AMA (Azure Monitoring Agent)
- Data Collection Rules (DCR)
- GeoIP CSV Watchlist (54,000+ IP ranges)

---

## Lab Steps

### Part 1 — Deploy the Honeypot VM

Provisioned a Windows 11 Pro N virtual machine in Azure (East US 2, Standard D2s v3 — 2 vCPUs, 8 GiB RAM) inside a resource group named **RG-SOC-Lab**.

Configured the **Network Security Group (CORP-NET-EAST-2-nsg)** with a custom inbound rule at priority 100 allowing all traffic from any source on any port — intentionally making the VM fully exposed to the public internet.

RDP'd into the VM and disabled Windows Defender Firewall across all profiles (Domain, Private, Public) via `wf.msc` to ensure attackers could reach the machine without restriction.

> <img width="3840" height="1824" alt="image" src="https://github.com/user-attachments/assets/3223bf7f-c29e-459d-9778-43106c72a780" />
> <img width="3840" height="1830" alt="image" src="https://github.com/user-attachments/assets/45b571b4-8ad6-49fe-a17b-193d800ea003" />
> <img width="3839" height="2159" alt="image" src="https://github.com/user-attachments/assets/b5f3d40b-faa3-4838-b980-44f2f2a791b7" />

---

### Part 2 — Observe Local Logs

After exposing the VM, failed login attempts (Event ID 4625) began appearing in Windows Event Viewer within minutes — confirming automated scanners had already discovered the machine.

> <img width="1198" height="717" alt="image" src="https://github.com/user-attachments/assets/3c313dae-b1b2-4be9-9381-e5c022dc3c47" />

---

### Part 3 — Set Up Log Analytics Workspace & Sentinel

Created a **Log Analytics Workspace** and connected it to **Microsoft Sentinel** as the central log repository. Configured the **Windows Security Events via AMA** data connector and deployed a **Data Collection Rule (DCR)** to begin forwarding security events from the honeypot VM.

> <img width="3188" height="1651" alt="image" src="https://github.com/user-attachments/assets/95c46ef9-4eb1-47a1-bfc6-100b78cf25a7" />
> <img width="1503" height="862" alt="image" src="https://github.com/user-attachments/assets/dcecfc73-276b-454c-b061-6bc76e50f3e6" />
> <img width="1689" height="868" alt="image" src="https://github.com/user-attachments/assets/fb81d60e-3e95-4379-99cc-b97e796a6fbe" />

---

### Part 4 — Query Logs with KQL

Verified log ingestion by querying the SecurityEvent table in Log Analytics:

```kql
SecurityEvent
| where EventID == 4625
| project TimeGenerated, Account, Computer, EventID, Activity, IpAddress
```

Confirmed failed login attempts were flowing in from external IPs in real time.

> <img width="3188" height="1651" alt="image" src="https://github.com/user-attachments/assets/292c608c-6428-4ab4-b8a5-13d601c175c0" />

---

### Part 5 — Enrich Logs with GeoIP Data

Raw security logs contain only IP addresses — no location data. Imported a GeoIP CSV file (54,000+ IP-to-location mappings) as a **Sentinel Watchlist** named `geoip` with `network` as the search key, which is the column Sentinel indexes to match attacker IPs against the correct geographic row.

> <img width="3840" height="1843" alt="image" src="https://github.com/user-attachments/assets/6f1412f0-f109-4177-a2b8-ff87f74f1339" />

---

### Part 6 — Build the Attack Map

Created a new Sentinel Workbook and used the Advanced Editor to paste a custom JSON configuration that renders a live geographic heatmap of all failed login attempts, sized and colored by attack volume.

The workbook query uses `ipv4_lookup` to join each attacker's IP against the GeoIP watchlist and surface location data:

```kql
let GeoIPDB_FULL = _GetWatchlist("geoip");
let WindowsEvents = SecurityEvent;
WindowsEvents | where EventID == 4625
| order by TimeGenerated desc
| evaluate ipv4_lookup(GeoIPDB_FULL, IpAddress, network)
| summarize FailureCount = count() by IpAddress, latitude, longitude, cityname, countryname
| project FailureCount, AttackerIp = IpAddress, latitude, longitude, city = cityname, country = countryname,
friendly_location = strcat(cityname, " (", countryname, ")");
```

> <img width="1215" height="687" alt="image" src="https://github.com/user-attachments/assets/ea78d6de-96b3-4b6f-9798-1e4d79179296" />

---

## Findings

Within 18 hours of deployment, the honeypot was receiving thousands of brute force login attempts from automated scanners across the globe. Top attacking locations included:

| Location | Failed Attempts |
|---|---|
| Maam, Netherlands | 14,800+ |
| Southend-on-Sea, United Kingdom | 2,440+ |
| Chessel, Switzerland | 1,750+ |
| Gothenburg, Sweden | 1,640+ |
| Australia | 1,630+ |
| Hastings, New Zealand | 1,630+ |
| Georgia | 1,380+ |

The Netherlands origin dominated attack volume, consistent with known VPN/proxy infrastructure commonly used to route automated RDP scanning traffic.

---

## Key Takeaways

- **Exposed RDP ports are discovered within minutes** by automated internet scanners — no manual targeting required
- **KQL** is a powerful log analysis language directly comparable to SQL and SPL used in Splunk
- **Log enrichment** (GeoIP) transforms raw IP data into actionable threat intelligence
- **SIEM workbooks** enable SOC analysts to visualize threat patterns and prioritize response
- **Microsoft Sentinel** (now unified in the Defender portal) consolidates SIEM and XDR capabilities into a single platform

---

## Disclaimer

This lab was built in an isolated Azure environment for educational purposes. The VM was intentionally exposed to attract real attack traffic. All systems involved are owned and controlled by me. No production systems or real users were affected.
