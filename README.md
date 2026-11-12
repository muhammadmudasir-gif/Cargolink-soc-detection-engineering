# CargoLink Logistics — SOC Analyst Readiness (Task 1)

**Analyst:** Muhammad Mudasir[cite: 1]  
**Domain:** Cyber Security / SOC Operations & Threat Hunting[cite: 1, 2]  

## Project Overview
This repository contains the initial threat hunting investigation for **CargoLink Logistics**[cite: 1, 2]. As the company scales its digital freight tracking, this task focuses on moving from manual log checking to identifying real malicious patterns (brute-force attacks) within raw system logs[cite: 1, 2].

## Repository Structure
* `auth.log` — Raw Linux SSH authentication log dataset containing normal and simulated brute-force attempts[cite: 2].
* `access.log` — Raw web server HTTP access log dataset containing normal traffic and unauthorized request statuses (`401`/`403`)[cite: 2].
* [`Incident_Report_Task1.md`](./Incident_Report_Task1.md) — Comprehensive security incident report detailing:
  * Identified suspicious outlier IP addresses[cite: 2].
  * Attack metrics, attempt frequencies, and targeted accounts/endpoints[cite: 2].
  * Exact attack start and end timestamps[cite: 2].
  * A structured "Normal vs. Malicious" traffic comparison table[cite: 2].
  * Raw log evidence and CLI commands used[cite: 2].

## Tools & Methods Used
* **Analysis & Filtering:** PowerShell (`Select-String`, `Where-Object`) / Linux CLI (`grep`, `awk`, `sort`, `uniq`)[cite: 2]
* **Environment:** Windows 11 / VS Code[cite: 2]
* **Reporting:** Markdown / GitHub[cite: 2]
