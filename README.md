# CargoLink Logistics — SOC Analyst Readiness (Task 1)

**Analyst:** Muhammad Mudasir  
**Domain:** Cyber Security / SOC Operations & Threat Hunting  
**Scope:** Initial Threat Hunting (`auth.log` & `access.log`)  

---

## 1. Executive Summary
During routine threat hunting across CargoLink Logistics' authentication (`auth.log`) and web server (`access.log`) logs, automated brute-force activity was identified originating from external IP addresses. The activity targeted administrative SSH accounts and web login endpoints over condensed timeframes.

---

## 2. Suspicious IP & Attack Metrics (Criteria 1 & 2)

| Log Source | Suspicious IP | Total Failed Attempts | Targeted Accounts / Endpoints | Attack Start Timestamp | Attack End Timestamp | Outcome |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `auth.log` | `203.0.113.50` | 7 | `root` (4), `admin` (2), `test` (1) | `Nov 12 04:12:30` | `Nov 12 04:12:42` | Blocked (`Failed password`) |
| `auth.log` | `198.51.100.22` | 2 | `postgres` (2) | `Nov 12 04:16:11` | `Nov 12 04:16:13` | Blocked (`Failed password`) |
| `access.log` | `10.0.0.99` | 5 | `POST /login` (4x `401`, 1x `403`) | `12/Nov/2026:04:11:15` | `12/Nov/2026:04:11:19` | Blocked (`401`/`403`) |
| `access.log` | `203.0.113.50` | 2 | `POST /api/auth/token` (2x `401`) | `12/Nov/2026:04:14:22` | `12/Nov/2026:04:14:23` | Blocked (`401`) |

---

## 3. Normal vs. Malicious Traffic Comparison (Criterion 3)

| Characteristic | Normal Traffic Behavior | Malicious Brute-Force Behavior |
| :--- | :--- | :--- |
| **Request Frequency** | Sporadic logins (1–2 attempts per user session) | High-velocity bursts (multiple requests every 1–2 seconds) |
| **Source IP Diversity** | Established internal employee IPs (`192.168.1.15`, `192.168.1.20`, `192.168.1.50`) | Concentrated volume originating from outlier IPs (`203.0.113.50`, `10.0.0.99`) |
| **Targeted Accounts / Paths** | Valid accounts (`ubuntu`, `admin`) & standard routes (`/index.html`, `/dashboard`, `/api/v1/shipments`) | Dictionary guesses (`root`, `admin`, `test`, `postgres`) & repeated auth endpoint hits (`POST /login`) |
| **HTTP / Auth Status** | `Accepted publickey`, `Accepted password`, or HTTP `200 OK` | Repeated `Failed password` or HTTP `401 Unauthorized` / `403 Forbidden` |

---

## 4. Raw Log Evidence & Commands Used

### A. SSH Authentication Log (`auth.log`)
**Command Used:**
```powershell
Get-Content .\sample_logs\auth.log | Select-String "Failed password"
# Linux CLI: grep "Failed password" auth.log | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" | sort | uniq -c | sort -nr

Evidence:

Nov 12 04:12:30 cargolink-srv01 sshd[1435]: Failed password for invalid user root from 203.0.113.50 port 49152 ssh2
Nov 12 04:12:32 cargolink-srv01 sshd[1437]: Failed password for invalid user root from 203.0.113.50 port 49154 ssh2
Nov 12 04:12:38 cargolink-srv01 sshd[1443]: Failed password for admin from 203.0.113.50 port 49160 ssh2
Nov 12 04:12:42 cargolink-srv01 sshd[1447]: Failed password for invalid user test from 203.0.113.50 port 49164 ssh2

10.0.0.99 - - [12/Nov/2026:04:11:15 +0000] "POST /login HTTP/1.1" 401 540
10.0.0.99 - - [12/Nov/2026:04:11:18 +0000] "POST /login HTTP/1.1" 403 198
10.0.0.99 - - [12/Nov/2026:04:11:19 +0000] "POST /login HTTP/1.1" 401 540
203.0.113.50 - - [12/Nov/2026:04:14:22 +0000] "POST /api/auth/token HTTP/1.1" 401 128
