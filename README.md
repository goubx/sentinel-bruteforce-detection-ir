# Brute Force Detection and Incident Response in Microsoft Sentinel

A detection engineering and incident response lab built in Microsoft Sentinel. This project creates a scheduled analytics rule to detect brute force login attempts, lets it surface real activity in the environment, and works the result to closure following the NIST 800-61 incident response lifecycle.

> Note: hostnames have been sanitized, including shared-environment systems that belong to other users. Attacker source IPs are kept as indicators of compromise.

| | |
|---|---|
| **SIEM** | Microsoft Sentinel |
| **Telemetry source** | Microsoft Defender for Endpoint (DeviceLogonEvents) |
| **Query Language** | KQL |
| **IR Framework** | NIST 800-61 |
| **Tactic** | Credential Access |
| **MITRE Technique** | T1110 Brute Force |
| **Outcome** | True positive. Brute force confirmed from 8 external IPs, no successful logons, contained via NSG lockdown |

## Contents

- [Overview](#overview)
- [How the Detection Works](#how-the-detection-works)
- [Part 1: The Analytics Rule](#part-1-the-analytics-rule)
- [Part 2: Detection Results](#part-2-detection-results)
- [Part 3: Working the Incident (NIST 800-61)](#part-3-working-the-incident-nist-800-61)
- [MITRE ATT&CK Mapping](#mitre-attck-mapping)
- [Lessons Learned](#lessons-learned)
- [Files](#files)

## Overview

The goal of this lab was to build a working brute force detection from the SIEM side, not just hunt for it after the fact. That means writing the detection logic, standing it up as a scheduled analytics rule, letting it surface genuine activity, and then running the full incident response process to closure.

## How the Detection Works

When an entity attempts to log into a VM, a log is written locally and forwarded to Microsoft Defender for Endpoint under the `DeviceLogonEvents` table. Those logs flow into the Log Analytics workspace behind Microsoft Sentinel, the SIEM. Inside Sentinel, a scheduled analytics rule evaluates that data and raises an alert when the same remote IP fails to log into the same host too many times in a set window.

## Part 1: The Analytics Rule

The detection looks for the same remote IP failing to log into the same host 10 or more times within 5 hours. After validating the query in Log Analytics, it was copied into the Analytics Rule Wizard to create a scheduled detection rule.

```kql
DeviceLogonEvents
| where TimeGenerated >= ago(5h)
| where ActionType == "LogonFailed"
| summarize NumberOfFailures = count() by RemoteIP, ActionType, DeviceName
| where NumberOfFailures >= 10
```

**Rule configuration:**

| Setting | Value |
|---------|-------|
| Status | Enabled |
| Run frequency | Every 4 hours |
| Lookback window | Last 5 hours |
| Entity mappings | RemoteIP, DeviceName |
| Incident creation | Automatic |
| Alert grouping | Single incident per 24 hours |
| Stop query after alert | Yes |
| MITRE mapping | T1110 Brute Force |

## Part 2: Detection Results

The environment already contained enough real brute force activity to satisfy the rule threshold. The query identified multiple public IP addresses generating repeated failed logons against several virtual machines, which is a clear brute force signal.

**Scope of the activity:**

- 8 distinct external source IPs
- 7 targeted hosts across the shared environment (shown as `HOST-01` through `HOST-07`)

**Source IPs observed:**

| Type | Value |
|------|-------|
| IP | 91.92.40.7 |
| IP | 125.137.115.145 |
| IP | 185.162.141.34 |
| IP | 91.92.40.217 |
| IP | 91.92.40.10 |
| IP | 186.10.68.218 |
| IP | 45.142.193.166 |
| IP | 80.94.95.83 |

## Part 3: Working the Incident (NIST 800-61)

### Preparation

Roles, procedures, and tooling were in place ahead of the investigation: Microsoft Sentinel as the SIEM for detection and incident management, and Microsoft Defender for Endpoint for endpoint isolation and response.

### Detection and Analysis

The analytics rule surfaced the activity, and the entity mappings showed the full picture: 8 external IPs generating repeated failed logons against 7 hosts. The pattern of high-volume failures from single sources against the same hosts confirmed genuine brute force behavior rather than noise.

**Success check.** The key question was whether any of the suspect IPs actually authenticated. This query checks every suspect IP for any logon that was not a failure:

```kql
DeviceLogonEvents
| where RemoteIP in (
    "91.92.40.7",
    "125.137.115.145",
    "185.162.141.34",
    "91.92.40.217",
    "91.92.40.10",
    "186.10.68.218",
    "45.142.193.166",
    "80.94.95.83"
)
| where ActionType != "LogonFailed"
```

**Result:** No successful logons were found from any of the suspect IPs. The brute force attempts did not succeed.

### Containment, Eradication, and Recovery

- Isolated the potentially impacted devices in Microsoft Defender for Endpoint and ran antimalware scans on each.
- In a live production environment the same steps would apply: isolate the affected assets with Defender EDR, run antivirus scans, review successful logons, and validate whether any accounts were compromised.
- Updated the Network Security Group to block public RDP from the internet and allow RDP only from a single known home IP. Azure Bastion is a stronger alternative, since it provides secure access without exposing RDP publicly at all.
- Since the brute force was unsuccessful, there was no active threat to eradicate. Recovery was limited to closing the exposure that allowed the attempts.

### Post-Incident Activities

A policy recommendation was proposed to require restricted NSG access on all virtual machines going forward, enforceable through Azure Policy. This prevents the same wide-open exposure from recurring on the next VM someone spins up. Findings and remediation were recorded with the incident.

### Closure

The incident was assessed as a true positive. The rule fired on genuine brute force activity, and the investigation confirmed the attempts were unsuccessful with no compromise. With containment and remediation complete, the case was closed out.

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|--------|-----------|----|----|
| Credential Access | Brute Force | T1110 | Repeated failed logons from single IPs against the same hosts, crossing the alert threshold |
| Initial Access | External Remote Services | T1133 | Attempts targeted publicly exposed VMs over RDP from the internet |

## Lessons Learned

**What this detection catches:**

- A single source IP hammering a host with failed logins is a clear brute force signal. A threshold-based scheduled rule turns that into an automatic incident instead of a manual hunt, which is the core value of building detection on the SIEM side.

**What would prevent the underlying exposure:**

- Wide-open NSGs let external IPs reach the VMs in the first place. Restricting access to known IPs, or removing public RDP entirely in favor of Azure Bastion, removes the attack surface.
- Enforcing NSG restrictions across all VMs through Azure Policy prevents this from recurring on future machines.

**What would sharpen the detection:**

- Build the success condition into the rule so it only fires on apparent successful brute forces, cutting noise and surfacing the cases that actually matter.
- Tune the threshold and window over time based on what normal failed-logon volume looks like in the environment.

## Files

- `README.md` - this writeup
- `analytics-rule.kql` - the detection query behind the Sentinel rule
- `success-check.kql` - the query used to confirm no successful brute force login

---

Part of an ongoing series of threat hunting and SOC investigations by Mohamed Yagoub.
