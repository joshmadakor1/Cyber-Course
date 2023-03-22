# Project Title

Building a SOC + Mini Honeynet in Azure with Log Analytics and Microsoft Sentinel

## Introduction

In this project, I build a mini honeynet in Azure and ingest log sources from various resources into a Log Analytics workspace, which is then used by Microsoft Sentinel to build attack maps, trigger alerts, and create incidents. I measured some security metrics in the insecure environment for 24 hours, apply some security controls to harden the environment, measure metrics for another 24 hours, then show the results below. The metrics we will show are:

- SecurityEvent (Windows Event Logs)
- Syslog (Linux Event Logs)
- SecurityAlert (Log Analytics Alerts Triggered)
- SecurityIncident (Incidents created by Sentinel)
- AzureNetworkAnalytics_CL (Malicious Flows allowed into our honeynet)

## Architecture [https://app.diagrams.net/](https://app.diagrams.net/)
### Architecture Before Hardening / Security Controls
![Architecture Diagram](/images/architecture-diagram.png)

### Architecture After Hardening / Security Controls
![Architecture Diagram](/images/architecture-diagram.png)

The architecture of the mini honeynet in Azure consists of the following components:

- Virtual Network (VNet)
- Network Security Group (NSG)
- Virtual Machines (2 windows, 1 linux)
- Log Analytics Workspace
- Azure Key Vault
- Azure Storage Account
- Microsoft Sentinel

For the "BEFORE" metrics, all resources were originally deployed, exposed to the internet. The Virtual Machines had both their Network Security Groups and built-in firewalls wide open, and all other resources are deployed with public endpoints visible to the Internet; aka, no use for Private Endpoints.

For the "AFTER" metrics, Network Security Groups were hardened by blocking ALL traffic with the exception of my admin workstation, and all other resources were protected by their built-in firewalls as well as Private Endpoint

## Attack Maps Before Hardening / Security Controls

![Architecture Diagram](/images/architecture-diagram.png)<br>
![Architecture Diagram](/images/architecture-diagram.png)<br>
![Architecture Diagram](/images/architecture-diagram.png)<br>
![Architecture Diagram](/images/architecture-diagram.png)<br>

## Metrics Before Hardening / Security Controls

The following table shows the metrics we measured in our insecure environment for 24 hours:

| Metric                   | Count |
| ------------------------ | ----- |
| SecurityEvent            | 500   |
| Syslog                   | 1000  |
| SecurityAlert            | 5     |
| SecurityIncident         | 0     |
| AzureNetworkAnalytics_CL | 200   |

## Attack Maps Before Hardening / Security Controls

_All map queries actually returned no results due to no instances of malicious activity for the 24 hour period after hardening._

## Metrics After Hardening / Security Controls

The following table shows the metrics we measured in our environment for another 24 hours, but after we have applied security controls:

| Metric                   | Count |
| ------------------------ | ----- |
| SecurityEvent            | 100   |
| Syslog                   | 500   |
| SecurityAlert            | 10    |
| SecurityIncident         | 2     |
| AzureNetworkAnalytics_CL | 50    |

## Conclusion

In this project, a mini honeynet was constructed in Microsoft Azure and log sources were integrated into a Log Analytics workspace. Microsoft Sentinel was employed to trigger alerts and create incidents based on the ingested logs. Additionally, metrics were measured in the insecure environment before security controls were applied, and then again after implementing security measures. It is noteworthy that the number of security events and incidents were drastially reduced after the security controls were applied, demonstrating their effectiveness.

It is worth noting that if the resources within the network were heavily utilized by regular users, it is likely that more security events and alerts may have been generated within the 24-hour period following the implementation of the security controls.
