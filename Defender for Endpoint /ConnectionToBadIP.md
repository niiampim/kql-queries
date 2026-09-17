# Successful Connection to Known Threat Intelligence IP

## Description

Identifies successful network connections from monitored endpoints to IP addresses associated with active threat intelligence indicators.

The query correlates Microsoft Defender for Endpoint network telemetry with active threat intelligence indicators to identify devices communicating with known or suspected malicious infrastructure.

## MITRE ATT&CK Mapping

- **Tactic:** Command and Control
- **Technique:** T1071 - Application Layer Protocol

> **Mapping Note:** A successful connection to a threat intelligence IP may indicate communication with malicious infrastructure. The IOC match alone does not confirm command-and-control activity and should be investigated with supporting process, network, and endpoint telemetry.

## Query

```kql
let ThreatIPs =
    ThreatIntelEntities
    | where IsActive == true
    | where ObservableKey == @"network-traffic:src_ref.value"
    | summarize arg_max(TimeGenerated, *) by ObservableValue
    | project ThreatIP = ObservableValue, Confidence;

DeviceNetworkEvents
| where ActionType == "ConnectionSuccess"
| where isnotempty(RemoteIP)
| join kind=inner (ThreatIPs) on $left.RemoteIP == $right.ThreatIP
| project
    TimeGenerated,
    DeviceName,
    DeviceId,
    RemoteIP,
    RemotePort,
    RemoteUrl,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    Confidence
| order by TimeGenerated desc
| take 10
```
