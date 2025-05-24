<p align="center">
  <a href="https://github.com/Samuel-Cavada" target="_blank">
    <img src="https://img.shields.io/badge/Back_to_Main_Page-000000?style=for-the-badge&logo=github&logoColor=white" alt="Back to Main Page"/>
  </a>
</p>

<h1 align="center">Scenario 3: Potential Impossible Travel</h1>

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Azure%20Sentinel-0078D4?style=for-the-badge&logo=microsoftazure&logoColor=white" alt="Cloud Platform" />
  <img src="https://img.shields.io/badge/Tool-Microsoft%20Sentinel-00B388?style=for-the-badge&logo=microsoftazure&logoColor=white" alt="Tool" />
  <img src="https://img.shields.io/badge/Tool-Microsoft%20Defender%20for%20Endpoint-2C5EA8?style=for-the-badge&logo=microsoftdefender&logoColor=white" alt="Tool" />
  <img src="https://img.shields.io/badge/Focus-Identity%20Analytics-orange?style=for-the-badge" alt="Focus Area" />
</p>

---

## 📌 Project Objective
> Detect anomalous login behavior across geographic regions to identify signs of account sharing or compromise. This project uses Microsoft Sentinel analytics to track potential impossible travel by correlating sign-in events over a rolling 7-day period.

---

## 🧰 Tools & Technologies
- **Platform:** Azure
- **OS:** N/A
- **Tools:** Microsoft Sentinel, Microsoft Defender for Endpoint, Entra ID
- **Languages/Scripts:** KQL

---

## 🧠 Skills Gained / Focus Areas
- Detected geographic anomalies using SigninLogs
- Built a Sentinel alert rule to monitor travel thresholds
- Used entity mapping for identity correlation
- Applied NIST 800-61 for incident response management

---

## 🧪 Environment Setup
> Onboarded an Azure VM and logged into [https://portal.azure.com](https://portal.azure.com) to generate login telemetry in the **SigninLogs** table. This triggered logins from various geographic regions, simulating potential impossible travel.

---

## 🛠️ Walkthrough
1. [Step 1: Create Alert Rule](#step-1-create-alert-rule)
2. [Step 2: Trigger Alert](#step-2-trigger-alert)
3. [Step 3: Work Incident](#step-3-work-incident)
4. [Step 4: Cleanup](#step-4-cleanup)

---

### ✅ Step 1: Create Alert Rule
> KQL used to detect impossible travel based on geographic variation:
```kql
let TimePeriodThreshold = timespan(7d);
let NumberOfDifferentLocationsAllowed = 2;
SigninLogs
| where TimeGenerated > ago(TimePeriodThreshold)
| summarize Count = count() by UserPrincipalName, UserId, City = tostring(parse_json(LocationDetails).city), State = tostring(parse_json(LocationDetails).state), Country = tostring(parse_json(LocationDetails).countryOrRegion)
| project UserPrincipalName, UserId, City, State, Country
| summarize PotentialImpossibleTravelInstances = count() by UserPrincipalName, UserId
| where PotentialImpossibleTravelInstances > NumberOfDifferentLocationsAllowed
```

> **Analytics Rule Settings:**
- Run every 4 hours
- Lookup data for last 5 hours
- Stop after alert is triggered
- Entity mappings:
  - **Account:** AadUserId → `UserId`, DisplayName → `UserPrincipalName`
- Automatically create incident
- Group alerts into one incident per 24 hours

---

### ✅ Step 2: Trigger Alert
> Triggered by logging into the Azure Portal from different VMs or IPs within a short window. This creates entries in **SigninLogs** from multiple regions.

---

### ✅ Step 3: Work Incident
> Followed **NIST 800-61** Lifecycle:

**Preparation:**  
- Confirmed telemetry setup and login simulation from varied IPs

**Detection & Analysis:**  
- Alert: "Impossible Travel – Josh"  
- Investigated user travel patterns:
```kql
let TargetUserPrincipalName = "josh.madakor@gmail.com";
let TimePeriodThreshold = timespan(7d);
SigninLogs
| where TimeGenerated > ago(TimePeriodThreshold)
| where UserPrincipalName == TargetUserPrincipalName
| project TimeGenerated, UserPrincipalName, City = tostring(parse_json(LocationDetails).city), State = tostring(parse_json(LocationDetails).state), Country = tostring(parse_json(LocationDetails).countryOrRegion)
| order by TimeGenerated desc
```

**Findings:**
- User `josh.madakor@gmail.com` logged in from **Boston** and **Seattle** within 4 hours → **suspicious**
- User `arisa_lognpacific@lognpacific.com` logged in from **Chicago** and **Milwaukee** within 1 day → **benign**

**Containment & Recovery:**  
- User `josh.madakor@gmail.com` account disabled in Entra ID  
- Manager notified and access reviewed  
- No other indicators of compromise

**Post-Incident:**  
- Recommended geo-fencing policy for Entra ID  
- Logged investigation timeline and confirmed alert accuracy

**Closure:**  
- Incident closed as **True Positive**

---

## 📝 Timeline Summary and Findings
- Impossible travel alert triggered by location spread  
- Some logins confirmed benign, others flagged as anomalous  
- Account action taken for one user; no further malicious activity observed

---

## 📎 References
- [MITRE ATT&CK T1078 – Valid Accounts](https://attack.mitre.org/techniques/T1078/)
- [SigninLogs Table Reference](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs)
- [Microsoft Sentinel Analytics Rule Creation](https://learn.microsoft.com/en-us/azure/sentinel/tutorial-detect-threats-custom)
