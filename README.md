# 📧 Email Threat Analysis

## 🔍 Overview

This repository demonstrates **end-to-end email threat analysis** contains a comprehensive guide and technical documentation for investigating sophisticated email-based attacks. It focuses on the triage and analysis of email headers, body content (payloads), and attachments using industry-standard tools.

It simulates real-world investigations involving:

* Phishing attacks
* Business Email Compromise (BEC)
* Malicious attachments and payload delivery
* Suspicious links and redirections

The project showcases practical skills using:

* Microsoft Defender for Office 365
* Microsoft Sentinel (SIEM)
* Email header analysis
* Threat intelligence correlation
* Secure attachment detonation (sandboxing)

---

## 🎯 Objectives

* Analyze **email headers** to identify spoofing and anomalies
* Detect malicious **payloads and embedded scripts**
* Investigate suspicious **URLs and redirections**
* Perform **attachment analysis and sandbox detonation**
* Map findings to **MITRE ATT&CK techniques**
* Demonstrate **SOC triage and escalation workflows**

---

## 🗂️ Repository Structure

```
email-threat-analysis-lab/
│
├── README.md
├── samples/
│   ├── phishing_email_1.eml
│   ├── bec_email_2.eml
│   └── malicious_attachment.zip
│
├── analysis/
│   ├── header_analysis.md
│   ├── payload_analysis.md
│   ├── link_analysis.md
│   └── attachment_analysis.md
│
├── evidence/
│   ├── screenshots/
│   └── logs/
│
└── detection-rules/
    ├── sentinel-kql-queries.md
    └── alert-tuning.md
```

---

## 🧪 Scenario 1: Phishing Email with Spoofed Domain

### 📩 Email Summary

* Sender: `security-update@micr0soft-support.com`
* Subject: "Urgent Password Reset Required"
* User reported suspicious login email

---

## 🧾 Email Header Analysis

### 🔎 Key Fields Analyzed

* **Received Chain**
* **Return-Path**
* **SPF / DKIM / DMARC**
* **Message-ID**
* **From vs Reply-To mismatch**

### 🧠 Findings

* SPF: ❌ Fail
* DKIM: ❌ None
* DMARC: ❌ Fail
* Sending IP not associated with Microsoft
* Domain uses **typosquatting** (`micr0soft`)

### 🛠️ Example Insight

```
Received: from unknown (185.234.x.x)
Authentication-Results: spf=fail dmarc=fail dkim=none
```

### 🚩 Conclusion

➡️ High-confidence phishing email using domain spoofing

---

## 💣 Payload Analysis

### 🔍 What Was Found

* Embedded HTML form mimicking Microsoft login
* Obfuscated JavaScript redirect

### 🧠 Techniques Used

* Base64 decoding
* Script de-obfuscation
* Static analysis

### 🚨 Indicators

* Credential harvesting form
* External POST request to attacker-controlled server

---

## 🔗 Link Analysis

### 🔎 URL Sample

```
http://secure-login-microsoft[.]co/verify
```

### 🧠 Analysis Steps

1. Checked domain age → Newly registered (2 days)
2. WHOIS lookup → Suspicious registrar
3. Sandbox detonation → Redirect chain observed

### 🔁 Redirection Flow

```
Initial URL → Bit.ly → Fake Microsoft Login Page
```

### 🚩 Verdict

➡️ Malicious credential harvesting link

---

## 📎 Attachment Analysis

### 📂 File

* `Invoice_2026.zip`

### 🔍 Inside Archive

* `Invoice_2026.docm` (macro-enabled)

### 🧪 Sandbox Execution

* Uploaded to sandbox environment
* Observed behavior:

  * PowerShell execution
  * External callback to C2 server
  * File drop in temp directory

### 🧠 Indicators of Compromise (IOCs)

* Hash: `abc123...`
* C2 IP: `45.77.x.x`
* Process: `powershell.exe -EncodedCommand`

### 🛑 Action Taken

* File quarantined
* Domain & IP blocked
* Endpoint isolation initiated

---

## 🧠 Scenario 2: Business Email Compromise (BEC)

### 📩 Email Summary

* Sender impersonates CFO
* Requests urgent wire transfer

### 🔍 Indicators

* Legitimate domain but unusual sending IP
* No malware (social engineering attack)
* Tone: urgent, confidential

### 🧾 Header Insight

* SPF: Pass (compromised account)
* Login from unusual geolocation

### 🚩 Conclusion

➡️ Account takeover leading to BEC attempt

---

## 🛡️ Detection & Response (Microsoft Sentinel)

### 🔎 Sample KQL Query

```kql
EmailEvents
| where Subject contains "urgent" or Subject contains "payment"
| where SenderFromDomain !in ("trustedcompany.com")
| summarize count() by SenderFromAddress, RecipientEmailAddress
```

---

## ⚙️ Automation (SOAR Playbook)

### 🔁 Automated Actions

* Extract indicators from email
* Check against threat intelligence
* Auto-block malicious domains
* Notify SOC team

---

## 🧬 MITRE ATT&CK Mapping

| Technique | Description              |
| --------- | ------------------------ |
| T1566     | Phishing                 |
| T1566.002 | Spearphishing Link       |
| T1566.001 | Spearphishing Attachment |
| T1059     | Command Execution        |
| T1204     | User Execution           |

---

## 📊 Key Takeaways

* Email headers are critical for identifying spoofing and authentication failures
* Payload analysis reveals hidden malicious scripts
* URL analysis uncovers phishing infrastructure
* Sandboxing is essential for safe attachment detonation
* BEC attacks often rely on **social engineering rather than malware**

---

## 🚀 Skills Demonstrated

* Email threat analysis (headers, payloads, links, attachments)
* Microsoft Defender for Office 365 investigation
* Microsoft Sentinel (SIEM + KQL)
* Phishing & BEC incident response
* Threat intelligence correlation
* SOC escalation and reporting

---

## 👤 Author

**Christopher Rajasekar (https://github.com/Chrisrajasekar)**

Focused on Email Security, Phishing Response & Threat Detection

---
