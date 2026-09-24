# 🛡️ DNSGuard

A lightweight Python-based DNS threat detection tool for identifying suspicious DNS activity and possible DNS tunneling patterns.

## 🛡️ Overview

DNSGuard analyzes DNS query logs and detects potentially suspicious activity using multiple indicators such as:

- Long DNS labels
- High-entropy domain labels
- Repeated DNS queries
- NXDOMAIN responses
- Combined risk scoring

The tool helps demonstrate how DNS traffic can be analyzed for early indicators of suspicious or abnormal behavior.

## ✨ Features

- 🔍 DNS query log analysis
- 🌐 Domain and client extraction
- 📊 Query frequency analysis
- 🔐 Entropy-based detection
- ⚠️ NXDOMAIN detection
- 🎯 Risk score calculation
- 🚨 Suspicious DNS activity identification
- ⚙️ Configurable detection thresholds
- 💻 Lightweight Python implementation

## 🧰 Technologies Used

- Python
- Regular Expressions (`re`)
- Collections (`Counter`, `defaultdict`)
- Mathematical Entropy Calculation (`math`)
- JSON Configuration
- DNS Log Analysis

## 📂 Project Structure

    DNSGuard/
    ├── dns_analyzer.py
    ├── sample_dns_logs.txt
    ├── config.json
    ├── requirements.txt
    └── README.md

## 🔍 Detection Method

DNSGuard evaluates DNS queries using multiple indicators.

### 1. Long DNS Labels

Unusually long subdomain labels can be an indicator of encoded or abnormal DNS traffic.

### 2. Entropy Analysis

DNSGuard calculates the Shannon entropy of the longest domain label.

Higher entropy can indicate random-looking or encoded data.

### 3. Query Frequency

Repeated queries for the same domain are monitored to identify unusual activity.

### 4. NXDOMAIN Activity

Frequent `NXDOMAIN` responses may indicate suspicious or non-existent domain requests.

### 5. Risk Scoring

Each suspicious indicator contributes to a risk score.

The final score is limited to:

    0 - 100

A higher score indicates more suspicious characteristics.

> DNSGuard uses heuristic analysis. A high risk score does not automatically mean that a domain is malicious.

## ⚙️ Configuration

Detection thresholds can be customized using `config.json`.

Example:

    {
        "long_label_length": 20,
        "high_entropy": 3.5,
        "high_query_frequency": 5,
        "risk_threshold": 50
    }

## 📄 Sample Log Format

DNSGuard expects DNS logs in the following format:

    timestamp client=IP query=domain status=STATUS

Example:

    2026-09-24 10:01:01 client=192.168.1.10 query=google.com status=NOERROR

## 🚀 How to Run

Make sure Python 3 is installed.

Run:

    python dns_analyzer.py

The analyzer reads:

    sample_dns_logs.txt

and displays the DNS threat analysis in the terminal.

## 📊 Sample Analysis

Example output:

    =======================================================
                     DNSGUARD
            DNS Threat Detection Engine
    =======================================================

    Total DNS Queries : 16
    Unique Domains   : 8
    Unique Clients   : 3
    Suspicious Domains: 3

    -------------------------------------------------------
    THREAT ANALYSIS
    -------------------------------------------------------

    Domain      : x8f92k1m7q2p9z4x7.example.com
    Entropy     : HIGH
    Risk Score  : 80/100
    Threat      : POSSIBLE DNS TUNNELING / SUSPICIOUS ACTIVITY

## 🎯 Project Objective

The objective of DNSGuard is to demonstrate a practical approach to DNS security monitoring using Python.

The project focuses on identifying suspicious DNS characteristics through:

- Log analysis
- Entropy analysis
- Frequency monitoring
- NXDOMAIN detection
- Risk scoring

## 🔮 Future Enhancements

- Real-time DNS traffic monitoring
- DNS packet analysis using PCAP files
- Machine learning-based anomaly detection
- Threat intelligence integration
- SIEM integration
- Dashboard-based visualization
- Automatic alert generation

## ⚠️ Security Note

DNSGuard is an educational security analysis tool.

Its detections are heuristic-based and should be treated as indicators for further investigation rather than proof of malicious activity.

