# IoV-BERT-IDS (Offline IoV Traffic Analysis Pipeline)

## Overview

**IoV-BERT-IDS** is an offline intrusion detection pipeline designed for **Internet of Vehicles (IoV)** environments.
The system processes **real network traffic captured from a mobile edge device**, extracts encrypted traffic metadata, builds temporal behavior sequences, and generates **BERT-based contextual embeddings** for downstream intrusion detection.

This project emphasizes **realistic edge constraints**, encrypted traffic analysis, and reproducible offline processing instead of fragile real-time packet sniffing.

---

## Key Highlights

* ✅ Uses **real mobile phone traffic** captured via laptop hotspot routing
* ✅ Works with **encrypted traffic** (DNS, TLS SNI, ports, timing)
* ✅ No payload inspection
* ✅ Offline, stable, and reproducible pipeline
* ✅ Transformer-based sequence modeling (BERT)
* ✅ IoV-realistic gateway / NAT architecture

---

## System Architecture

```
Mobile Phone (IoV Edge Node)
        |
        |  (Traffic routed via hotspot)
        v
Laptop Gateway
        |
        |  dumpcap (PCAP capture)
        v
PCAPng File
        |
        |  PyShark (offline parsing)
        v
Feature Extraction (CSV)
        |
        |  Temporal Tokenization
        v
IoV Sequences
        |
        |  BERT Encoder
        v
Contextual Embeddings
        |
        |  (Optional classifier / analysis)
        v
Detection / Research Output
```

---

## Features

### Traffic Acquisition

* Captures **real phone-generated traffic** via laptop hotspot
* Uses `dumpcap` for reliable packet capture
* Avoids unreliable passive Wi-Fi sniffing

### Feature Extraction

* DNS query names
* TLS Server Name Indication (SNI)
* Destination ports
* Inter-packet time deltas
* IP-level metadata

### Sequence Modeling

* Sliding window–based temporal sequences
* Semantically meaningful token construction
* IoV-aware behavioral modeling

### BERT-Based Encoding

* Uses `bert-base-uncased`
* CLS token embeddings (`768-dimensional`)
* Suitable for anomaly detection or classification

---

## Prerequisites

### System Requirements

* Python **3.10**
* Windows 10 / 11
* Wireshark installed
* Npcap installed
* Minimum 4 GB RAM

### Required Software

* **Wireshark**
* **Npcap** (installed during Wireshark setup)

---

## Installation

```bash
git clone https://github.com/HussainRaza17/IoV-BERT-IDS.git
cd IoV-BERT-IDS
python -m venv venv310
venv310\Scripts\activate
pip install -r requirements.txt
```

---

## Traffic Capture (One-Time Setup)

1. Enable **Mobile Hotspot** on the laptop
2. Connect the mobile phone to the laptop hotspot
3. Capture traffic using:

```powershell
"C:\Program Files\Wireshark\dumpcap.exe" -i <WiFi_Interface_Number> -w data/phone_hotspot.pcapng
```

4. Use the phone normally (YouTube, Maps, browsing)
5. Stop capture after 1–2 minutes

---

## Running the Pipeline

### Single Entry Script

```bash
python run_iov_bert_offline.py
```

### Expected Output

* `iov_features.csv`
* IoV token sequences
* BERT embedding tensor:

```
torch.Size([N, 768])
```

Successful execution confirms **end-to-end pipeline completion**.

---

## Output Description

* **iov_features.csv**
  Structured network metadata extracted from the PCAP file

* **BERT Embeddings**
  Contextual representations of IoV network behavior
  Can be used for:

  * Anomaly detection
  * Attack classification
  * Research experimentation

---

## Project Scope (Intentionally Limited)

This project **does NOT include**:

* Live packet capture in Python
* Real-time dashboards or UI
* Payload inspection
* On-device IDS deployment

These decisions were made to ensure **stability, realism, and reproducibility**.

---

## File Structure

```
IoV-BERT-IDS/
│
├── data/
│   └── phone_hotspot.pcapng
│
├── run_iov_bert_offline.py
├── iov_offline_capture.py
├── iov_feature_extract.py
├── iov_tokenize.py
├── requirements.txt
└── README.md
```

---

## Use Cases

* IoV security research
* Encrypted traffic behavior analysis
* Transformer-based network modeling
* Edge-aware IDS prototyping
* Academic projects and demonstrations

---

## License

MIT License

---

## Disclaimer

This project is intended for **educational and research purposes only**.
Captured traffic should be limited to devices you own or have explicit permission to analyze.

---

### Final Note

This repository represents a **completed, stable, and working prototype**.
Future extensions (classification models, dashboards, alerting systems) can be built on top of this foundation.
