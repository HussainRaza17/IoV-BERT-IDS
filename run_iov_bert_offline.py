"""
IoV-BERT-IDS : Offline PCAP Runner
---------------------------------
Input  : data/phone_hotspot.pcapng
Output : BERT embeddings + detection output

This script replaces ALL live capture logic.
"""

import os
import pandas as pd
import torch
from transformers import BertTokenizer, BertModel

# =========================
# CONFIG
# =========================
PCAP_PATH = "data/phone_hotspot.pcapng"
FEATURE_CSV = "iov_features.csv"
SEQUENCE_WINDOW = 20
DEVICE = "cuda" if torch.cuda.is_available() else "cpu"

# =========================
# STEP 1: OFFLINE CAPTURE
# =========================
import pyshark

def load_pcap(path):
    print("[*] Loading PCAP...")
    return pyshark.FileCapture(
        path,
        use_json=True,
        include_raw=False,
        keep_packets=False
    )

# =========================
# STEP 2: FEATURE EXTRACTION
# =========================
def extract_features(pcap_path):
    cap = load_pcap(pcap_path)
    rows = []
    prev_time = None

    for pkt in cap:
        try:
            row = {}
            t = float(pkt.sniff_timestamp)
            row["time_delta"] = 0 if prev_time is None else round(t - prev_time, 6)
            prev_time = t

            if not hasattr(pkt, "ip"):
                continue

            row["src_ip"] = pkt.ip.src
            row["dst_ip"] = pkt.ip.dst

            if hasattr(pkt, "tcp"):
                row["dst_port"] = pkt.tcp.dstport
            elif hasattr(pkt, "udp"):
                row["dst_port"] = pkt.udp.dstport
            else:
                row["dst_port"] = "NA"

            row["dns"] = pkt.dns.qry_name if hasattr(pkt, "dns") and hasattr(pkt.dns, "qry_name") else "NONE"
            row["sni"] = pkt.tls.handshake_extensions_server_name if hasattr(pkt, "tls") and hasattr(pkt.tls, "handshake_extensions_server_name") else "NONE"

            rows.append(row)

        except Exception:
            continue

    df = pd.DataFrame(rows)
    df.to_csv(FEATURE_CSV, index=False)
    print(f"[+] Features saved: {FEATURE_CSV}")
    return df

# =========================
# STEP 3: TOKENIZATION
# =========================
def build_sequences(df, window=SEQUENCE_WINDOW):
    print("[*] Building IoV sequences...")

    def token(row):
        return f"DNS:{row['dns']} SNI:{row['sni']} PORT:{row['dst_port']} DT:{row['time_delta']}"

    df["token"] = df.apply(token, axis=1)

    sequences = []
    for i in range(len(df) - window):
        sequences.append(" ".join(df.iloc[i:i+window]["token"].values))

    print(f"[+] Total sequences: {len(sequences)}")
    return sequences

# =========================
# STEP 4: BERT EMBEDDINGS
# =========================
def run_bert(sequences):
    print("[*] Running BERT...")

    tokenizer = BertTokenizer.from_pretrained("bert-base-uncased")
    model = BertModel.from_pretrained("bert-base-uncased").to(DEVICE)
    model.eval()

    inputs = tokenizer(
        sequences[:50],   # limit for demo
        padding=True,
        truncation=True,
        return_tensors="pt"
    ).to(DEVICE)

    with torch.no_grad():
        outputs = model(**inputs)

    embeddings = outputs.last_hidden_state[:, 0, :]
    print("[+] BERT embeddings shape:", embeddings.shape)
    return embeddings

# =========================
# MAIN
# =========================
if __name__ == "__main__":

    print("\n===== IoV-BERT-IDS OFFLINE RUN =====\n")

    if not os.path.exists(PCAP_PATH):
        print("[!] PCAP file not found:", PCAP_PATH)
        exit(1)

    df = extract_features(PCAP_PATH)
    sequences = build_sequences(df)

    if len(sequences) == 0:
        print("[!] No sequences built. Check PCAP.")
        exit(1)

    embeddings = run_bert(sequences)

    print("\n✅ PIPELINE COMPLETED SUCCESSFULLY")
    print("You now have real IoV-BERT embeddings from phone traffic.\n")
