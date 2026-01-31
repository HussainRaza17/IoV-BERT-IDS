import pandas as pd
from iov_offline_capture import load_pcap

def extract_features(pcap_path, out_csv="iov_features.csv"):
    cap = load_pcap(pcap_path)
    rows = []

    prev_time = None

    for pkt in cap:
        try:
            row = {}

            # Time delta (important for IoV)
            t = float(pkt.sniff_timestamp)
            row["time_delta"] = 0 if prev_time is None else round(t - prev_time, 6)
            prev_time = t

            # IP
            if hasattr(pkt, "ip"):
                row["src_ip"] = pkt.ip.src
                row["dst_ip"] = pkt.ip.dst
            else:
                continue

            # Port
            if hasattr(pkt, "tcp"):
                row["dst_port"] = pkt.tcp.dstport
            elif hasattr(pkt, "udp"):
                row["dst_port"] = pkt.udp.dstport
            else:
                row["dst_port"] = "NA"

            # DNS
            if hasattr(pkt, "dns") and hasattr(pkt.dns, "qry_name"):
                row["dns"] = pkt.dns.qry_name
            else:
                row["dns"] = "NONE"

            # TLS SNI
            if hasattr(pkt, "tls") and hasattr(pkt.tls, "handshake_extensions_server_name"):
                row["sni"] = pkt.tls.handshake_extensions_server_name
            else:
                row["sni"] = "NONE"

            rows.append(row)

        except Exception:
            continue

    df = pd.DataFrame(rows)
    df.to_csv(out_csv, index=False)
    print(f"[+] Features saved to {out_csv}")

if __name__ == "__main__":
    extract_features("data/phone_hotspot.pcapng")
