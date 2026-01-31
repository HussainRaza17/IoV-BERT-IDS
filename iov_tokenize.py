import pandas as pd

def build_sequences(csv_path, window=20):
    df = pd.read_csv(csv_path)

    def token(row):
        return (
            f"DNS:{row['dns']} "
            f"SNI:{row['sni']} "
            f"PORT:{row['dst_port']} "
            f"DT:{row['time_delta']}"
        )

    df["token"] = df.apply(token, axis=1)

    sequences = []
    for i in range(len(df) - window):
        sequences.append(" ".join(df.iloc[i:i+window]["token"].values))

    return sequences

if __name__ == "__main__":
    seqs = build_sequences("iov_features.csv")
    print("[+] Example sequence:\n")
    print(seqs[0])
