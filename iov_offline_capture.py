import pyshark

def load_pcap(pcap_path):
    """
    Stable offline PCAP loader for Windows
    """
    return pyshark.FileCapture(
        pcap_path,
        use_json=True,
        include_raw=False,
        keep_packets=False
    )


