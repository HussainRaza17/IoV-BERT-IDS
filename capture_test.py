import pyshark

INTERFACE = r"/Device/NPF_{402546C9-2D7F-4D62-B7F9-D9112B9CDE45}"

cap = pyshark.LiveCapture(
    interface=INTERFACE,
    tshark_path=r"C:/Program Files/Wireshark/tshark.exe",
    dumpcap_path=r"C:/Program Files/Wireshark/dumpcap.exe"
)

print("Listening... open a website now")

for i, pkt in enumerate(cap.sniff_continuously()):
    print(pkt.highest_layer)
    if i >= 10:
        break

