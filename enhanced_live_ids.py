import streamlit as st
import joblib
import numpy as np
import pandas as pd
import asyncio
import threading
import time
import queue
from datetime import datetime, timedelta
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
import pyshark
from collections import defaultdict, deque
import json
import logging
from sklearn.preprocessing import normalize
from sentence_transformers import SentenceTransformer
from sklearn.metrics import confusion_matrix
import matplotlib.pyplot as plt
import seaborn as sns

# === Windows asyncio fix for pyshark ===
if hasattr(asyncio, 'WindowsSelectorEventLoopPolicy'):
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

# === Configure Logging ===
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('ids_logs.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# === Load Model & Data ===
@st.cache_resource
def load_models():
    try:
        model = joblib.load("lightgbm_llm_ids.pkl")
        vectorizer = SentenceTransformer("paraphrase-MiniLM-L3-v2")
        
        # Load training embeddings for OOD detection
        try:
            train_embeddings = joblib.load("X_embeddings.pkl")
            train_embeddings = normalize(train_embeddings)
        except:
            train_embeddings = None
            
        # Load test data for confusion matrix
        try:
            y_test = joblib.load("y_test.pkl")
            y_pred = joblib.load("y_pred.pkl")
        except:
            y_test = None
            y_pred = None
            
        return model, vectorizer, train_embeddings, y_test, y_pred
    except Exception as e:
        st.error(f"Failed to load models: {str(e)}")
        return None, None, None, None, None

# === Global Variables for Live Monitoring ===
def initialize_session_state():
    """Initialize all required session state variables"""
    if 'monitoring_active' not in st.session_state:
        st.session_state.monitoring_active = False
    if 'packet_queue' not in st.session_state:
        st.session_state.packet_queue = queue.Queue()
    if 'flow_data' not in st.session_state:
        st.session_state.flow_data = deque(maxlen=1000)
    if 'attack_alerts' not in st.session_state:
        st.session_state.attack_alerts = deque(maxlen=100)
    if 'stats' not in st.session_state:
        st.session_state.stats = {
            'total_packets': 0,
            'total_flows': 0,
            'attacks_detected': 0,
            'benign_flows': 0,
            'start_time': None
        }
    if 'capture_thread' not in st.session_state:
        st.session_state.capture_thread = None

# Initialize session state
initialize_session_state()

# === Network Flow Analysis ===
class NetworkFlowAnalyzer:
    def __init__(self, model, vectorizer, train_embeddings=None, threshold=0.35):
        self.model = model
        self.vectorizer = vectorizer
        self.train_embeddings = train_embeddings
        self.threshold = threshold
        self.flows = defaultdict(lambda: {
            'packets': [],
            'start_time': None,
            'end_time': None,
            'src_ip': None,
            'dst_ip': None,
            'protocol': None,
            'total_fwd_packets': 0,
            'total_bwd_packets': 0,
            'fwd_packet_lengths': [],
            'bwd_packet_lengths': [],
            'fwd_iat_times': [],
            'bwd_iat_times': [],
            'init_win_fwd': 0,
            'init_win_bwd': 0
        })
        
    def extract_flow_features(self, flow_key, flow_data):
        """Extract features from a network flow for analysis"""
        if len(flow_data['packets']) < 2:
            return None
            
        # Calculate flow duration
        duration = (flow_data['end_time'] - flow_data['start_time']) * 1000000  # microseconds
        
        # Calculate packet statistics
        fwd_lengths = flow_data['fwd_packet_lengths']
        bwd_lengths = flow_data['bwd_packet_lengths']
        fwd_iat = flow_data['fwd_iat_times']
        bwd_iat = flow_data['bwd_iat_times']
        
        # Calculate means
        fwd_packet_length_mean = np.mean(fwd_lengths) if fwd_lengths else 0
        bwd_packet_length_mean = np.mean(bwd_lengths) if bwd_lengths else 0
        packet_length_mean = np.mean(fwd_lengths + bwd_lengths) if (fwd_lengths or bwd_lengths) else 0
        flow_iat_mean = np.mean(fwd_iat + bwd_iat) if (fwd_iat or bwd_iat) else 0
        
        # Calculate totals
        fwd_iat_total = np.sum(fwd_iat) if fwd_iat else 0
        bwd_iat_total = np.sum(bwd_iat) if bwd_iat else 0
        
        # Create descriptive text similar to training data
        flow_text = (
            f"Flow duration is {duration:.1f} microseconds, "
            f"Total Fwd Packets is {flow_data['total_fwd_packets']}, "
            f"Total Backward Packets is {flow_data['total_bwd_packets']}, "
            f"Fwd Packet Length Mean is {fwd_packet_length_mean:.1f}, "
            f"Bwd Packet Length Mean is {bwd_packet_length_mean:.1f}, "
            f"Packet Length Mean is {packet_length_mean:.1f}, "
            f"Flow IAT Mean is {flow_iat_mean:.3f}, "
            f"Fwd IAT Total is {fwd_iat_total:.1f}, "
            f"Bwd IAT Total is {bwd_iat_total:.1f}, "
            f"Init Win bytes forward is {flow_data['init_win_fwd']}, "
            f"Init Win bytes backward is {flow_data['init_win_bwd']}"
        )
        
        return flow_text
    
    def analyze_flow(self, flow_text):
        """Analyze a flow and return prediction results"""
        try:
            # Encode and normalize input
            input_embedding = self.vectorizer.encode([flow_text])
            input_embedding = normalize(input_embedding)
            
            # OOD Detection
            ood_warning = None
            if self.train_embeddings is not None:
                similarities = np.max(np.dot(input_embedding, self.train_embeddings.T))
                if similarities < self.threshold:
                    ood_warning = f"Flow seems different from training data (similarity = {similarities:.2f})"
            
            # Prediction
            prediction = self.model.predict(input_embedding)[0]
            proba = self.model.predict_proba(input_embedding)[0]
            confidence = round(proba[prediction] * 100, 2)
            
            label_name = "BENIGN" if prediction == 0 else "ATTACK"
            severity = "HIGH" if confidence > 90 else "MEDIUM" if confidence > 70 else "LOW"
            
            return {
                'prediction': prediction,
                'label': label_name,
                'confidence': confidence,
                'severity': severity,
                'ood_warning': ood_warning,
                'timestamp': datetime.now()
            }
            
        except Exception as e:
            logger.error(f"Flow analysis failed: {str(e)}")
            return None
    
    def process_packet(self, packet):
        """Process a single packet and update flow data"""
        try:
            # Extract basic packet information
            if not hasattr(packet, 'ip'):
                return
                
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            protocol = packet.highest_layer
            packet_length = int(packet.length)
            timestamp = float(packet.sniff_timestamp)
            
            # Create flow key (bidirectional)
            flow_key = tuple(sorted([src_ip, dst_ip]))
            
            # Initialize flow if new
            if self.flows[flow_key]['start_time'] is None:
                self.flows[flow_key]['start_time'] = timestamp
                self.flows[flow_key]['src_ip'] = src_ip
                self.flows[flow_key]['dst_ip'] = dst_ip
                self.flows[flow_key]['protocol'] = protocol
            
            # Update flow data
            self.flows[flow_key]['end_time'] = timestamp
            self.flows[flow_key]['packets'].append(packet)
            
            # Determine direction and update counters
            if packet.ip.src == self.flows[flow_key]['src_ip']:
                self.flows[flow_key]['total_fwd_packets'] += 1
                self.flows[flow_key]['fwd_packet_lengths'].append(packet_length)
                if len(self.flows[flow_key]['fwd_packet_lengths']) > 1:
                    iat = timestamp - self.flows[flow_key]['packets'][-2].sniff_timestamp
                    self.flows[flow_key]['fwd_iat_times'].append(iat)
            else:
                self.flows[flow_key]['total_bwd_packets'] += 1
                self.flows[flow_key]['bwd_packet_lengths'].append(packet_length)
                if len(self.flows[flow_key]['bwd_packet_lengths']) > 1:
                    iat = timestamp - self.flows[flow_key]['packets'][-2].sniff_timestamp
                    self.flows[flow_key]['bwd_iat_times'].append(iat)
            
            # Extract TCP window sizes if available
            if hasattr(packet, 'tcp'):
                if hasattr(packet.tcp, 'window_size'):
                    if packet.ip.src == self.flows[flow_key]['src_ip']:
                        self.flows[flow_key]['init_win_fwd'] = int(packet.tcp.window_size)
                    else:
                        self.flows[flow_key]['init_win_bwd'] = int(packet.tcp.window_size)
            
            # Check if flow is complete (timeout or sufficient packets)
            flow_duration = timestamp - self.flows[flow_key]['start_time']
            if (flow_duration > 30 or  # 30 second timeout
                len(self.flows[flow_key]['packets']) > 100):  # Max 100 packets per flow
                
                # Extract features and analyze
                flow_text = self.extract_flow_features(flow_key, self.flows[flow_key])
                if flow_text:
                    result = self.analyze_flow(flow_text)
                    if result:
                        # Add to flow data for display
                        flow_info = {
                            'flow_key': f"{self.flows[flow_key]['src_ip']} ↔ {self.flows[flow_key]['dst_ip']}",
                            'protocol': self.flows[flow_key]['protocol'],
                            'duration': flow_duration,
                            'packet_count': len(self.flows[flow_key]['packets']),
                            'result': result
                        }
                        st.session_state.flow_data.append(flow_info)
                        
                        # Update statistics
                        st.session_state.stats['total_flows'] += 1
                        if result['prediction'] == 1:
                            st.session_state.stats['attacks_detected'] += 1
                            st.session_state.attack_alerts.append(flow_info)
                        else:
                            st.session_state.stats['benign_flows'] += 1
                
                # Remove completed flow
                del self.flows[flow_key]
                
        except Exception as e:
            logger.error(f"Packet processing failed: {str(e)}")

# === Wireshark Test ===
def test_wireshark_interface(interface):
    """Test if Wireshark can capture on the specified interface"""
    try:
        # Set up asyncio event loop for testing
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        # Try to create a capture
        capture = pyshark.LiveCapture(interface=interface, eventloop=loop)
        return True, "Wireshark is working properly"
    except Exception as e:
        return False, f"Wireshark error: {str(e)}"

# === Live Packet Capture ===
def start_live_capture(interface, packet_count, analyzer):
    """Start live packet capture in a separate thread"""
    try:
        # Set up asyncio event loop for this thread
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        # Create capture with proper event loop
        capture = pyshark.LiveCapture(interface=interface, eventloop=loop)
        st.session_state.stats['start_time'] = datetime.now()
        
        for i, packet in enumerate(capture.sniff_continuously(packet_count=packet_count), start=1):
            if not st.session_state.monitoring_active:
                break
                
            analyzer.process_packet(packet)
            st.session_state.stats['total_packets'] += 1
            
            # Update progress
            if i % 10 == 0:
                try:
                    st.session_state.packet_queue.put(f"Processed {i} packets...")
                except:
                    pass  # Ignore queue errors in thread
                
    except Exception as e:
        logger.error(f"Live capture failed: {str(e)}")
        try:
            st.session_state.packet_queue.put(f"Capture error: {str(e)}")
        except:
            pass  # Ignore queue errors in thread

# === Streamlit UI ===
st.set_page_config(
    page_title="IoV-BERT-IDS Live Monitor", 
    layout="wide", 
    page_icon="🚨",
    initial_sidebar_state="expanded"
)

# Load models
model, vectorizer, train_embeddings, y_test, y_pred = load_models()

if model is None:
    st.error("Failed to load required models. Please check your model files.")
    st.stop()

# === Sidebar Configuration ===
st.sidebar.title("🔧 Configuration")

# Interface selection
interfaces = ["Wi-Fi", "Ethernet", "Local Area Connection", "Wi-Fi 2"]
interface = st.sidebar.selectbox("Network Interface:", interfaces, index=0)

# Monitoring controls
col1, col2 = st.sidebar.columns(2)
with col1:
    if st.button("▶️ Start Monitoring", disabled=st.session_state.monitoring_active):
        st.session_state.monitoring_active = True
        st.session_state.stats = {
            'total_packets': 0,
            'total_flows': 0,
            'attacks_detected': 0,
            'benign_flows': 0,
            'start_time': datetime.now()
        }
        st.rerun()

with col2:
    if st.button("⏹️ Stop Monitoring", disabled=not st.session_state.monitoring_active):
        st.session_state.monitoring_active = False
        st.rerun()

# Wireshark test button
if st.sidebar.button("🔍 Test Wireshark"):
    with st.spinner("Testing Wireshark interface..."):
        success, message = test_wireshark_interface(interface)
        if success:
            st.sidebar.success(f"✅ {message}")
        else:
            st.sidebar.error(f"❌ {message}")
            st.sidebar.info("💡 Try running as administrator or check interface name")

# OOD threshold
if train_embeddings is not None:
    threshold = st.sidebar.slider(
        "OOD Detection Threshold:",
        min_value=0.1,
        max_value=0.8,
        value=0.35,
        step=0.05,
        help="Lower values = more sensitive to out-of-distribution data"
    )
else:
    threshold = 0.35

# Alert settings
st.sidebar.subheader("🚨 Alert Settings")
min_confidence = st.sidebar.slider("Minimum Confidence for Alerts:", 50, 95, 80)
show_ood_warnings = st.sidebar.checkbox("Show OOD Warnings", True)

# === Main Dashboard ===
st.title("🚨 IoV-BERT-IDS Live Network Monitor")
st.markdown("Real-time network flow analysis and intrusion detection using BERT-based classification")

# === Statistics Cards ===
if st.session_state.stats['start_time']:
    runtime = datetime.now() - st.session_state.stats['start_time']
    runtime_str = str(runtime).split('.')[0]  # Remove microseconds
else:
    runtime_str = "00:00:00"

col1, col2, col3, col4, col5 = st.columns(5)
with col1:
    st.metric("Runtime", runtime_str)
with col2:
    st.metric("Packets Processed", st.session_state.stats['total_packets'])
with col3:
    st.metric("Flows Analyzed", st.session_state.stats['total_flows'])
with col4:
    st.metric("Attacks Detected", st.session_state.stats['attacks_detected'], 
              delta=f"+{len([a for a in st.session_state.attack_alerts if (datetime.now() - a['result']['timestamp']).seconds < 60])} in last minute" if st.session_state.attack_alerts else None)
with col5:
    st.metric("Benign Flows", st.session_state.stats['benign_flows'])

# === Real-time Monitoring ===
if st.session_state.monitoring_active:
    # Initialize analyzer
    analyzer = NetworkFlowAnalyzer(model, vectorizer, train_embeddings, threshold)
    
    # Start capture in background
    if st.session_state.capture_thread is None or not st.session_state.capture_thread.is_alive():
        st.session_state.capture_thread = threading.Thread(
            target=start_live_capture, 
            args=(interface, 1000, analyzer),  # Capture up to 1000 packets
            name="LiveCaptureThread"
        )
        st.session_state.capture_thread.daemon = True
        st.session_state.capture_thread.start()
    
    # Show monitoring status
    st.success(f"🔴 Live monitoring active on {interface}")
    
    # Process queue messages
    while not st.session_state.packet_queue.empty():
        message = st.session_state.packet_queue.get_nowait()
        st.info(message)

# === Real-time Visualizations ===
if st.session_state.flow_data:
    st.subheader("📊 Real-time Analysis")
    
    # Convert flow data to DataFrame for visualization
    flow_df = pd.DataFrame([
        {
            'timestamp': flow['result']['timestamp'],
            'flow': flow['flow_key'],
            'protocol': flow['protocol'],
            'duration': flow['duration'],
            'packet_count': flow['packet_count'],
            'prediction': flow['result']['label'],
            'confidence': flow['result']['confidence'],
            'severity': flow['result']['severity']
        }
        for flow in st.session_state.flow_data
    ])
    
    # Time series of predictions
    fig = make_subplots(
        rows=2, cols=2,
        subplot_titles=('Attack Detection Over Time', 'Confidence Levels', 'Flow Duration Distribution', 'Protocol Distribution'),
        specs=[[{"secondary_y": True}, {"secondary_y": False}],
               [{"secondary_y": False}, {"secondary_y": False}]]
    )
    
    # Attack detection timeline
    flow_df['is_attack'] = flow_df['prediction'] == 'ATTACK'
    attack_timeline = flow_df.groupby(flow_df['timestamp'].dt.floor('1min')).agg({
        'is_attack': ['sum', 'count']
    }).reset_index()
    attack_timeline.columns = ['timestamp', 'attacks', 'total']
    
    fig.add_trace(
        go.Scatter(x=attack_timeline['timestamp'], y=attack_timeline['attacks'], 
                  name='Attacks', line=dict(color='red', width=2)),
        row=1, col=1
    )
    fig.add_trace(
        go.Scatter(x=attack_timeline['timestamp'], y=attack_timeline['total'], 
                  name='Total Flows', line=dict(color='blue', width=1)),
        row=1, col=1, secondary_y=True
    )
    
    # Confidence levels
    fig.add_trace(
        go.Histogram(x=flow_df['confidence'], name='Confidence Distribution', 
                    marker_color='lightblue'),
        row=1, col=2
    )
    
    # Flow duration distribution
    fig.add_trace(
        go.Histogram(x=flow_df['duration'], name='Duration Distribution', 
                    marker_color='lightgreen'),
        row=2, col=1
    )
    
    # Protocol distribution
    protocol_counts = flow_df['protocol'].value_counts()
    fig.add_trace(
        go.Pie(labels=protocol_counts.index, values=protocol_counts.values, 
               name='Protocols'),
        row=2, col=2
    )
    
    fig.update_layout(height=600, showlegend=True, title_text="Live Network Analysis Dashboard")
    st.plotly_chart(fig, use_container_width=True)

# === Attack Alerts ===
if st.session_state.attack_alerts:
    st.subheader("🚨 Recent Attack Alerts")
    
    # Show recent attacks
    recent_attacks = [alert for alert in st.session_state.attack_alerts 
                     if (datetime.now() - alert['result']['timestamp']).seconds < 300]  # Last 5 minutes
    
    for i, attack in enumerate(recent_attacks[-10:]):  # Show last 10 attacks
        severity_color = "🔴" if attack['result']['severity'] == "HIGH" else "🟡" if attack['result']['severity'] == "MEDIUM" else "🟢"
        
        with st.expander(f"{severity_color} {attack['flow_key']} - {attack['result']['label']} ({attack['result']['confidence']}%)"):
            col1, col2 = st.columns(2)
            with col1:
                st.write(f"**Protocol:** {attack['protocol']}")
                st.write(f"**Duration:** {attack['duration']:.2f}s")
                st.write(f"**Packets:** {attack['packet_count']}")
            with col2:
                st.write(f"**Confidence:** {attack['result']['confidence']}%")
                st.write(f"**Severity:** {attack['result']['severity']}")
                st.write(f"**Time:** {attack['result']['timestamp'].strftime('%H:%M:%S')}")
            
            if attack['result']['ood_warning']:
                st.warning(attack['result']['ood_warning'])

# === Flow Details Table ===
if st.session_state.flow_data:
    st.subheader("📋 Recent Flow Analysis")
    
    # Create a more detailed table
    display_data = []
    for flow in list(st.session_state.flow_data)[-20:]:  # Show last 20 flows
        display_data.append({
            'Time': flow['result']['timestamp'].strftime('%H:%M:%S'),
            'Flow': flow['flow_key'],
            'Protocol': flow['protocol'],
            'Duration (s)': f"{flow['duration']:.2f}",
            'Packets': flow['packet_count'],
            'Prediction': flow['result']['label'],
            'Confidence': f"{flow['result']['confidence']}%",
            'Severity': flow['result']['severity']
        })
    
    if display_data:
        st.dataframe(pd.DataFrame(display_data), use_container_width=True)

# === Model Evaluation (if available) ===
if y_test is not None and y_pred is not None:
    with st.expander("📊 Model Performance Metrics"):
        st.subheader("Confusion Matrix")
        
        cm = confusion_matrix(y_test, y_pred)
        fig, ax = plt.subplots(figsize=(8, 6))
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', ax=ax,
                   xticklabels=['Benign', 'Attack'],
                   yticklabels=['Benign', 'Attack'])
        ax.set_xlabel("Predicted")
        ax.set_ylabel("Actual")
        ax.set_title("Model Confusion Matrix")
        st.pyplot(fig)

# === Footer ===
st.markdown("---")
st.markdown(
    """
    <div style='text-align: center; color: #666;'>
        <p>IoV-BERT-IDS Live Monitor | Real-time Network Intrusion Detection System</p>
        <p>Powered by BERT embeddings and LightGBM classification</p>
    </div>
    """,
    unsafe_allow_html=True
)
