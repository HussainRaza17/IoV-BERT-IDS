"""
Utility functions for IoV-BERT-IDS Live Monitor
"""

import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Tuple
import logging
from collections import defaultdict, deque
import json
import pickle
from pathlib import Path

try:
    import pyshark
except ImportError:
    pyshark = None
    logger_init = logging.getLogger(__name__)
    logger_init.warning("pyshark is not installed. Please install it using 'pip install pyshark'")

logger = logging.getLogger(__name__)

class DataProcessor:
    """Handles data processing and feature extraction"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.feature_columns = config.get('selected_features', [])
        
    def extract_packet_features(self, packet) -> Dict[str, Any]:
        """Extract features from a single packet"""
        try:
            features = {}
            
            if hasattr(packet, 'ip'):
                features['src_ip'] = packet.ip.src
                features['dst_ip'] = packet.ip.dst
                features['protocol'] = packet.highest_layer
                features['packet_length'] = int(packet.length)
                features['timestamp'] = float(packet.sniff_timestamp)
                
                # Extract TCP-specific features
                if hasattr(packet, 'tcp'):
                    features['tcp_window_size'] = getattr(packet.tcp, 'window_size', 0)
                    features['tcp_flags'] = getattr(packet.tcp, 'flags', 0)
                    features['tcp_seq'] = getattr(packet.tcp, 'seq', 0)
                    features['tcp_ack'] = getattr(packet.tcp, 'ack', 0)
                
                # Extract UDP-specific features
                if hasattr(packet, 'udp'):
                    features['udp_length'] = getattr(packet.udp, 'length', 0)
                    features['udp_checksum'] = getattr(packet.udp, 'checksum', 0)
                
                # Extract ICMP-specific features
                if hasattr(packet, 'icmp'):
                    features['icmp_type'] = getattr(packet.icmp, 'type', 0)
                    features['icmp_code'] = getattr(packet.icmp, 'code', 0)
            
            return features
            
        except Exception as e:
            logger.error(f"Failed to extract packet features: {e}")
            return {}
    
    def calculate_flow_statistics(self, packets: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate flow statistics from a list of packets"""
        if len(packets) < 2:
            return {}
        
        # Separate forward and backward packets
        src_ip = packets[0]['src_ip']
        fwd_packets = [p for p in packets if p['src_ip'] == src_ip]
        bwd_packets = [p for p in packets if p['src_ip'] != src_ip]
        
        # Calculate basic statistics
        stats = {
            'total_fwd_packets': len(fwd_packets),
            'total_bwd_packets': len(bwd_packets),
            'total_packets': len(packets),
            'flow_duration': packets[-1]['timestamp'] - packets[0]['timestamp']
        }
        
        # Calculate packet length statistics
        fwd_lengths = [p['packet_length'] for p in fwd_packets]
        bwd_lengths = [p['packet_length'] for p in bwd_packets]
        all_lengths = fwd_lengths + bwd_lengths
        
        if fwd_lengths:
            stats['fwd_packet_length_mean'] = np.mean(fwd_lengths)
            stats['fwd_packet_length_std'] = np.std(fwd_lengths)
            stats['fwd_packet_length_max'] = np.max(fwd_lengths)
            stats['fwd_packet_length_min'] = np.min(fwd_lengths)
        else:
            stats.update({
                'fwd_packet_length_mean': 0,
                'fwd_packet_length_std': 0,
                'fwd_packet_length_max': 0,
                'fwd_packet_length_min': 0
            })
        
        if bwd_lengths:
            stats['bwd_packet_length_mean'] = np.mean(bwd_lengths)
            stats['bwd_packet_length_std'] = np.std(bwd_lengths)
            stats['bwd_packet_length_max'] = np.max(bwd_lengths)
            stats['bwd_packet_length_min'] = np.min(bwd_lengths)
        else:
            stats.update({
                'bwd_packet_length_mean': 0,
                'bwd_packet_length_std': 0,
                'bwd_packet_length_max': 0,
                'bwd_packet_length_min': 0
            })
        
        if all_lengths:
            stats['packet_length_mean'] = np.mean(all_lengths)
            stats['packet_length_std'] = np.std(all_lengths)
        else:
            stats.update({
                'packet_length_mean': 0,
                'packet_length_std': 0
            })
        
        # Calculate inter-arrival times
        timestamps = [p['timestamp'] for p in packets]
        iats = np.diff(timestamps)
        
        if len(iats) > 0:
            stats['flow_iat_mean'] = np.mean(iats)
            stats['flow_iat_std'] = np.std(iats)
            stats['flow_iat_max'] = np.max(iats)
            stats['flow_iat_min'] = np.min(iats)
        else:
            stats.update({
                'flow_iat_mean': 0,
                'flow_iat_std': 0,
                'flow_iat_max': 0,
                'flow_iat_min': 0
            })
        
        # Calculate forward and backward IAT
        fwd_timestamps = [p['timestamp'] for p in fwd_packets]
        bwd_timestamps = [p['timestamp'] for p in bwd_packets]
        
        if len(fwd_timestamps) > 1:
            fwd_iats = np.diff(fwd_timestamps)
            stats['fwd_iat_total'] = np.sum(fwd_iats)
            stats['fwd_iat_mean'] = np.mean(fwd_iats)
        else:
            stats['fwd_iat_total'] = 0
            stats['fwd_iat_mean'] = 0
        
        if len(bwd_timestamps) > 1:
            bwd_iats = np.diff(bwd_timestamps)
            stats['bwd_iat_total'] = np.sum(bwd_iats)
            stats['bwd_iat_mean'] = np.mean(bwd_iats)
        else:
            stats['bwd_iat_total'] = 0
            stats['bwd_iat_mean'] = 0
        
        # Extract TCP window sizes
        tcp_packets = [p for p in packets if 'tcp_window_size' in p]
        if tcp_packets:
            fwd_tcp = [p for p in tcp_packets if p['src_ip'] == src_ip]
            bwd_tcp = [p for p in tcp_packets if p['src_ip'] != src_ip]
            
            stats['init_win_bytes_forward'] = fwd_tcp[0]['tcp_window_size'] if fwd_tcp else 0
            stats['init_win_bytes_backward'] = bwd_tcp[0]['tcp_window_size'] if bwd_tcp else 0
        else:
            stats['init_win_bytes_forward'] = 0
            stats['init_win_bytes_backward'] = 0
        
        return stats
    
    def create_flow_description(self, stats: Dict[str, Any], protocol: str = "TCP") -> str:
        """Create a descriptive text for the flow similar to training data"""
        return (
            f"Flow duration is {stats.get('flow_duration', 0) * 1000000:.1f} microseconds, "
            f"Total Fwd Packets is {stats.get('total_fwd_packets', 0)}, "
            f"Total Backward Packets is {stats.get('total_bwd_packets', 0)}, "
            f"Fwd Packet Length Mean is {stats.get('fwd_packet_length_mean', 0):.1f}, "
            f"Bwd Packet Length Mean is {stats.get('bwd_packet_length_mean', 0):.1f}, "
            f"Packet Length Mean is {stats.get('packet_length_mean', 0):.1f}, "
            f"Flow IAT Mean is {stats.get('flow_iat_mean', 0):.3f}, "
            f"Fwd IAT Total is {stats.get('fwd_iat_total', 0):.1f}, "
            f"Bwd IAT Total is {stats.get('bwd_iat_total', 0):.1f}, "
            f"Init Win bytes forward is {stats.get('init_win_bytes_forward', 0)}, "
            f"Init Win bytes backward is {stats.get('init_win_bytes_backward', 0)}"
        )

class AlertManager:
    """Manages alerts and notifications"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.alerts = deque(maxlen=config.get('max_alert_history', 100))
        self.alert_counts = defaultdict(int)
        
    def create_alert(self, flow_info: Dict[str, Any], prediction_result: Dict[str, Any]) -> Dict[str, Any]:
        """Create an alert from flow information and prediction result"""
        alert = {
            'id': f"alert_{len(self.alerts)}_{int(datetime.now().timestamp())}",
            'timestamp': datetime.now(),
            'flow_key': flow_info.get('flow_key', 'Unknown'),
            'src_ip': flow_info.get('src_ip', 'Unknown'),
            'dst_ip': flow_info.get('dst_ip', 'Unknown'),
            'protocol': flow_info.get('protocol', 'Unknown'),
            'prediction': prediction_result.get('label', 'Unknown'),
            'confidence': prediction_result.get('confidence', 0),
            'severity': prediction_result.get('severity', 'LOW'),
            'ood_warning': prediction_result.get('ood_warning'),
            'flow_duration': flow_info.get('duration', 0),
            'packet_count': flow_info.get('packet_count', 0)
        }
        
        return alert
    
    def add_alert(self, alert: Dict[str, Any]):
        """Add alert to the alert queue"""
        self.alerts.append(alert)
        self.alert_counts[alert['prediction']] += 1
        
        # Log high-severity alerts
        if alert['severity'] == 'HIGH':
            logger.warning(f"HIGH SEVERITY ALERT: {alert['flow_key']} - {alert['prediction']} ({alert['confidence']}%)")
    
    def get_recent_alerts(self, minutes: int = 5) -> List[Dict[str, Any]]:
        """Get alerts from the last N minutes"""
        cutoff_time = datetime.now() - timedelta(minutes=minutes)
        return [alert for alert in self.alerts if alert['timestamp'] > cutoff_time]
    
    def get_alert_summary(self) -> Dict[str, Any]:
        """Get summary of alerts"""
        recent_alerts = self.get_recent_alerts(60)  # Last hour
        
        summary = {
            'total_alerts': len(self.alerts),
            'recent_alerts': len(recent_alerts),
            'high_severity': len([a for a in recent_alerts if a['severity'] == 'HIGH']),
            'medium_severity': len([a for a in recent_alerts if a['severity'] == 'MEDIUM']),
            'low_severity': len([a for a in recent_alerts if a['severity'] == 'LOW']),
            'attack_count': len([a for a in recent_alerts if a['prediction'] == 'ATTACK']),
            'benign_count': len([a for a in recent_alerts if a['prediction'] == 'BENIGN'])
        }
        
        return summary

class StatisticsTracker:
    """Tracks and manages system statistics"""
    
    def __init__(self):
        self.stats = {
            'total_packets': 0,
            'total_flows': 0,
            'attacks_detected': 0,
            'benign_flows': 0,
            'start_time': None,
            'last_reset': None
        }
        self.hourly_stats = deque(maxlen=24)  # Keep 24 hours of data
        
    def reset_stats(self):
        """Reset all statistics"""
        self.stats = {
            'total_packets': 0,
            'total_flows': 0,
            'attacks_detected': 0,
            'benign_flows': 0,
            'start_time': datetime.now(),
            'last_reset': datetime.now()
        }
        self.hourly_stats.clear()
    
    def update_packet_count(self, count: int = 1):
        """Update packet count"""
        self.stats['total_packets'] += count
    
    def update_flow_count(self, is_attack: bool = False):
        """Update flow count"""
        self.stats['total_flows'] += 1
        if is_attack:
            self.stats['attacks_detected'] += 1
        else:
            self.stats['benign_flows'] += 1
    
    def get_runtime(self) -> str:
        """Get formatted runtime string"""
        if self.stats['start_time']:
            runtime = datetime.now() - self.stats['start_time']
            return str(runtime).split('.')[0]  # Remove microseconds
        return "00:00:00"
    
    def get_attack_rate(self) -> float:
        """Get attack rate as percentage"""
        if self.stats['total_flows'] > 0:
            return (self.stats['attacks_detected'] / self.stats['total_flows']) * 100
        return 0.0
    
    def get_packet_rate(self) -> float:
        """Get packet processing rate per second"""
        if self.stats['start_time']:
            runtime_seconds = (datetime.now() - self.stats['start_time']).total_seconds()
            if runtime_seconds > 0:
                return self.stats['total_packets'] / runtime_seconds
        return 0.0

class DataExporter:
    """Handles data export and persistence"""
    
    def __init__(self, export_dir: str = "exports"):
        self.export_dir = Path(export_dir)
        self.export_dir.mkdir(exist_ok=True)
    
    def export_flows(self, flows: List[Dict[str, Any]], filename: Optional[str] = None) -> str:
        """Export flow data to CSV"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"flows_export_{timestamp}.csv"
        
        filepath = self.export_dir / filename
        df = pd.DataFrame(flows)
        df.to_csv(filepath, index=False)
        
        logger.info(f"Exported {len(flows)} flows to {filepath}")
        return str(filepath)
    
    def export_alerts(self, alerts: List[Dict[str, Any]], filename: Optional[str] = None) -> str:
        """Export alerts to JSON"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"alerts_export_{timestamp}.json"
        
        filepath = self.export_dir / filename
        
        # Convert datetime objects to strings for JSON serialization
        export_data = []
        for alert in alerts:
            alert_copy = alert.copy()
            alert_copy['timestamp'] = alert_copy['timestamp'].isoformat()
            export_data.append(alert_copy)
        
        with open(filepath, 'w') as f:
            json.dump(export_data, f, indent=2)
        
        logger.info(f"Exported {len(alerts)} alerts to {filepath}")
        return str(filepath)
    
    def export_statistics(self, stats: Dict[str, Any], filename: Optional[str] = None) -> str:
        """Export statistics to JSON"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"stats_export_{timestamp}.json"
        
        filepath = self.export_dir / filename
        
        # Convert datetime objects to strings
        export_stats = stats.copy()
        if 'start_time' in export_stats and export_stats['start_time']:
            export_stats['start_time'] = export_stats['start_time'].isoformat()
        if 'last_reset' in export_stats and export_stats['last_reset']:
            export_stats['last_reset'] = export_stats['last_reset'].isoformat()
def validate_network_interface(interface: str) -> bool:
    """Validate if network interface is available"""
    if pyshark is None:
        return False
    try:
        # Try to create a live capture to test interface
        capture = pyshark.LiveCapture(interface=interface)
        return True
    except Exception:
        return False
def get_available_interfaces() -> List[str]:
    """Get list of available network interfaces"""
    if pyshark is None:
        return ['Wi-Fi', 'Ethernet']  # Fallback
    try:
        # This is a simplified approach - in practice, you might want to use
        # platform-specific methods to get interface names
        common_interfaces = [
            'Wi-Fi', 'Ethernet', 'Local Area Connection', 'Wi-Fi 2',
            'eth0', 'wlan0', 'en0', 'en1'
        ]
        
        available = []
        for interface in common_interfaces:
            if validate_network_interface(interface):
                available.append(interface)
        
        return available
    except Exception:
        return ['Wi-Fi', 'Ethernet']  # Fallback
        available = []
        for interface in common_interfaces:
            if validate_network_interface(interface):
                available.append(interface)
        
        return available
    except Exception:
        return ['Wi-Fi', 'Ethernet']  # Fallback

def format_bytes(bytes_value: int) -> str:
    """Format bytes to human readable string"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_value < 1024.0:
            return f"{bytes_value:.1f} {unit}"
        bytes_value /= 1024.0
    return f"{bytes_value:.1f} PB"

def format_duration(seconds: float) -> str:
    """Format duration to human readable string"""
    if seconds < 60:
        return f"{seconds:.2f}s"
    elif seconds < 3600:
        return f"{seconds/60:.1f}m"
    else:
        return f"{seconds/3600:.1f}h"
