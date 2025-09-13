#!/usr/bin/env python3
"""
Demo script showing how to use IoV-BERT-IDS components programmatically
"""

import sys
import time
import numpy as np
from datetime import datetime
from pathlib import Path

# Add current directory to path
sys.path.append(str(Path(__file__).parent))

from utils import DataProcessor, AlertManager, StatisticsTracker, DataExporter
from config import get_env_config, validate_config

def demo_data_processing():
    """Demonstrate data processing capabilities"""
    print("🔧 Data Processing Demo")
    print("-" * 30)
    
    # Initialize data processor
    config = {
        'selected_features': [
            'Destination_Port', 'Flow_Duration', 'Total_Fwd_Packets', 'Total_Backward_Packets',
            'Fwd_Packet_Length_Mean', 'Bwd_Packet_Length_Mean',
            'Packet_Length_Mean', 'Flow_IAT_Mean', 'Fwd_IAT_Total', 'Bwd_IAT_Total',
            'Init_Win_bytes_forward', 'Init_Win_bytes_backward'
        ]
    }
    
    processor = DataProcessor(config)
    
    # Simulate packet data
    mock_packets = [
        {
            'src_ip': '192.168.1.100',
            'dst_ip': '192.168.1.1',
            'protocol': 'TCP',
            'packet_length': 1500,
            'timestamp': 1000.0,
            'tcp_window_size': 65535
        },
        {
            'src_ip': '192.168.1.1',
            'dst_ip': '192.168.1.100',
            'protocol': 'TCP',
            'packet_length': 1000,
            'timestamp': 1000.1,
            'tcp_window_size': 32768
        },
        {
            'src_ip': '192.168.1.100',
            'dst_ip': '192.168.1.1',
            'protocol': 'TCP',
            'packet_length': 500,
            'timestamp': 1000.2,
            'tcp_window_size': 65535
        }
    ]
    
    # Calculate flow statistics
    stats = processor.calculate_flow_statistics(mock_packets)
    print("📊 Flow Statistics:")
    for key, value in stats.items():
        print(f"   {key}: {value}")
    
    # Create flow description
    flow_desc = processor.create_flow_description(stats)
    print(f"\n📝 Flow Description:\n   {flow_desc}")
    
    return stats, flow_desc

def demo_alert_management():
    """Demonstrate alert management capabilities"""
    print("\n🚨 Alert Management Demo")
    print("-" * 30)
    
    # Initialize alert manager
    config = {'max_alert_history': 100}
    alert_manager = AlertManager(config)
    
    # Create mock alerts
    mock_flows = [
        {
            'flow_key': '192.168.1.100 ↔ 192.168.1.1',
            'src_ip': '192.168.1.100',
            'dst_ip': '192.168.1.1',
            'protocol': 'TCP',
            'duration': 1.5,
            'packet_count': 10
        },
        {
            'flow_key': '192.168.1.200 ↔ 10.0.0.1',
            'src_ip': '192.168.1.200',
            'dst_ip': '10.0.0.1',
            'protocol': 'UDP',
            'duration': 0.5,
            'packet_count': 5
        }
    ]
    
    mock_predictions = [
        {
            'label': 'BENIGN',
            'confidence': 85.5,
            'severity': 'LOW',
            'ood_warning': None
        },
        {
            'label': 'ATTACK',
            'confidence': 95.2,
            'severity': 'HIGH',
            'ood_warning': 'Flow seems different from training data'
        }
    ]
    
    # Create and add alerts
    for flow, prediction in zip(mock_flows, mock_predictions):
        alert = alert_manager.create_alert(flow, prediction)
        alert_manager.add_alert(alert)
        print(f"✅ Created alert: {alert['prediction']} ({alert['confidence']}%)")
    
    # Get alert summary
    summary = alert_manager.get_alert_summary()
    print(f"\n📈 Alert Summary:")
    for key, value in summary.items():
        print(f"   {key}: {value}")
    
    return alert_manager

def demo_statistics_tracking():
    """Demonstrate statistics tracking capabilities"""
    print("\n📊 Statistics Tracking Demo")
    print("-" * 30)
    
    # Initialize statistics tracker
    tracker = StatisticsTracker()
    
    # Simulate some activity
    print("Simulating network activity...")
    for i in range(10):
        tracker.update_packet_count(np.random.randint(1, 10))
        is_attack = np.random.random() < 0.2  # 20% chance of attack
        tracker.update_flow_count(is_attack)
        time.sleep(0.1)  # Simulate processing time
    
    # Display statistics
    print(f"📈 Current Statistics:")
    print(f"   Total Packets: {tracker.stats['total_packets']}")
    print(f"   Total Flows: {tracker.stats['total_flows']}")
    print(f"   Attacks Detected: {tracker.stats['attacks_detected']}")
    print(f"   Benign Flows: {tracker.stats['benign_flows']}")
    print(f"   Attack Rate: {tracker.get_attack_rate():.1f}%")
    print(f"   Packet Rate: {tracker.get_packet_rate():.1f} packets/sec")
    print(f"   Runtime: {tracker.get_runtime()}")
    
    return tracker

def demo_data_export():
    """Demonstrate data export capabilities"""
    print("\n💾 Data Export Demo")
    print("-" * 30)
    
    # Initialize data exporter
    exporter = DataExporter("demo_exports")
    
    # Create mock data
    mock_flows = [
        {
            'timestamp': datetime.now(),
            'flow_key': '192.168.1.100 ↔ 192.168.1.1',
            'protocol': 'TCP',
            'duration': 1.5,
            'packet_count': 10,
            'prediction': 'BENIGN',
            'confidence': 85.5
        },
        {
            'timestamp': datetime.now(),
            'flow_key': '192.168.1.200 ↔ 10.0.0.1',
            'protocol': 'UDP',
            'duration': 0.5,
            'packet_count': 5,
            'prediction': 'ATTACK',
            'confidence': 95.2
        }
    ]
    
    mock_alerts = [
        {
            'id': 'alert_1',
            'timestamp': datetime.now(),
            'flow_key': '192.168.1.200 ↔ 10.0.0.1',
            'prediction': 'ATTACK',
            'confidence': 95.2,
            'severity': 'HIGH'
        }
    ]
    
    # Export data
    try:
        flows_file = exporter.export_flows(mock_flows)
        print(f"✅ Exported flows to: {flows_file}")
        
        alerts_file = exporter.export_alerts(mock_alerts)
        print(f"✅ Exported alerts to: {alerts_file}")
        
        stats_file = exporter.export_statistics({'total_flows': 2, 'attacks': 1})
        print(f"✅ Exported statistics to: {stats_file}")
        
    except Exception as e:
        print(f"❌ Export failed: {e}")

def demo_configuration():
    """Demonstrate configuration management"""
    print("\n⚙️ Configuration Demo")
    print("-" * 30)
    
    try:
        # Validate configuration
        validate_config()
        print("✅ Configuration validation passed")
        
        # Get environment configuration
        env_config = get_env_config()
        print("🌍 Environment Configuration:")
        for key, value in env_config.items():
            print(f"   {key}: {value}")
            
    except Exception as e:
        print(f"❌ Configuration error: {e}")

def main():
    """Main demo function"""
    print("🎯 IoV-BERT-IDS Component Demo")
    print("=" * 50)
    
    try:
        # Run all demos
        demo_configuration()
        demo_data_processing()
        demo_alert_management()
        demo_statistics_tracking()
        demo_data_export()
        
        print("\n🎉 All demos completed successfully!")
        print("\n💡 To run the full application:")
        print("   python run_live_monitor.py")
        print("   or")
        print("   streamlit run enhanced_live_ids.py")
        
    except Exception as e:
        print(f"\n❌ Demo failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
