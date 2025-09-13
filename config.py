"""
Configuration file for IoV-BERT-IDS Live Monitor
"""

import os
from pathlib import Path

# === Model Configuration ===
MODEL_CONFIG = {
    'model_path': 'lightgbm_llm_ids.pkl',
    'embeddings_path': 'X_embeddings.pkl',
    'test_data_path': 'y_test.pkl',
    'predictions_path': 'y_pred.pkl',
    'vectorizer_model': 'paraphrase-MiniLM-L3-v2'
}

# === Network Configuration ===
NETWORK_CONFIG = {
    'default_interface': 'Wi-Fi',
    'available_interfaces': ['Wi-Fi', 'Ethernet', 'Local Area Connection', 'Wi-Fi 2'],
    'max_packets_per_flow': 100,
    'flow_timeout_seconds': 30,
    'max_flows_in_memory': 1000
}

# === Detection Configuration ===
DETECTION_CONFIG = {
    'default_ood_threshold': 0.35,
    'min_confidence_alert': 80,
    'high_confidence_threshold': 90,
    'medium_confidence_threshold': 70,
    'low_confidence_threshold': 50
}

# === UI Configuration ===
UI_CONFIG = {
    'max_display_flows': 20,
    'max_display_alerts': 10,
    'chart_height': 600,
    'refresh_interval_seconds': 5,
    'max_flow_history': 1000,
    'max_alert_history': 100
}

# === Logging Configuration ===
LOGGING_CONFIG = {
    'log_level': 'INFO',
    'log_file': 'ids_logs.log',
    'max_log_size_mb': 10,
    'backup_count': 5
}

# === Feature Extraction Configuration ===
FEATURE_CONFIG = {
    'selected_features': [
        'Destination_Port', 'Flow_Duration', 'Total_Fwd_Packets', 'Total_Backward_Packets',
        'Fwd_Packet_Length_Mean', 'Bwd_Packet_Length_Mean',
        'Packet_Length_Mean', 'Flow_IAT_Mean', 'Fwd_IAT_Total', 'Bwd_IAT_Total',
        'Init_Win_bytes_forward', 'Init_Win_bytes_backward'
    ],
    'flow_aggregation_window': 60,  # seconds
    'min_packets_per_flow': 2
}

# === Alert Configuration ===
ALERT_CONFIG = {
    'severity_levels': {
        'HIGH': {'min_confidence': 90, 'color': '🔴', 'priority': 1},
        'MEDIUM': {'min_confidence': 70, 'color': '🟡', 'priority': 2},
        'LOW': {'min_confidence': 50, 'color': '🟢', 'priority': 3}
    },
    'alert_retention_hours': 24,
    'max_alerts_per_minute': 100
}

# === Performance Configuration ===
PERFORMANCE_CONFIG = {
    'max_concurrent_flows': 50,
    'batch_processing_size': 32,
    'memory_cleanup_interval': 300,  # seconds
    'enable_caching': True
}

# === Security Configuration ===
SECURITY_CONFIG = {
    'enable_ood_detection': True,
    'enable_anomaly_detection': True,
    'enable_rate_limiting': True,
    'max_packets_per_second': 1000
}

# === File Paths ===
BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / 'data'
LOGS_DIR = BASE_DIR / 'logs'
MODELS_DIR = BASE_DIR / 'models'

# Create directories if they don't exist
for directory in [DATA_DIR, LOGS_DIR, MODELS_DIR]:
    directory.mkdir(exist_ok=True)

# === Environment Variables ===
def get_env_config():
    """Load configuration from environment variables"""
    return {
        'debug_mode': os.getenv('DEBUG', 'False').lower() == 'true',
        'log_level': os.getenv('LOG_LEVEL', LOGGING_CONFIG['log_level']),
        'interface': os.getenv('NETWORK_INTERFACE', NETWORK_CONFIG['default_interface']),
        'max_packets': int(os.getenv('MAX_PACKETS', '1000')),
        'ood_threshold': float(os.getenv('OOD_THRESHOLD', str(DETECTION_CONFIG['default_ood_threshold'])))
    }

# === Validation Functions ===
def validate_config():
    """Validate configuration parameters"""
    errors = []
    
    # Check if model files exist
    for key, path in MODEL_CONFIG.items():
        if key.endswith('_path') and not Path(path).exists():
            errors.append(f"Model file not found: {path}")
    
    # Validate thresholds
    if not 0 <= DETECTION_CONFIG['default_ood_threshold'] <= 1:
        errors.append("OOD threshold must be between 0 and 1")
    
    if not 0 <= DETECTION_CONFIG['min_confidence_alert'] <= 100:
        errors.append("Min confidence alert must be between 0 and 100")
    
    if errors:
        raise ValueError(f"Configuration validation failed: {'; '.join(errors)}")
    
    return True

# === Configuration Helper Functions ===
def get_model_path(model_name):
    """Get full path for model file"""
    return MODELS_DIR / model_name if not Path(model_name).is_absolute() else Path(model_name)

def get_log_file_path():
    """Get full path for log file"""
    return LOGS_DIR / LOGGING_CONFIG['log_file']

def get_interface_list():
    """Get list of available network interfaces"""
    return NETWORK_CONFIG['available_interfaces']

def get_severity_config(severity):
    """Get configuration for specific severity level"""
    return ALERT_CONFIG['severity_levels'].get(severity.upper(), ALERT_CONFIG['severity_levels']['LOW'])

# Initialize configuration
if __name__ == "__main__":
    try:
        validate_config()
        print("✅ Configuration validation passed")
    except ValueError as e:
        print(f"❌ Configuration validation failed: {e}")
