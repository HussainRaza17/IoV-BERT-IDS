# IoV-BERT-IDS Live Monitor

A real-time network intrusion detection system that captures live network traffic and analyzes it using BERT-based embeddings and LightGBM classification.

## 🚀 Features

### Real-time Network Monitoring
- **Live Packet Capture**: Captures network packets in real-time using pyshark
- **Flow Analysis**: Automatically groups packets into network flows and extracts features
- **Multi-Protocol Support**: Handles TCP, UDP, ICMP, and other network protocols
- **Bidirectional Flow Tracking**: Tracks both forward and backward packet flows

### Advanced Detection Capabilities
- **BERT-based Classification**: Uses sentence transformers for feature extraction
- **LightGBM Model**: High-performance gradient boosting for attack detection
- **Out-of-Distribution Detection**: Identifies flows that differ from training data
- **Confidence Scoring**: Provides confidence levels for all predictions
- **Severity Classification**: Categorizes threats as HIGH, MEDIUM, or LOW severity

### Interactive Dashboard
- **Real-time Visualizations**: Live charts showing attack patterns and flow statistics
- **Alert Management**: Comprehensive alert system with severity-based notifications
- **Flow Details**: Detailed view of analyzed network flows
- **Performance Metrics**: Real-time statistics and performance monitoring
- **Export Capabilities**: Export flows, alerts, and statistics for further analysis

### Modern UI/UX
- **Streamlit Interface**: Clean, responsive web interface
- **Real-time Updates**: Live data refresh without page reloads
- **Interactive Charts**: Plotly-powered visualizations with zoom and filter capabilities
- **Responsive Design**: Works on desktop and mobile devices
- **Dark/Light Theme**: Configurable interface themes

## 📋 Prerequisites

### System Requirements
- Python 3.8 or higher
- Windows 10/11 (with Wireshark installed)
- Administrator privileges for packet capture
- At least 4GB RAM
- 1GB free disk space

### Required Software
- **Wireshark**: For packet capture capabilities
- **Npcap**: Network packet capture driver (installed with Wireshark)

## 🛠️ Installation

### 1. Clone the Repository
```bash
git clone <repository-url>
cd IoV-BERT-IDS
```

### 2. Create Virtual Environment
```bash
python -m venv venv
# On Windows
venv\Scripts\activate
# On Linux/Mac
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Install Wireshark
- Download and install Wireshark from [https://www.wireshark.org/](https://www.wireshark.org/)
- Make sure to install Npcap during the installation process
- Restart your computer after installation

### 5. Verify Installation
```bash
python -c "import pyshark; print('PyShark installed successfully')"
```

## 🚀 Quick Start

### 1. Start the Application
```bash
streamlit run enhanced_live_ids.py
```

### 2. Configure Settings
- Select your network interface (Wi-Fi, Ethernet, etc.)
- Set the OOD detection threshold (default: 0.35)
- Configure alert settings

### 3. Start Monitoring
- Click "Start Monitoring" to begin live packet capture
- Watch real-time visualizations and alerts
- Use "Stop Monitoring" to halt the capture

## 📊 Usage Guide

### Interface Configuration
1. **Network Interface Selection**: Choose the interface you want to monitor
2. **Packet Count**: Set the maximum number of packets to capture per session
3. **OOD Threshold**: Adjust sensitivity for out-of-distribution detection

### Monitoring Controls
- **Start Monitoring**: Begin live packet capture and analysis
- **Stop Monitoring**: Halt the current monitoring session
- **Reset Statistics**: Clear all collected data and restart counters

### Understanding the Dashboard

#### Statistics Cards
- **Runtime**: How long the monitoring has been active
- **Packets Processed**: Total number of packets analyzed
- **Flows Analyzed**: Number of network flows processed
- **Attacks Detected**: Number of malicious flows identified
- **Benign Flows**: Number of normal flows identified

#### Real-time Visualizations
- **Attack Detection Timeline**: Shows attack frequency over time
- **Confidence Distribution**: Histogram of prediction confidence levels
- **Flow Duration Distribution**: Analysis of flow durations
- **Protocol Distribution**: Breakdown of network protocols

#### Alert System
- **Severity Levels**: 
  - 🔴 HIGH: Confidence > 90%
  - 🟡 MEDIUM: Confidence 70-90%
  - 🟢 LOW: Confidence 50-70%
- **Alert Details**: Click on alerts to see detailed information
- **OOD Warnings**: Notifications for out-of-distribution data

## 🔧 Configuration

### Environment Variables
```bash
# Debug mode
export DEBUG=true

# Log level
export LOG_LEVEL=INFO

# Network interface
export NETWORK_INTERFACE=Wi-Fi

# Maximum packets per session
export MAX_PACKETS=1000

# OOD detection threshold
export OOD_THRESHOLD=0.35
```

### Configuration File
Edit `config.py` to customize:
- Model paths and settings
- Network interface preferences
- Detection thresholds
- UI configuration
- Logging settings

## 📈 Performance Optimization

### System Tuning
1. **Memory Management**: The system automatically manages memory by limiting flow history
2. **Batch Processing**: Flows are processed in batches for efficiency
3. **Caching**: Model loading and feature extraction are cached
4. **Cleanup**: Automatic cleanup of old data and logs

### Recommended Settings
- **Max Flows in Memory**: 1000 (adjust based on available RAM)
- **Flow Timeout**: 30 seconds
- **Max Packets per Flow**: 100
- **Batch Size**: 32

## 🚨 Troubleshooting

### Common Issues

#### "No such device" Error
- **Cause**: Network interface not found
- **Solution**: Check interface name in system settings
- **Fix**: Use `ipconfig` (Windows) or `ifconfig` (Linux) to list interfaces

#### Permission Denied
- **Cause**: Insufficient privileges for packet capture
- **Solution**: Run as administrator or use sudo
- **Fix**: Right-click terminal and "Run as administrator"

#### Model Loading Errors
- **Cause**: Missing model files
- **Solution**: Ensure all .pkl files are in the project directory
- **Fix**: Re-run the training notebook to generate models

#### High CPU Usage
- **Cause**: Processing too many packets simultaneously
- **Solution**: Reduce packet count or increase flow timeout
- **Fix**: Adjust settings in the configuration

### Debug Mode
Enable debug mode for detailed logging:
```bash
export DEBUG=true
streamlit run enhanced_live_ids.py
```

## 📊 Data Export

### Export Options
1. **Flow Data**: Export analyzed flows to CSV
2. **Alert Data**: Export alerts to JSON
3. **Statistics**: Export system statistics to JSON

### Export Locations
- Exports are saved in the `exports/` directory
- Files are timestamped for easy identification
- Data includes all relevant metadata and timestamps

## 🔒 Security Considerations

### Data Privacy
- No network data is stored permanently by default
- All captured data is processed in memory only
- Export functions allow you to control data retention

### Network Security
- The system only captures and analyzes network traffic
- No data is transmitted to external servers
- All processing is done locally

### Access Control
- Requires administrator privileges for packet capture
- No built-in authentication (add if needed for production)
- Consider network segmentation for sensitive environments

## 🤝 Contributing

### Development Setup
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

### Code Style
- Follow PEP 8 guidelines
- Use type hints where appropriate
- Add docstrings to functions and classes
- Include error handling

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- **CIC-IDS-2017 Dataset**: Used for model training
- **Sentence Transformers**: For BERT-based embeddings
- **LightGBM**: For gradient boosting classification
- **Streamlit**: For the web interface
- **PyShark**: For packet capture capabilities
- **Plotly**: For interactive visualizations

## 📞 Support

For issues and questions:
1. Check the troubleshooting section
2. Search existing issues
3. Create a new issue with detailed information
4. Include system information and error logs

## 🔄 Updates and Changelog

### Version 2.0.0 (Current)
- Real-time packet capture and analysis
- Interactive dashboard with live visualizations
- Comprehensive alert system
- Export capabilities
- Performance optimizations
- Enhanced UI/UX

### Version 1.0.0
- Basic text-based classification
- Static model evaluation
- Simple Streamlit interface

---

**Note**: This system is designed for educational and research purposes. For production use, consider additional security measures and compliance requirements.
