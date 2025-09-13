#!/usr/bin/env python3
"""
Launcher script for IoV-BERT-IDS Live Monitor
"""

import sys
import os
import subprocess
from pathlib import Path

def check_dependencies():
    """Check if all required dependencies are installed"""
    required_packages = [
        'streamlit', 'joblib', 'sentence_transformers', 'lightgbm', 
        'sklearn', 'pyshark', 'plotly', 'pandas', 'numpy', 
        'matplotlib', 'seaborn'
    ]
    
    missing_packages = []
    for package in required_packages:
        try:
            __import__(package)
        except ImportError:
            missing_packages.append(package)
    
    if missing_packages:
        print("❌ Missing required packages:")
        for package in missing_packages:
            print(f"   - {package}")
        print("\n💡 Install missing packages with:")
        print(f"   pip install {' '.join(missing_packages)}")
        return False
    
    return True

def check_model_files():
    """Check if required model files exist"""
    required_files = [
        'lightgbm_llm_ids.pkl',
        'X_embeddings.pkl',
        'y_test.pkl',
        'y_pred.pkl'
    ]
    
    missing_files = []
    for file in required_files:
        if not Path(file).exists():
            missing_files.append(file)
    
    if missing_files:
        print("❌ Missing required model files:")
        for file in missing_files:
            print(f"   - {file}")
        print("\n💡 Run the training notebook to generate model files")
        return False
    
    return True

def check_wireshark():
    """Check if Wireshark is available"""
    try:
        # Try to import pyshark and create a capture
        import pyshark
        # This will fail if Wireshark is not properly installed
        capture = pyshark.LiveCapture(interface='Wi-Fi')
        return True
    except Exception as e:
        print("❌ Wireshark not properly installed or configured")
        print(f"   Error: {str(e)}")
        print("\n💡 Install Wireshark from https://www.wireshark.org/")
        print("   Make sure to install Npcap during installation")
        return False

def main():
    """Main launcher function"""
    print("🚀 IoV-BERT-IDS Live Monitor Launcher")
    print("=" * 50)
    
    # Check dependencies
    print("📦 Checking dependencies...")
    if not check_dependencies():
        sys.exit(1)
    print("✅ All dependencies installed")
    
    # Check model files
    print("\n🤖 Checking model files...")
    if not check_model_files():
        sys.exit(1)
    print("✅ All model files found")
    
    # Check Wireshark
    print("\n🔍 Checking Wireshark installation...")
    if not check_wireshark():
        print("⚠️  Wireshark check failed, but continuing...")
        print("   You may need to run as administrator")
    else:
        print("✅ Wireshark is properly configured")
    
    # Launch the application
    print("\n🚀 Starting IoV-BERT-IDS Live Monitor...")
    print("   Open your browser to http://localhost:8501")
    print("   Press Ctrl+C to stop the application")
    print("=" * 50)
    
    try:
        # Run the Streamlit app
        subprocess.run([
            sys.executable, '-m', 'streamlit', 'run', 'enhanced_live_ids.py',
            '--server.port', '8501',
            '--server.address', 'localhost',
            '--browser.gatherUsageStats', 'false'
        ])
    except KeyboardInterrupt:
        print("\n👋 Application stopped by user")
    except Exception as e:
        print(f"\n❌ Error starting application: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
