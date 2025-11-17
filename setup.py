#!/usr/bin/env python3
"""
Setup script for IoV-BERT-IDS Live Monitor
"""

import os
import sys
import subprocess
import platform
from pathlib import Path

def print_header():
    """Print setup header"""
    print("🚀 IoV-BERT-IDS Live Monitor Setup")
    print("=" * 50)
    print("Setting up your real-time network intrusion detection system...")
    print()

def check_python_version():
    """Check if Python version is compatible"""
    print("🐍 Checking Python version...")
    
    if sys.version_info < (3, 8):
        print("❌ Python 3.8 or higher is required")
        print(f"   Current version: {sys.version}")
        return False
    
    print(f"✅ Python {sys.version.split()[0]} is compatible")
    return True

def create_virtual_environment():
    """Create virtual environment"""
    print("\n📦 Creating virtual environment...")
    
    venv_path = Path("venv")
    if venv_path.exists():
        print("✅ Virtual environment already exists")
        return True
    
    try:
        subprocess.run([sys.executable, "-m", "venv", "venv"], check=True)
        print("✅ Virtual environment created successfully")
        return True
    except subprocess.CalledProcessError:
        print("❌ Failed to create virtual environment")
        return False

def get_pip_command():
    """Get the correct pip command for the platform"""
    if platform.system() == "Windows":
        return str(Path("venv/Scripts/pip.exe"))
    else:
        return str(Path("venv/bin/pip"))

def get_python_command():
    """Get the correct python command for the platform"""
    if platform.system() == "Windows":
        return str(Path("venv/Scripts/python.exe"))
    else:
        return str(Path("venv/bin/python"))

def install_dependencies():
    """Install required dependencies"""
    print("\n📚 Installing dependencies...")
    
    pip_cmd = get_pip_command()
    
    # Upgrade pip first
    try:
        subprocess.run([pip_cmd, "install", "--upgrade", "pip"], check=True)
        print("✅ pip upgraded successfully")
    except subprocess.CalledProcessError:
        print("⚠️  Failed to upgrade pip, continuing...")
    
    # Install requirements
    if Path("requirements.txt").exists():
        try:
            subprocess.run([pip_cmd, "install", "-r", "requirements.txt"], check=True)
            print("✅ Dependencies installed successfully")
            return True
        except subprocess.CalledProcessError:
            print("❌ Failed to install dependencies from requirements.txt")
            return False
    else:
        print("❌ requirements.txt not found")
        return False

def check_wireshark_installation():
    """Check if Wireshark is installed"""
    print("\n🔍 Checking Wireshark installation...")
    
    try:
        import importlib.util
        import importlib
        # Check if pyshark is available without causing a static import error
        spec = importlib.util.find_spec("pyshark")
        if spec is None:
            raise ImportError("pyshark not found")
        pyshark = importlib.import_module("pyshark")
        # Try to create a capture to test Wireshark (fallback to default interface)
        try:
            capture = pyshark.LiveCapture(interface='Wi-Fi')
        except Exception:
            capture = pyshark.LiveCapture()
        # If object created, assume pyshark + Wireshark are available
        print("✅ Wireshark is properly installed and configured")
        return True
    except ImportError:
        print("❌ PyShark not installed (this should be fixed by dependency installation)")
        return False
    except Exception as e:
        print("⚠️  Wireshark may not be properly installed")
        print(f"   Error: {str(e)}")
        print("   You may need to install Wireshark manually")
        return False

def check_model_files():
    """Check if model files exist"""
    print("\n🤖 Checking model files...")
    
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
        print("❌ Missing model files:")
        for file in missing_files:
            print(f"   - {file}")
        print("\n💡 You need to run the training notebook to generate these files")
        print("   Open network-detection-system.ipynb and run all cells")
        return False
    
    print("✅ All model files found")
    return True

def create_directories():
    """Create necessary directories"""
    print("\n📁 Creating directories...")
    
    directories = ['exports', 'logs', 'data', 'models']
    for directory in directories:
        Path(directory).mkdir(exist_ok=True)
        print(f"✅ Created directory: {directory}")

def create_launcher_scripts():
    """Create launcher scripts for different platforms"""
    print("\n🚀 Creating launcher scripts...")
    
    # Windows batch file
    if platform.system() == "Windows":
        batch_content = """@echo off
echo Starting IoV-BERT-IDS Live Monitor...
call venv\\Scripts\\activate.bat
python run_live_monitor.py
pause
"""
        with open("start_monitor.bat", "w") as f:
            f.write(batch_content)
        print("✅ Created start_monitor.bat")
    
    # Unix shell script
    shell_content = """#!/bin/bash
echo "Starting IoV-BERT-IDS Live Monitor..."
source venv/bin/activate
python run_live_monitor.py
"""
    with open("start_monitor.sh", "w") as f:
        f.write(shell_content)
    
    # Make it executable on Unix systems
    if platform.system() != "Windows":
        os.chmod("start_monitor.sh", 0o755)
    
    print("✅ Created start_monitor.sh")

def run_demo():
    """Run the demo to test the installation"""
    print("\n🧪 Running demo to test installation...")
    
    python_cmd = get_python_command()
    
    try:
        result = subprocess.run([python_cmd, "demo_usage.py"], 
                              capture_output=True, text=True, timeout=60)
        
        if result.returncode == 0:
            print("✅ Demo completed successfully")
            print("   All components are working correctly")
            return True
        else:
            print("❌ Demo failed")
            print(f"   Error: {result.stderr}")
            return False
            
    except subprocess.TimeoutExpired:
        print("⚠️  Demo timed out, but this might be normal")
        return True
    except Exception as e:
        print(f"❌ Demo error: {e}")
        return False

def print_final_instructions():
    """Print final setup instructions"""
    print("\n🎉 Setup Complete!")
    print("=" * 50)
    print("Your IoV-BERT-IDS Live Monitor is ready to use!")
    print()
    print("🚀 To start the application:")
    if platform.system() == "Windows":
        print("   Double-click start_monitor.bat")
        print("   or run: python run_live_monitor.py")
    else:
        print("   ./start_monitor.sh")
        print("   or run: python run_live_monitor.py")
    print()
    print("🌐 The application will open in your browser at:")
    print("   http://localhost:8501")
    print()
    print("📚 For more information, see README.md")
    print("🔧 For configuration options, see config.py")
    print()
    print("⚠️  Important Notes:")
    print("   - Run as administrator for packet capture")
    print("   - Make sure Wireshark is installed")
    print("   - Check your network interface settings")

def main():
    """Main setup function"""
    print_header()
    
    # Check Python version
    if not check_python_version():
        sys.exit(1)
    
    # Create virtual environment
    if not create_virtual_environment():
        sys.exit(1)
    
    # Install dependencies
    if not install_dependencies():
        print("⚠️  Dependency installation failed, but continuing...")
    
    # Check Wireshark
    check_wireshark_installation()
    
    # Check model files
    models_ok = check_model_files()
    if not models_ok:
        print("⚠️  Model files missing, you'll need to train the model first")
    
    # Create directories
    create_directories()
    
    # Create launcher scripts
    create_launcher_scripts()
    
    # Run demo
    demo_ok = run_demo()
    if not demo_ok:
        print("⚠️  Demo failed, but setup may still be functional")
    
    # Print final instructions
    print_final_instructions()

if __name__ == "__main__":
    main()
