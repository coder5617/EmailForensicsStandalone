#!/usr/bin/env python3
"""
Troubleshooting script for Email Forensics Desktop App
Helps diagnose and fix common issues
"""

import sys
import os
import subprocess
from pathlib import Path

def check_python_version():
    """Check Python version"""
    print("=" * 60)
    print("PYTHON VERSION CHECK")
    print("-" * 60)
    
    version = sys.version_info
    print(f"Python version: {version.major}.{version.minor}.{version.micro}")
    
    if version.major < 3 or (version.major == 3 and version.minor < 9):
        print("❌ Python 3.9 or higher is required")
        return False
    else:
        print("✅ Python version is compatible")
        return True

def check_imports():
    """Check if all required modules can be imported"""
    print("\n" + "=" * 60)
    print("MODULE IMPORT CHECK")
    print("-" * 60)
    
    modules_to_check = [
        ('PySide6', 'PySide6.QtWidgets'),
        ('dnspython', 'dns.resolver'),
        ('requests', 'requests'),
        ('reportlab', 'reportlab.platypus'),
    ]
    
    all_ok = True
    for display_name, import_name in modules_to_check:
        try:
            module_parts = import_name.split('.')
            module = __import__(import_name)
            for part in module_parts[1:]:
                module = getattr(module, part)
            print(f"✅ {display_name:15} - OK")
        except ImportError as e:
            print(f"❌ {display_name:15} - FAILED: {e}")
            all_ok = False
    
    return all_ok

def check_local_modules():
    """Check if all local modules exist"""
    print("\n" + "=" * 60)
    print("LOCAL MODULE CHECK")
    print("-" * 60)
    
    required_files = [
        'email_forensics_main.py',
        'email_core.py',
        'ip_lookup.py',
        'dns_lookup.py',
        'config_manager.py',
        'export_manager.py'
    ]
    
    all_ok = True
    for file in required_files:
        if os.path.exists(file):
            print(f"✅ {file:25} - Found")
        else:
            print(f"❌ {file:25} - Missing")
            all_ok = False
    
    return all_ok

def fix_style_issue():
    """Fix the reportlab style issue"""
    print("\n" + "=" * 60)
    print("FIXING REPORTLAB STYLE ISSUE")
    print("-" * 60)
    
    try:
        # Read the current export_manager.py
        with open('export_manager.py', 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Check if already fixed
        if 'CustomCode' in content and "'Code'" not in content:
            print("✅ export_manager.py already fixed")
            return True
        
        # Apply fixes
        replacements = [
            ("name='Code'", "name='CustomCode'"),
            ("self.styles['Code']", "self.styles['CustomCode']"),
            (", self.styles.Code)", ", self.styles.CustomCode)"),
        ]
        
        for old, new in replacements:
            if old in content:
                content = content.replace(old, new)
                print(f"  Fixed: {old} -> {new}")
        
        # Write back
        with open('export_manager.py', 'w', encoding='utf-8') as f:
            f.write(content)
        
        print("✅ export_manager.py has been fixed")
        return True
        
    except Exception as e:
        print(f"❌ Failed to fix export_manager.py: {e}")
        return False

def install_missing_packages():
    """Offer to install missing packages"""
    print("\n" + "=" * 60)
    print("PACKAGE INSTALLATION")
    print("-" * 60)
    
    response = input("Would you like to install missing packages? (y/n): ")
    if response.lower() != 'y':
        return False
    
    packages = ['PySide6', 'dnspython', 'requests', 'reportlab']
    
    for package in packages:
        print(f"\nInstalling {package}...")
        try:
            subprocess.check_call([sys.executable, '-m', 'pip', 'install', package])
            print(f"✅ {package} installed successfully")
        except subprocess.CalledProcessError:
            print(f"❌ Failed to install {package}")
            return False
    
    return True

def test_run():
    """Try to run the application"""
    print("\n" + "=" * 60)
    print("TEST RUN")
    print("-" * 60)
    
    print("Attempting to import and initialize the application...")
    
    try:
        # Import the modules
        import email_core
        print("✅ email_core imported")
        
        import ip_lookup
        print("✅ ip_lookup imported")
        
        import dns_lookup
        print("✅ dns_lookup imported")
        
        import config_manager
        print("✅ config_manager imported")
        
        import export_manager
        print("✅ export_manager imported")
        
        # Try to create instances
        analyzer = email_core.EmailAnalyzer()
        print("✅ EmailAnalyzer created")
        
        config = config_manager.ConfigManager()
        print("✅ ConfigManager created")
        
        exporter = export_manager.ExportManager()
        print("✅ ExportManager created")
        
        print("\n✅ All modules working correctly!")
        return True
        
    except Exception as e:
        print(f"\n❌ Error during test: {e}")
        import traceback
        traceback.print_exc()
        return False

def create_test_script():
    """Create a minimal test script"""
    print("\n" + "=" * 60)
    print("CREATING TEST SCRIPT")
    print("-" * 60)
    
    test_script = '''#!/usr/bin/env python3
"""Minimal test script for Email Forensics App"""

import sys
print("Python:", sys.version)

try:
    from PySide6.QtWidgets import QApplication, QMainWindow, QTextEdit, QPushButton, QVBoxLayout, QWidget
    from PySide6.QtCore import Qt
    
    class TestWindow(QMainWindow):
        def __init__(self):
            super().__init__()
            self.setWindowTitle("Email Forensics Test")
            self.setGeometry(100, 100, 600, 400)
            
            central = QWidget()
            self.setCentralWidget(central)
            layout = QVBoxLayout(central)
            
            self.text = QTextEdit()
            self.text.setPlaceholderText("If you can see this, PySide6 is working!")
            layout.addWidget(self.text)
            
            button = QPushButton("Test Button - Click Me!")
            button.clicked.connect(self.on_click)
            layout.addWidget(button)
        
        def on_click(self):
            self.text.append("Button clicked! Qt is working properly.")
    
    app = QApplication(sys.argv)
    window = TestWindow()
    window.show()
    sys.exit(app.exec())
    
except Exception as e:
    print(f"Error: {e}")
    input("Press Enter to exit...")
'''
    
    with open('test_gui.py', 'w') as f:
        f.write(test_script)
    
    print("✅ Created test_gui.py")
    print("   Run it with: python test_gui.py")
    return True

def main():
    """Main troubleshooting routine"""
    print("=" * 60)
    print("EMAIL FORENSICS DESKTOP - TROUBLESHOOTING")
    print("=" * 60)
    
    # Check Python version
    if not check_python_version():
        print("\n⚠️  Please install Python 3.9 or higher")
        input("Press Enter to exit...")
        return
    
    # Check local modules
    if not check_local_modules():
        print("\n⚠️  Missing local modules. Ensure all .py files are in the current directory")
        input("Press Enter to exit...")
        return
    
    # Fix the style issue
    fix_style_issue()
    
    # Check imports
    if not check_imports():
        print("\n⚠️  Some packages are missing")
        if install_missing_packages():
            print("\n✅ Packages installed. Please restart the script.")
        else:
            print("\n⚠️  Please install missing packages manually:")
            print("   pip install PySide6 dnspython requests reportlab")
        input("Press Enter to exit...")
        return
    
    # Test run
    if test_run():
        print("\n" + "=" * 60)
        print("✅ ALL CHECKS PASSED!")
        print("=" * 60)
        print("\nYou should now be able to run:")
        print("  python email_forensics_main.py")
        print("\nIf you still have issues, try:")
        print("  python test_gui.py")
        create_test_script()
    else:
        print("\n⚠️  Some issues remain. Check the error messages above.")
    
    input("\nPress Enter to exit...")

if __name__ == "__main__":
    main()