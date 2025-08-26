#!/usr/bin/env python3
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
