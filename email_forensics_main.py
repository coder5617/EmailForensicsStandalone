#!/usr/bin/env python3
"""
Email Forensics Desktop Application
A native desktop app for analyzing email headers and authentication
No web dependencies - fully offline capable
"""

import sys
import json
import os
from pathlib import Path
from datetime import datetime
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTextEdit, QPushButton, QLabel, QTreeWidget, QTreeWidgetItem,
    QTabWidget, QTableWidget, QTableWidgetItem, QHeaderView,
    QSplitter, QGroupBox, QMessageBox, QFileDialog, QProgressBar,
    QStatusBar, QMenuBar, QMenu, QToolBar, QStyle, QStyleFactory
)
from PySide6.QtCore import Qt, QThread, Signal, QTimer, QMimeData, QPropertyAnimation, QEasingCurve
from PySide6.QtGui import QAction, QIcon, QFont, QColor, QPalette, QDragEnterEvent, QDropEvent, QClipboard

# Import core modules
from email_core import EmailAnalyzer, EmailParseResult
from ip_lookup import IPLookupService
from dns_lookup import DNSLookupService
from config_manager import ConfigManager
from export_manager import ExportManager

class AnalysisThread(QThread):
    """Background thread for email analysis"""
    finished = Signal(object)
    error = Signal(str)
    progress = Signal(int, str)
    
    def __init__(self, header_text):
        super().__init__()
        self.header_text = header_text
        self.analyzer = EmailAnalyzer()
    
    def run(self):
        try:
            self.progress.emit(10, "Parsing email headers...")
            result = self.analyzer.analyze(self.header_text, progress_callback=self.progress.emit)
            self.finished.emit(result)
        except Exception as e:
            self.error.emit(str(e))

class EmailForensicsApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.config = ConfigManager()
        self.export_manager = ExportManager()
        self.current_result = None
        self.clipboard_monitor_enabled = False
        self.init_ui()
        self.setup_clipboard_monitor()
        self.apply_theme()
        
    def init_ui(self):
        """Initialize the user interface"""
        self.setWindowTitle("Email Forensics Analyzer")
        self.setGeometry(100, 100, 1400, 900)
        
        # Create central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Create menu bar
        self.create_menu_bar()
        
        # Create toolbar
        self.create_toolbar()
        
        # Create status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.progress_bar = QProgressBar()
        self.progress_bar.setMaximumWidth(200)
        self.progress_bar.setVisible(False)
        self.status_bar.addPermanentWidget(self.progress_bar)
        
        # Main layout
        main_layout = QVBoxLayout(central_widget)
        
        # Create splitter for input and output
        splitter = QSplitter(Qt.Vertical)
        
        # Input section
        input_widget = self.create_input_section()
        splitter.addWidget(input_widget)
        
        # Output section with tabs
        self.output_tabs = QTabWidget()
        self.output_tabs.setTabPosition(QTabWidget.North)
        
        # Create output tabs
        self.summary_tab = self.create_summary_tab()
        self.relay_tab = self.create_relay_tab()
        self.headers_tab = self.create_headers_tab()
        self.raw_tab = self.create_raw_tab()
        
        self.output_tabs.addTab(self.summary_tab, "📊 Summary")
        self.output_tabs.addTab(self.relay_tab, "🔄 Relay Chain")
        self.output_tabs.addTab(self.headers_tab, "📋 All Headers")
        self.output_tabs.addTab(self.raw_tab, "📝 Raw Results")
        
        splitter.addWidget(self.output_tabs)
        splitter.setSizes([300, 600])
        
        main_layout.addWidget(splitter)
        
        # Set initial status
        self.status_bar.showMessage("Ready to analyze email headers")
        
    def create_menu_bar(self):
        """Create application menu bar"""
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu("&File")
        
        open_eml_action = QAction("&Open EML File", self)
        open_eml_action.setShortcut("Ctrl+O")
        open_eml_action.triggered.connect(self.open_eml_file)
        file_menu.addAction(open_eml_action)
        
        open_msg_action = QAction("Open &MSG File", self)
        open_msg_action.setShortcut("Ctrl+M")
        open_msg_action.triggered.connect(self.open_msg_file)
        file_menu.addAction(open_msg_action)
        
        save_action = QAction("&Export Results", self)
        save_action.setShortcut("Ctrl+S")
        save_action.triggered.connect(self.export_results)
        file_menu.addAction(save_action)
        
        file_menu.addSeparator()
        
        exit_action = QAction("E&xit", self)
        exit_action.setShortcut("Ctrl+Q")
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # Edit menu
        edit_menu = menubar.addMenu("&Edit")
        
        clear_action = QAction("&Clear Input", self)
        clear_action.setShortcut("Ctrl+L")
        clear_action.triggered.connect(self.clear_input)
        edit_menu.addAction(clear_action)
        
        paste_action = QAction("&Paste from Clipboard", self)
        paste_action.setShortcut("Ctrl+V")
        paste_action.triggered.connect(self.paste_from_clipboard)
        edit_menu.addAction(paste_action)
        
        # Tools menu
        tools_menu = menubar.addMenu("&Tools")
        
        self.clipboard_monitor_action = QAction("&Clipboard Monitor", self)
        self.clipboard_monitor_action.setCheckable(True)
        self.clipboard_monitor_action.triggered.connect(self.toggle_clipboard_monitor)
        tools_menu.addAction(self.clipboard_monitor_action)
        
        settings_action = QAction("&Settings", self)
        settings_action.setShortcut("Ctrl+,")
        settings_action.triggered.connect(self.show_settings)
        tools_menu.addAction(settings_action)
        
        # View menu
        view_menu = menubar.addMenu("&View")
        
        self.dark_mode_action = QAction("&Dark Mode", self)
        self.dark_mode_action.setCheckable(True)
        self.dark_mode_action.setChecked(self.config.get("dark_mode", True))
        self.dark_mode_action.triggered.connect(self.toggle_theme)
        view_menu.addAction(self.dark_mode_action)
        
        # Help menu
        help_menu = menubar.addMenu("&Help")
        
        about_action = QAction("&About", self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)
        
    def create_toolbar(self):
        """Create application toolbar"""
        toolbar = QToolBar()
        toolbar.setMovable(False)
        self.addToolBar(toolbar)
        
        # Analyze button
        analyze_action = QAction("🔍 Analyze", self)
        analyze_action.triggered.connect(self.analyze_headers)
        toolbar.addAction(analyze_action)
        
        toolbar.addSeparator()
        
        # Open EML file button
        open_eml_action = QAction("📁 Open EML", self)
        open_eml_action.triggered.connect(self.open_eml_file)
        toolbar.addAction(open_eml_action)
        
        # Open MSG file button
        open_msg_action = QAction("📧 Open MSG", self)
        open_msg_action.triggered.connect(self.open_msg_file)
        toolbar.addAction(open_msg_action)
        
        # Export button
        export_action = QAction("💾 Export", self)
        export_action.triggered.connect(self.export_results)
        toolbar.addAction(export_action)
        
        toolbar.addSeparator()
        
        # Clear button
        clear_action = QAction("🗑️ Clear", self)
        clear_action.triggered.connect(self.clear_all)
        toolbar.addAction(clear_action)
        
    def create_input_section(self):
        """Create the input section widget"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Header
        header_layout = QHBoxLayout()
        header_label = QLabel("📧 Email Headers Input")
        header_label.setStyleSheet("font-size: 16px; font-weight: bold;")
        header_layout.addWidget(header_label)
        header_layout.addStretch()
        
        # Instructions button
        help_button = QPushButton("ℹ️ How to get headers")
        help_button.clicked.connect(self.show_header_instructions)
        header_layout.addWidget(help_button)
        
        layout.addLayout(header_layout)
        
        # Text input area
        self.input_text = QTextEdit()
        self.input_text.setPlaceholderText(
            "Paste email headers here or drag & drop an .eml/.msg file...\n\n"
            "Supported formats:\n"
            "• Complete email headers (copy from email client)\n"
            "• .eml files (drag & drop or use File → Open)\n"
            "• .msg files (Outlook format - drag & drop or use File → Open)\n"
            "• Raw email content\n\n"
            "For Outlook: File → Save As → Save as .msg file"
        )
        self.input_text.setAcceptDrops(True)
        self.input_text.dragEnterEvent = self.drag_enter_event
        self.input_text.dropEvent = self.drop_event
        layout.addWidget(self.input_text)
        
        # Button row
        button_layout = QHBoxLayout()
        
        self.analyze_button = QPushButton("🔍 Analyze Headers")
        self.analyze_button.clicked.connect(self.analyze_headers)
        self.analyze_button.setStyleSheet("""
            QPushButton {
                background-color: #ff9800;
                color: black;
                font-weight: bold;
                padding: 10px 20px;
                border-radius: 5px;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #ffa726;
            }
            QPushButton:pressed {
                background-color: #fb8c00;
            }
        """)
        button_layout.addWidget(self.analyze_button)
        
        button_layout.addStretch()
        
        clear_button = QPushButton("Clear")
        clear_button.clicked.connect(self.clear_input)
        button_layout.addWidget(clear_button)
        
        paste_button = QPushButton("Paste from Clipboard")
        paste_button.clicked.connect(self.paste_from_clipboard)
        button_layout.addWidget(paste_button)
        
        layout.addLayout(button_layout)
        
        return widget
    
    def create_summary_tab(self):
        """Create the summary results tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Authentication summary group
        auth_group = QGroupBox("🔐 Authentication Results")
        auth_layout = QVBoxLayout()
        
        self.auth_tree = QTreeWidget()
        self.auth_tree.setHeaderLabels(["Check", "Status", "Result"])
        self.auth_tree.setAlternatingRowColors(True)
        auth_layout.addWidget(self.auth_tree)
        
        auth_group.setLayout(auth_layout)
        layout.addWidget(auth_group)
        
        # IP Information group
        ip_group = QGroupBox("🌐 Sender IP Information")
        ip_layout = QVBoxLayout()
        
        self.ip_table = QTableWidget()
        self.ip_table.setColumnCount(2)
        self.ip_table.setHorizontalHeaderLabels(["Property", "Value"])
        self.ip_table.horizontalHeader().setStretchLastSection(True)
        self.ip_table.setAlternatingRowColors(True)
        ip_layout.addWidget(self.ip_table)
        
        ip_group.setLayout(ip_layout)
        layout.addWidget(ip_group)
        
        # DNS Records group
        dns_group = QGroupBox("📋 DNS Records")
        dns_layout = QVBoxLayout()
        
        self.dns_text = QTextEdit()
        self.dns_text.setReadOnly(True)
        self.dns_text.setMaximumHeight(150)
        dns_layout.addWidget(self.dns_text)
        
        dns_group.setLayout(dns_layout)
        layout.addWidget(dns_group)
        
        return widget
    
    def create_relay_tab(self):
        """Create the relay chain tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Relay chain table
        self.relay_table = QTableWidget()
        self.relay_table.setColumnCount(7)
        self.relay_table.setHorizontalHeaderLabels([
            "Hop", "Delay", "From", "By", "With", "Time", "Blacklist"
        ])
        
        # Set column resize modes for better display
        header = self.relay_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)  # Hop
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)  # Delay
        header.setSectionResizeMode(2, QHeaderView.Stretch)           # From (stretch)
        header.setSectionResizeMode(3, QHeaderView.Stretch)           # By (stretch)
        header.setSectionResizeMode(4, QHeaderView.ResizeToContents)  # With
        header.setSectionResizeMode(5, QHeaderView.ResizeToContents)  # Time
        header.setSectionResizeMode(6, QHeaderView.ResizeToContents)  # Blacklist
        
        # Enable text wrapping and set row height
        self.relay_table.setWordWrap(True)
        self.relay_table.setAlternatingRowColors(True)
        self.relay_table.setSelectionBehavior(QTableWidget.SelectRows)
        
        # Set minimum column widths
        self.relay_table.setColumnWidth(0, 50)   # Hop
        self.relay_table.setColumnWidth(1, 80)   # Delay
        self.relay_table.setColumnWidth(2, 300)  # From
        self.relay_table.setColumnWidth(3, 200)  # By
        self.relay_table.setColumnWidth(4, 100)  # With
        self.relay_table.setColumnWidth(5, 150)  # Time
        self.relay_table.setColumnWidth(6, 80)   # Blacklist
        
        layout.addWidget(self.relay_table)
        
        # Total delay label
        self.delay_label = QLabel("Total Delivery Time: N/A")
        self.delay_label.setStyleSheet("font-size: 14px; font-weight: bold; padding: 10px;")
        layout.addWidget(self.delay_label)
        
        return widget
    
    def create_headers_tab(self):
        """Create the all headers tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        self.headers_table = QTableWidget()
        self.headers_table.setColumnCount(2)
        self.headers_table.setHorizontalHeaderLabels(["Header", "Value"])
        self.headers_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.headers_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.headers_table.setAlternatingRowColors(True)
        layout.addWidget(self.headers_table)
        
        return widget
    
    def create_raw_tab(self):
        """Create the raw results tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        self.raw_text = QTextEdit()
        self.raw_text.setReadOnly(True)
        self.raw_text.setFont(QFont("Courier New", 10))
        layout.addWidget(self.raw_text)
        
        return widget
    
    def drag_enter_event(self, event: QDragEnterEvent):
        """Handle drag enter events"""
        if event.mimeData().hasUrls():
            for url in event.mimeData().urls():
                file_path = url.toLocalFile().lower()
                if file_path.endswith('.eml') or file_path.endswith('.msg'):
                    event.acceptProposedAction()
                    return
        event.ignore()
    
    def drop_event(self, event: QDropEvent):
        """Handle drop events"""
        files = [url.toLocalFile() for url in event.mimeData().urls()]
        for file in files:
            file_lower = file.lower()
            if file_lower.endswith('.eml'):
                self.load_eml_file(file)
                break
            elif file_lower.endswith('.msg'):
                self.load_msg_file(file)
                break
    
    def analyze_headers(self):
        """Analyze the email headers"""
        header_text = self.input_text.toPlainText().strip()
        
        if not header_text:
            QMessageBox.warning(self, "Warning", "Please enter email headers to analyze.")
            return
        
        # Disable UI during analysis
        self.analyze_button.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.status_bar.showMessage("Analyzing...")
        
        # Start analysis in background thread
        self.analysis_thread = AnalysisThread(header_text)
        self.analysis_thread.finished.connect(self.on_analysis_complete)
        self.analysis_thread.error.connect(self.on_analysis_error)
        self.analysis_thread.progress.connect(self.on_analysis_progress)
        self.analysis_thread.start()
    
    def on_analysis_progress(self, value: int, message: str):
        """Update progress during analysis"""
        self.progress_bar.setValue(value)
        self.status_bar.showMessage(message)
    
    def on_analysis_complete(self, result: EmailParseResult):
        """Handle analysis completion"""
        self.current_result = result
        
        # Fetch IP information if we have a sender IP
        if result.sender_ip:
            self.status_bar.showMessage("Fetching IP information...")
            ip_service = IPLookupService(api_key=self.config.get('ipinfo_api_key'))
            result.ip_info = ip_service.get_ip_info(result.sender_ip)
        
        self.display_results(result)
        
        # Re-enable UI
        self.analyze_button.setEnabled(True)
        self.progress_bar.setVisible(False)
        self.status_bar.showMessage("Analysis complete", 5000)
    
    def on_analysis_error(self, error_msg: str):
        """Handle analysis error"""
        QMessageBox.critical(self, "Analysis Error", f"Failed to analyze headers:\n{error_msg}")
        
        # Re-enable UI
        self.analyze_button.setEnabled(True)
        self.progress_bar.setVisible(False)
        self.status_bar.showMessage("Analysis failed", 5000)
    
    def display_results(self, result: EmailParseResult):
        """Display analysis results in the UI"""
        # Update summary tab
        self.update_auth_tree(result)
        self.update_ip_table(result)
        self.update_dns_text(result)
        
        # Update relay tab
        self.update_relay_table(result)
        
        # Update headers tab
        self.update_headers_table(result)
        
        # Update raw tab
        self.update_raw_text(result)
        
        # Switch to summary tab
        self.output_tabs.setCurrentIndex(0)
    
    def update_auth_tree(self, result: EmailParseResult):
        """Update authentication tree widget"""
        self.auth_tree.clear()
        
        # DMARC
        dmarc_item = QTreeWidgetItem(self.auth_tree)
        dmarc_item.setText(0, "DMARC Compliance")
        dmarc_item.setText(1, result.dmarc_status.upper())
        dmarc_item.setText(2, "✅ Pass" if result.dmarc_compliant else "❌ Fail")
        if result.dmarc_compliant:
            dmarc_item.setBackground(2, QColor(76, 175, 80, 50))
        else:
            dmarc_item.setBackground(2, QColor(244, 67, 54, 50))
        
        # SPF
        spf_align_item = QTreeWidgetItem(self.auth_tree)
        spf_align_item.setText(0, "SPF Alignment")
        spf_align_item.setText(1, "-")
        spf_align_item.setText(2, "✅ Aligned" if result.spf_aligned else "❌ Not Aligned")
        
        spf_auth_item = QTreeWidgetItem(self.auth_tree)
        spf_auth_item.setText(0, "SPF Authentication")
        spf_auth_item.setText(1, result.spf_status.upper())
        spf_auth_item.setText(2, "✅ Pass" if result.spf_authenticated else "❌ Fail")
        
        # DKIM
        dkim_align_item = QTreeWidgetItem(self.auth_tree)
        dkim_align_item.setText(0, "DKIM Alignment")
        dkim_align_item.setText(1, "-")
        dkim_align_item.setText(2, "✅ Aligned" if result.dkim_aligned else "❌ Not Aligned")
        
        dkim_auth_item = QTreeWidgetItem(self.auth_tree)
        dkim_auth_item.setText(0, "DKIM Authentication")
        dkim_auth_item.setText(1, result.dkim_status.upper())
        dkim_auth_item.setText(2, "✅ Pass" if result.dkim_authenticated else "❌ Fail")
        
        self.auth_tree.expandAll()
        
    def update_ip_table(self, result: EmailParseResult):
        """Update IP information table"""
        self.ip_table.setRowCount(0)
        
        if result.sender_ip and result.ip_info:
            items = [
                ("IP Address", result.sender_ip),
                ("Hostname", result.ip_info.get("hostname", "N/A")),
                ("City", result.ip_info.get("city", "N/A")),
                ("Region", result.ip_info.get("region", "N/A")),
                ("Country", result.ip_info.get("country", "N/A")),
                ("Organization", result.ip_info.get("org", "N/A")),
                ("Postal Code", result.ip_info.get("postal", "N/A")),
                ("Timezone", result.ip_info.get("timezone", "N/A"))
            ]
            
            for i, (key, value) in enumerate(items):
                if value and value != "N/A":
                    self.ip_table.insertRow(i)
                    self.ip_table.setItem(i, 0, QTableWidgetItem(key))
                    self.ip_table.setItem(i, 1, QTableWidgetItem(str(value)))
    
    def update_dns_text(self, result: EmailParseResult):
        """Update DNS records text"""
        dns_text = ""
        
        if result.dmarc_txt:
            dns_text += f"DMARC Record:\n{result.dmarc_txt}\n\n"
        
        if result.spf_txt:
            dns_text += f"SPF Record:\n{result.spf_txt}\n\n"
        
        if result.dkim_info:
            dns_text += f"DKIM Info:\n{result.dkim_info}"
        
        self.dns_text.setPlainText(dns_text)
    
    def update_relay_table(self, result: EmailParseResult):
        """Update relay chain table"""
        self.relay_table.setRowCount(len(result.relays))
        
        for i, relay in enumerate(result.relays):
            # Hop
            hop_item = QTableWidgetItem(str(relay['hop']))
            hop_item.setTextAlignment(Qt.AlignCenter)
            self.relay_table.setItem(i, 0, hop_item)
            
            # Delay
            delay_item = QTableWidgetItem(f"{relay['delay']:.2f}s")
            delay_item.setTextAlignment(Qt.AlignCenter)
            self.relay_table.setItem(i, 1, delay_item)
            
            # From - full text with tooltip
            from_item = QTableWidgetItem(relay['from'])
            from_item.setToolTip(relay['from'])  # Full text in tooltip
            self.relay_table.setItem(i, 2, from_item)
            
            # By - full text with tooltip
            by_item = QTableWidgetItem(relay['by'])
            by_item.setToolTip(relay['by'])  # Full text in tooltip
            self.relay_table.setItem(i, 3, by_item)
            
            # With
            with_item = QTableWidgetItem(relay['with'])
            with_item.setToolTip(relay['with'])
            self.relay_table.setItem(i, 4, with_item)
            
            # Time
            time_item = QTableWidgetItem(relay['time'])
            self.relay_table.setItem(i, 5, time_item)
            
            # Blacklist
            blacklist_item = QTableWidgetItem("✅" if relay['blacklist'] else "❌")
            blacklist_item.setTextAlignment(Qt.AlignCenter)
            self.relay_table.setItem(i, 6, blacklist_item)
        
        # Resize rows to content
        self.relay_table.resizeRowsToContents()
        
        self.delay_label.setText(f"Total Delivery Time: {result.total_delay:.3f} seconds ({result.delay_source})")
    
    def update_headers_table(self, result: EmailParseResult):
        """Update all headers table"""
        self.headers_table.setRowCount(len(result.headers))
        
        for i, (name, value) in enumerate(result.headers.items()):
            self.headers_table.setItem(i, 0, QTableWidgetItem(name))
            value_item = QTableWidgetItem(str(value)[:500])
            value_item.setToolTip(str(value))
            self.headers_table.setItem(i, 1, value_item)
    
    def update_raw_text(self, result: EmailParseResult):
        """Update raw results text"""
        raw_json = json.dumps(result.to_dict(), indent=2, default=str)
        self.raw_text.setPlainText(raw_json)
    
    def clear_input(self):
        """Clear input text"""
        self.input_text.clear()
    
    def clear_all(self):
        """Clear all data"""
        self.clear_input()
        self.auth_tree.clear()
        self.ip_table.setRowCount(0)
        self.dns_text.clear()
        self.relay_table.setRowCount(0)
        self.headers_table.setRowCount(0)
        self.raw_text.clear()
        self.delay_label.setText("Total Delivery Time: N/A")
        self.current_result = None
        self.status_bar.showMessage("Cleared all data", 3000)
    
    def paste_from_clipboard(self):
        """Paste text from clipboard"""
        clipboard = QApplication.clipboard()
        self.input_text.setPlainText(clipboard.text())
    
    def open_eml_file(self):
        """Open and load an EML file"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Open EML File", "", "Email Files (*.eml);;All Files (*.*)"
        )
        if file_path:
            self.load_eml_file(file_path)
    
    def open_msg_file(self):
        """Open and load an MSG file"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Open MSG File", "", "Outlook Message Files (*.msg);;All Files (*.*)"
        )
        if file_path:
            self.load_msg_file(file_path)
    
    def load_eml_file(self, file_path: str):
        """Load EML file content"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            self.input_text.setPlainText(content)
            self.status_bar.showMessage(f"Loaded: {os.path.basename(file_path)}", 5000)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load EML file:\n{str(e)}")
    
    def load_msg_file(self, file_path: str):
        """Load MSG file content"""
        try:
            # Try to import extract_msg for MSG support
            try:
                import extract_msg
                msg = extract_msg.Message(file_path)
                
                # Get headers from MSG file
                headers = []
                
                # Add standard headers
                if msg.sender:
                    headers.append(f"From: {msg.sender}")
                if msg.to:
                    headers.append(f"To: {msg.to}")
                if msg.cc:
                    headers.append(f"Cc: {msg.cc}")
                if msg.subject:
                    headers.append(f"Subject: {msg.subject}")
                if msg.date:
                    headers.append(f"Date: {msg.date}")
                if hasattr(msg, 'message_id') and msg.message_id:
                    headers.append(f"Message-ID: {msg.message_id}")
                
                # Get the email headers if available
                if hasattr(msg, 'header') and msg.header:
                    # Full headers are available
                    self.input_text.setPlainText(msg.header)
                else:
                    # Try to get transport headers
                    transport_headers = ""
                    if hasattr(msg, 'transport_message_headers'):
                        transport_headers = msg.transport_message_headers
                    elif hasattr(msg, '_properties') and 'transport_message_headers' in msg._properties:
                        transport_headers = msg._properties.get('transport_message_headers', '')
                    
                    if transport_headers:
                        self.input_text.setPlainText(transport_headers)
                    else:
                        # Fallback: use basic headers we collected
                        headers_text = '\n'.join(headers)
                        if headers_text:
                            self.input_text.setPlainText(headers_text)
                            QMessageBox.information(self, "Limited Headers", 
                                "This MSG file contains limited header information. " +
                                "For best results, use 'View Source' in Outlook to get full headers.")
                        else:
                            QMessageBox.warning(self, "No Headers Found", 
                                "Could not extract email headers from this MSG file.\n" +
                                "Try opening the email in Outlook and using File → Properties → Internet Headers.")
                
                msg.close()
                self.status_bar.showMessage(f"Loaded MSG: {os.path.basename(file_path)}", 5000)
                
            except ImportError:
                # extract_msg not installed, try alternative method
                self._load_msg_fallback(file_path)
                
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load MSG file:\n{str(e)}\n\n" +
                "Tip: You may need to install 'extract-msg' package:\n" +
                "pip install extract-msg")
    
    def _load_msg_fallback(self, file_path: str):
        """Fallback method to load MSG file without extract_msg"""
        try:
            # Try to read as binary and extract readable text
            with open(file_path, 'rb') as f:
                content = f.read()
            
            # Look for common header patterns in the binary data
            import re
            
            # Try to find headers in the binary content
            text_content = content.decode('utf-8', errors='ignore')
            
            # Look for email header patterns
            header_patterns = [
                r'From:.*?\n',
                r'To:.*?\n',
                r'Subject:.*?\n',
                r'Date:.*?\n',
                r'Message-ID:.*?\n',
                r'Received:.*?\n',
                r'Return-Path:.*?\n',
                r'Authentication-Results:.*?\n'
            ]
            
            found_headers = []
            for pattern in header_patterns:
                matches = re.findall(pattern, text_content, re.IGNORECASE | re.MULTILINE)
                found_headers.extend(matches)
            
            if found_headers:
                headers_text = ''.join(found_headers)
                self.input_text.setPlainText(headers_text)
                QMessageBox.information(self, "Partial Headers", 
                    "Extracted partial headers from MSG file.\n" +
                    "For complete headers, install 'extract-msg' package:\n" +
                    "pip install extract-msg")
            else:
                QMessageBox.warning(self, "MSG Support", 
                    "To open MSG files, please install the extract-msg package:\n\n" +
                    "pip install extract-msg\n\n" +
                    "Alternatively, open the email in Outlook and use:\n" +
                    "File → Properties → Internet Headers")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to read MSG file:\n{str(e)}")
    
    def export_results(self):
        """Export analysis results"""
        if not self.current_result:
            QMessageBox.warning(self, "Warning", "No results to export. Please analyze headers first.")
            return
        
        file_path, selected_filter = QFileDialog.getSaveFileName(
            self, "Export Results", f"email_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            "PDF Files (*.pdf);;JSON Files (*.json);;CSV Files (*.csv);;Text Files (*.txt)"
        )
        
        if file_path:
            try:
                if "pdf" in selected_filter.lower():
                    self.export_manager.export_to_pdf(self.current_result, file_path)
                elif "json" in selected_filter.lower():
                    self.export_manager.export_to_json(self.current_result, file_path)
                elif "csv" in selected_filter.lower():
                    self.export_manager.export_to_csv(self.current_result, file_path)
                else:
                    self.export_manager.export_to_text(self.current_result, file_path)
                
                QMessageBox.information(self, "Success", f"Results exported to:\n{file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Export Error", f"Failed to export:\n{str(e)}")
    
    def setup_clipboard_monitor(self):
        """Setup clipboard monitoring"""
        self.clipboard_timer = QTimer()
        self.clipboard_timer.timeout.connect(self.check_clipboard)
        self.last_clipboard_text = ""
    
    def toggle_clipboard_monitor(self):
        """Toggle clipboard monitoring on/off"""
        self.clipboard_monitor_enabled = self.clipboard_monitor_action.isChecked()
        
        if self.clipboard_monitor_enabled:
            self.clipboard_timer.start(1000)  # Check every second
            self.status_bar.showMessage("Clipboard monitor enabled", 3000)
        else:
            self.clipboard_timer.stop()
            self.status_bar.showMessage("Clipboard monitor disabled", 3000)
    
    def check_clipboard(self):
        """Check clipboard for email headers"""
        clipboard = QApplication.clipboard()
        text = clipboard.text()
        
        if text and text != self.last_clipboard_text:
            # Simple heuristic to detect email headers
            if any(header in text.lower() for header in ['received:', 'from:', 'to:', 'subject:', 'message-id:']):
                self.last_clipboard_text = text
                response = QMessageBox.question(
                    self, "Email Headers Detected",
                    "Email headers detected in clipboard. Import them?",
                    QMessageBox.Yes | QMessageBox.No
                )
                if response == QMessageBox.Yes:
                    self.input_text.setPlainText(text)
                    self.analyze_headers()
    
    def show_settings(self):
        """Show settings dialog"""
        # This would open a settings dialog - simplified for this example
        QMessageBox.information(self, "Settings", "Settings dialog would appear here.\nConfigure API keys, themes, etc.")
    
    def show_header_instructions(self):
        """Show instructions for getting email headers"""
        instructions = """
        <h3>How to Get Email Headers:</h3>
        <ul>
        <li><b>Gmail:</b> Open email → More (3 dots) → Show original</li>
        <li><b>Outlook:</b> Open email → File → Properties → Internet headers</li>
        <li><b>Yahoo:</b> Open email → More → View raw message</li>
        <li><b>Apple Mail:</b> View → Message → All Headers</li>
        </ul>
        <p>You can also drag & drop .eml files directly into the input area!</p>
        """
        QMessageBox.information(self, "Getting Email Headers", instructions)
    
    def show_about(self):
        """Show about dialog"""
        about_text = """
        <h2>Email Forensics Analyzer</h2>
        <p>Version 1.0.0</p>
        <p>A powerful desktop tool for analyzing email headers and authentication.</p>
        <p>Features:</p>
        <ul>
        <li>DMARC, SPF, DKIM authentication analysis</li>
        <li>Relay chain visualization</li>
        <li>IP geolocation lookup</li>
        <li>Blacklist checking</li>
        <li>Export to PDF, JSON, CSV</li>
        </ul>
        """
        QMessageBox.about(self, "About", about_text)
    
    def toggle_theme(self):
        """Toggle between dark and light themes"""
        self.config.set("dark_mode", self.dark_mode_action.isChecked())
        self.apply_theme()
    
    def apply_theme(self):
        """Apply the current theme"""
        app = QApplication.instance()
        if self.config.get("dark_mode", True):
            # Dark theme
            dark_palette = QPalette()
            dark_palette.setColor(QPalette.Window, QColor(30, 30, 30))
            dark_palette.setColor(QPalette.WindowText, Qt.white)
            dark_palette.setColor(QPalette.Base, QColor(45, 45, 45))
            dark_palette.setColor(QPalette.AlternateBase, QColor(60, 60, 60))
            dark_palette.setColor(QPalette.ToolTipBase, Qt.white)
            dark_palette.setColor(QPalette.ToolTipText, Qt.white)
            dark_palette.setColor(QPalette.Text, Qt.white)
            dark_palette.setColor(QPalette.Button, QColor(45, 45, 45))
            dark_palette.setColor(QPalette.ButtonText, Qt.white)
            dark_palette.setColor(QPalette.BrightText, Qt.red)
            dark_palette.setColor(QPalette.Link, QColor(255, 152, 0))
            dark_palette.setColor(QPalette.Highlight, QColor(255, 152, 0))
            dark_palette.setColor(QPalette.HighlightedText, Qt.black)
            app.setPalette(dark_palette)
        else:
            # Light theme
            app.setPalette(app.style().standardPalette())

def main():
    app = QApplication(sys.argv)
    app.setApplicationName("Email Forensics Analyzer")
    app.setOrganizationName("EmailForensics")
    app.setStyle(QStyleFactory.create("Fusion"))
    
    window = EmailForensicsApp()
    window.show()
    
    sys.exit(app.exec())

if __name__ == "__main__":
    main()