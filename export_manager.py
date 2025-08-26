"""
Export Manager Module
Handles exporting analysis results to various formats
"""

import json
import csv
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, Optional
import io

# Import reportlab components for PDF generation
try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
    from reportlab.pdfgen import canvas
    HAS_REPORTLAB = True
except ImportError:
    HAS_REPORTLAB = False
    print("Warning: reportlab not installed. PDF export will be disabled.")

class ExportManager:
    """Manages exporting analysis results to various formats"""
    
    def __init__(self):
        if HAS_REPORTLAB:
            self.styles = getSampleStyleSheet()
            self._setup_custom_styles()
    
    def _setup_custom_styles(self):
        """Setup custom PDF styles"""
        # Title style - check if already exists
        if 'CustomTitle' not in self.styles:
            self.styles.add(ParagraphStyle(
                name='CustomTitle',
                parent=self.styles['Title'],
                fontSize=24,
                textColor=colors.HexColor('#ff9800'),
                alignment=TA_CENTER,
                spaceAfter=30
            ))
        
        # Heading style
        if 'CustomHeading' not in self.styles:
            self.styles.add(ParagraphStyle(
                name='CustomHeading',
                parent=self.styles['Heading1'],
                fontSize=16,
                textColor=colors.HexColor('#333333'),
                spaceAfter=12,
                spaceBefore=12
            ))
        
        # Subheading style
        if 'CustomSubHeading' not in self.styles:
            self.styles.add(ParagraphStyle(
                name='CustomSubHeading',
                parent=self.styles['Heading2'],
                fontSize=14,
                textColor=colors.HexColor('#555555'),
                spaceAfter=8,
                spaceBefore=8
            ))
        
        # Success style
        if 'Success' not in self.styles:
            self.styles.add(ParagraphStyle(
                name='Success',
                parent=self.styles['Normal'],
                textColor=colors.HexColor('#4caf50'),
                fontSize=11
            ))
        
        # Error style
        if 'Error' not in self.styles:
            self.styles.add(ParagraphStyle(
                name='Error',
                parent=self.styles['Normal'],
                textColor=colors.HexColor('#f44336'),
                fontSize=11
            ))
        
        # Code style - check if already exists before adding
        if 'CustomCode' not in self.styles:
            self.styles.add(ParagraphStyle(
                name='CustomCode',
                parent=self.styles['Normal'],
                fontName='Courier',
                fontSize=9,
                leftIndent=20,
                rightIndent=20,
                backColor=colors.HexColor('#f5f5f5')
            ))
    
    def export_to_pdf(self, result, file_path: str):
        """Export analysis results to PDF"""
        if not HAS_REPORTLAB:
            raise ImportError("reportlab is required for PDF export. Install with: pip install reportlab")
        
        doc = SimpleDocTemplate(
            file_path,
            pagesize=letter,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=18
        )
        
        # Container for the 'Flowable' objects
        elements = []
        
        # Title
        elements.append(Paragraph("Email Forensics Analysis Report", self.styles['CustomTitle']))
        elements.append(Spacer(1, 12))
        
        # Report metadata
        elements.append(Paragraph(f"<b>Generated:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", 
                                self.styles['Normal']))
        if result.from_domain:
            elements.append(Paragraph(f"<b>From Domain:</b> {result.from_domain}", 
                                    self.styles['Normal']))
        if result.sender_ip:
            elements.append(Paragraph(f"<b>Sender IP:</b> {result.sender_ip}", 
                                    self.styles['Normal']))
        elements.append(Spacer(1, 20))
        
        # Authentication Summary
        elements.append(Paragraph("Authentication Summary", self.styles['CustomHeading']))
        
        auth_data = [
            ['Check', 'Status', 'Result'],
            ['DMARC Compliance', result.dmarc_status.upper(), 
             '✓ Pass' if result.dmarc_compliant else '✗ Fail'],
            ['SPF Alignment', '-', 
             '✓ Aligned' if result.spf_aligned else '✗ Not Aligned'],
            ['SPF Authentication', result.spf_status.upper(), 
             '✓ Pass' if result.spf_authenticated else '✗ Fail'],
            ['DKIM Alignment', '-', 
             '✓ Aligned' if result.dkim_aligned else '✗ Not Aligned'],
            ['DKIM Authentication', result.dkim_status.upper(), 
             '✓ Pass' if result.dkim_authenticated else '✗ Fail']
        ]
        
        auth_table = Table(auth_data, colWidths=[2.5*inch, 1.5*inch, 1.5*inch])
        
        # Base table style
        table_style = [
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#ff9800')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f9f9f9')),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]
        
        # Color code the results
        for i in range(1, len(auth_data)):
            if 'Pass' in auth_data[i][2] or 'Aligned' in auth_data[i][2]:
                table_style.append(('TEXTCOLOR', (2, i), (2, i), colors.green))
            else:
                table_style.append(('TEXTCOLOR', (2, i), (2, i), colors.red))
        
        auth_table.setStyle(TableStyle(table_style))
        elements.append(auth_table)
        elements.append(Spacer(1, 20))
        
        # Sender IP Information
        if result.sender_ip:
            elements.append(Paragraph("Sender IP Information", self.styles['CustomHeading']))
            
            ip_data = [['Property', 'Value']]
            ip_data.append(['IP Address', result.sender_ip])
            
            if result.ip_info and 'error' not in result.ip_info:
                for key in ['hostname', 'city', 'region', 'country', 'org', 'postal', 'timezone']:
                    if key in result.ip_info and result.ip_info[key]:
                        ip_data.append([key.title(), str(result.ip_info[key])])
            
            ip_table = Table(ip_data, colWidths=[2*inch, 3.5*inch])
            ip_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 11),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f9f9f9')),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            
            elements.append(ip_table)
            elements.append(Spacer(1, 20))
        
        # Relay Chain
        elements.append(Paragraph("Email Relay Chain", self.styles['CustomHeading']))
        elements.append(Paragraph(f"<b>Total Delivery Time:</b> {result.total_delay:.3f} seconds ({result.delay_source})", 
                                self.styles['Normal']))
        elements.append(Spacer(1, 10))
        
        if result.relays:
            relay_data = [['Hop', 'Delay', 'From', 'Time']]
            for relay in result.relays[:15]:  # Limit to first 15 relays for PDF
                # Use Paragraph for 'from' to enable wrapping
                from_paragraph = Paragraph(relay['from'], self.styles['Normal'])
                relay_data.append([
                    str(relay['hop']),
                    f"{relay['delay']:.2f}s",
                    from_paragraph,
                    relay['time']
                ])
            # Adjust column widths: give more space to 'From'
            relay_table = Table(relay_data, colWidths=[0.7*inch, 0.8*inch, 3.5*inch, 1.5*inch])
            relay_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (1, -1), 'CENTER'),
                ('ALIGN', (2, 0), (2, -1), 'LEFT'),
                ('ALIGN', (3, 0), (3, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f9f9f9')),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f0f0f0')])
            ]))
            elements.append(relay_table)
            if len(result.relays) > 15:
                elements.append(Spacer(1, 5))
                elements.append(Paragraph(f"<i>... and {len(result.relays) - 15} more relay hops</i>", self.styles['Normal']))
        
        # DNS Records (on new page if they exist)
        if result.dmarc_txt or result.spf_txt or result.dkim_info:
            elements.append(PageBreak())
            elements.append(Paragraph("DNS Authentication Records", self.styles['CustomHeading']))
            
            if result.dmarc_txt:
                elements.append(Paragraph("DMARC Record:", self.styles['CustomSubHeading']))
                # Break long DNS records into manageable chunks
                dmarc_text = self._wrap_long_text(result.dmarc_txt, 80)
                elements.append(Paragraph(dmarc_text, self.styles['CustomCode']))
                elements.append(Spacer(1, 15))
            
            if result.spf_txt:
                elements.append(Paragraph("SPF Record:", self.styles['CustomSubHeading']))
                spf_text = self._wrap_long_text(result.spf_txt, 80)
                elements.append(Paragraph(spf_text, self.styles['CustomCode']))
                elements.append(Spacer(1, 15))
            
            if result.dkim_info and result.dkim_info != "No DKIM-Signature found":
                elements.append(Paragraph("DKIM Information:", self.styles['CustomSubHeading']))
                dkim_text = self._wrap_long_text(result.dkim_info, 80)
                elements.append(Paragraph(dkim_text, self.styles['CustomCode']))
        
        # Summary and Recommendations
        elements.append(PageBreak())
        elements.append(Paragraph("Analysis Summary", self.styles['CustomHeading']))
        
        summary_points = []
        
        # Check overall authentication status
        if result.dmarc_compliant and result.spf_authenticated and result.dkim_authenticated:
            summary_points.append("✓ All authentication checks passed successfully")
        else:
            if not result.dmarc_compliant:
                summary_points.append("✗ DMARC compliance failed - email may be spoofed")
            if not result.spf_authenticated:
                summary_points.append("✗ SPF authentication failed - sender server not authorized")
            if not result.dkim_authenticated:
                summary_points.append("✗ DKIM authentication failed - message may be modified")
        
        # Add delivery time assessment
        if result.total_delay < 10:
            summary_points.append(f"✓ Fast delivery time: {result.total_delay:.2f} seconds")
        elif result.total_delay < 60:
            summary_points.append(f"• Normal delivery time: {result.total_delay:.2f} seconds")
        else:
            summary_points.append(f"⚠ Slow delivery time: {result.total_delay:.2f} seconds")
        
        # Add relay chain assessment
        if len(result.relays) < 5:
            summary_points.append(f"✓ Direct routing with {len(result.relays)} hops")
        elif len(result.relays) < 10:
            summary_points.append(f"• Standard routing with {len(result.relays)} hops")
        else:
            summary_points.append(f"⚠ Complex routing with {len(result.relays)} hops")
        
        for point in summary_points:
            elements.append(Paragraph(f"• {point}", self.styles['Normal']))
            elements.append(Spacer(1, 5))
        
        # Footer
        elements.append(Spacer(1, 30))
        elements.append(Paragraph("<i>Generated by Email Forensics Analyzer Desktop v1.0</i>", 
                                self.styles['Normal']))
        
        # Build PDF
        doc.build(elements)
    
    def _wrap_long_text(self, text: str, max_length: int = 80) -> str:
        """Wrap long text for better display in PDF"""
        if len(text) <= max_length:
            return text
        
        words = text.split()
        lines = []
        current_line = []
        current_length = 0
        
        for word in words:
            word_length = len(word) + 1  # +1 for space
            if current_length + word_length <= max_length:
                current_line.append(word)
                current_length += word_length
            else:
                if current_line:
                    lines.append(' '.join(current_line))
                current_line = [word]
                current_length = word_length
        
        if current_line:
            lines.append(' '.join(current_line))
        
        return '<br/>'.join(lines)
    
    def export_to_json(self, result, file_path: str):
        """Export analysis results to JSON"""
        data = result.to_dict()
        data['export_metadata'] = {
            'timestamp': datetime.now().isoformat(),
            'version': '1.0',
            'format': 'json'
        }
        
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, default=str, ensure_ascii=False)
    
    def export_to_csv(self, result, file_path: str):
        """Export analysis results to CSV"""
        with open(file_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            
            # Metadata section
            writer.writerow(['Email Forensics Analysis Report'])
            writer.writerow(['Generated', datetime.now().strftime('%Y-%m-%d %H:%M:%S')])
            writer.writerow([])
            
            # Authentication results
            writer.writerow(['=== Authentication Results ==='])
            writer.writerow(['Check', 'Status', 'Result'])
            writer.writerow(['DMARC Compliance', result.dmarc_status.upper(), 
                           'Pass' if result.dmarc_compliant else 'Fail'])
            writer.writerow(['SPF Alignment', '-', 
                           'Aligned' if result.spf_aligned else 'Not Aligned'])
            writer.writerow(['SPF Authentication', result.spf_status.upper(), 
                           'Pass' if result.spf_authenticated else 'Fail'])
            writer.writerow(['DKIM Alignment', '-', 
                           'Aligned' if result.dkim_aligned else 'Not Aligned'])
            writer.writerow(['DKIM Authentication', result.dkim_status.upper(), 
                           'Pass' if result.dkim_authenticated else 'Fail'])
            writer.writerow([])
            
            # Domain information
            writer.writerow(['=== Domain Information ==='])
            writer.writerow(['From Domain', result.from_domain])
            writer.writerow(['Return Path Domain', result.return_path_domain])
            writer.writerow([])
            
            # IP Information
            if result.sender_ip:
                writer.writerow(['=== Sender IP Information ==='])
                writer.writerow(['IP Address', result.sender_ip])
                if result.ip_info and 'error' not in result.ip_info:
                    for key, value in result.ip_info.items():
                        if key != 'ip' and value:
                            writer.writerow([key.title(), value])
                writer.writerow([])
            
            # Relay Chain
            writer.writerow(['=== Relay Chain ==='])
            writer.writerow(['Total Delivery Time (seconds)', f"{result.total_delay:.3f}"])
            writer.writerow(['Delay Source', result.delay_source])
            writer.writerow([])
            writer.writerow(['Hop', 'Delay (s)', 'From', 'By', 'With', 'Time', 'IP'])
            for relay in result.relays:
                writer.writerow([
                    relay['hop'],
                    f"{relay['delay']:.2f}",
                    relay['from'],
                    relay['by'],
                    relay['with'],
                    relay['time'],
                    relay.get('ip', '')
                ])
            writer.writerow([])
            
            # DNS Records
            if result.dmarc_txt or result.spf_txt:
                writer.writerow(['=== DNS Records ==='])
                if result.dmarc_txt:
                    writer.writerow(['DMARC', result.dmarc_txt])
                if result.spf_txt:
                    writer.writerow(['SPF', result.spf_txt])
                if result.dkim_info:
                    writer.writerow(['DKIM', result.dkim_info[:500]])  # Truncate long DKIM
                writer.writerow([])
            
            # Headers (limited selection for CSV)
            writer.writerow(['=== Key Headers ==='])
            important_headers = ['From', 'To', 'Subject', 'Date', 'Message-ID', 
                               'Return-Path', 'Authentication-Results']
            for header in important_headers:
                if header in result.headers:
                    value = str(result.headers[header])[:500]  # Truncate very long values
                    writer.writerow([header, value])
    
    def export_to_text(self, result, file_path: str):
        """Export analysis results to text file"""
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write(" " * 20 + "EMAIL FORENSICS ANALYSIS REPORT\n")
            f.write("=" * 80 + "\n\n")
            
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Analysis Version: 1.0\n\n")
            
            # Authentication Summary
            f.write("AUTHENTICATION SUMMARY\n")
            f.write("-" * 40 + "\n")
            f.write(f"{'DMARC Compliance:':<25} {result.dmarc_status.upper():<10} ")
            f.write("PASS\n" if result.dmarc_compliant else "FAIL\n")
            f.write(f"{'SPF Alignment:':<25} {'N/A':<10} ")
            f.write("ALIGNED\n" if result.spf_aligned else "NOT ALIGNED\n")
            f.write(f"{'SPF Authentication:':<25} {result.spf_status.upper():<10} ")
            f.write("PASS\n" if result.spf_authenticated else "FAIL\n")
            f.write(f"{'DKIM Alignment:':<25} {'N/A':<10} ")
            f.write("ALIGNED\n" if result.dkim_aligned else "NOT ALIGNED\n")
            f.write(f"{'DKIM Authentication:':<25} {result.dkim_status.upper():<10} ")
            f.write("PASS\n" if result.dkim_authenticated else "FAIL\n")
            f.write("\n")
            
            # Domain Information
            f.write("DOMAIN INFORMATION\n")
            f.write("-" * 40 + "\n")
            f.write(f"From Domain: {result.from_domain}\n")
            f.write(f"Return Path Domain: {result.return_path_domain}\n")
            f.write("\n")
            
            # Sender IP
            if result.sender_ip:
                f.write("SENDER IP INFORMATION\n")
                f.write("-" * 40 + "\n")
                f.write(f"IP Address: {result.sender_ip}\n")
                if result.ip_info and 'error' not in result.ip_info:
                    for key, value in result.ip_info.items():
                        if key != 'ip' and value:
                            f.write(f"{key.title():<15} {value}\n")
                f.write("\n")
            
            # Relay Chain
            f.write("RELAY CHAIN ANALYSIS\n")
            f.write("-" * 40 + "\n")
            f.write(f"Total Delivery Time: {result.total_delay:.3f} seconds\n")
            f.write(f"Delay Source: {result.delay_source}\n")
            f.write(f"Number of Hops: {len(result.relays)}\n\n")
            
            f.write("Detailed Relay Information:\n")
            for relay in result.relays:
                f.write(f"\nHop {relay['hop']}:\n")
                f.write(f"  Delay: {relay['delay']:.2f} seconds\n")
                f.write(f"  From: {relay['from']}\n")
                if relay['by']:
                    f.write(f"  By: {relay['by']}\n")
                if relay['with']:
                    f.write(f"  Protocol: {relay['with']}\n")
                if relay['time']:
                    f.write(f"  Time: {relay['time']}\n")
                if relay.get('ip'):
                    f.write(f"  IP: {relay['ip']}\n")
            f.write("\n")
            
            # DNS Records
            if result.dmarc_txt or result.spf_txt or result.dkim_info:
                f.write("DNS AUTHENTICATION RECORDS\n")
                f.write("-" * 40 + "\n")
                
                if result.dmarc_txt:
                    f.write("DMARC Record:\n")
                    f.write(f"  {result.dmarc_txt}\n\n")
                
                if result.spf_txt:
                    f.write("SPF Record:\n")
                    f.write(f"  {result.spf_txt}\n\n")
                
                if result.dkim_info and result.dkim_info != "No DKIM-Signature found":
                    f.write("DKIM Information:\n")
                    f.write(f"  {result.dkim_info}\n\n")
            
            # Selected Headers
            f.write("KEY EMAIL HEADERS\n")
            f.write("-" * 40 + "\n")
            important_headers = ['From', 'To', 'Subject', 'Date', 'Message-ID', 
                               'Return-Path', 'Reply-To', 'X-Originating-IP',
                               'X-Mailer', 'User-Agent', 'Authentication-Results']
            
            for header_name in important_headers:
                if header_name in result.headers:
                    value = str(result.headers[header_name])
                    if len(value) > 200:
                        value = value[:200] + "..."
                    f.write(f"{header_name}: {value}\n")
            
            f.write("\n")
            f.write("=" * 80 + "\n")
            f.write("End of Report\n")
    
    def export_to_html(self, result, file_path: str):
        """Export analysis results to HTML"""
        
        # Determine authentication status colors
        def get_status_class(passed: bool) -> str:
            return "pass" if passed else "fail"
        
        html = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Email Forensics Report - """ + datetime.now().strftime('%Y-%m-%d') + """</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        .container { 
            max-width: 1200px; 
            margin: 0 auto; 
            background: white; 
            border-radius: 12px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }
        .header {
            background: linear-gradient(135deg, #ff9800 0%, #ff6b00 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }
        h1 { 
            font-size: 2.5em;
            margin-bottom: 10px;
            font-weight: 700;
        }
        .metadata {
            font-size: 0.9em;
            opacity: 0.9;
        }
        .content {
            padding: 40px;
        }
        h2 { 
            color: #ff9800;
            margin: 30px 0 20px 0;
            padding-bottom: 10px;
            border-bottom: 2px solid #ff9800;
            font-size: 1.8em;
        }
        h3 {
            color: #555;
            margin: 20px 0 10px 0;
            font-size: 1.3em;
        }
        table { 
            width: 100%; 
            border-collapse: collapse; 
            margin: 20px 0;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            border-radius: 8px;
            overflow: hidden;
        }
        th { 
            background: #ff9800; 
            color: white; 
            padding: 12px; 
            text-align: left;
            font-weight: 600;
        }
        td { 
            padding: 10px; 
            border-bottom: 1px solid #e0e0e0;
        }
        tr:nth-child(even) { 
            background: #f9f9f9; 
        }
        tr:hover {
            background: #f0f0f0;
        }
        .pass { 
            color: #4caf50; 
            font-weight: bold;
        }
        .fail { 
            color: #f44336; 
            font-weight: bold;
        }
        .dns-record { 
            background: #f5f5f5; 
            padding: 15px; 
            margin: 15px 0; 
            border-radius: 8px; 
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            border-left: 4px solid #ff9800;
            overflow-x: auto;
        }
        .summary-box {
            background: linear-gradient(135deg, #e3f2fd 0%, #bbdefb 100%);
            border-radius: 8px;
            padding: 20px;
            margin: 20px 0;
        }
        .summary-item {
            margin: 10px 0;
            padding-left: 25px;
            position: relative;
        }
        .summary-item:before {
            content: '•';
            position: absolute;
            left: 0;
            color: #ff9800;
            font-size: 1.2em;
        }
        .footer {
            background: #f5f5f5;
            padding: 20px;
            text-align: center;
            color: #666;
            font-size: 0.9em;
        }
        .badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.85em;
            font-weight: bold;
            margin-left: 10px;
        }
        .badge-success {
            background: #4caf50;
            color: white;
        }
        .badge-error {
            background: #f44336;
            color: white;
        }
        .badge-warning {
            background: #ff9800;
            color: white;
        }
        @media print {
            body { background: white; }
            .container { box-shadow: none; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>📧 Email Forensics Analysis Report</h1>
            <div class="metadata">Generated: """ + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + """</div>
        </div>
        
        <div class="content">
            <h2>🔐 Authentication Summary</h2>
            <table>
                <tr>
                    <th>Check</th>
                    <th>Status</th>
                    <th>Result</th>
                </tr>"""
        
        # Add authentication rows
        auth_checks = [
            ('DMARC Compliance', result.dmarc_status.upper(), result.dmarc_compliant),
            ('SPF Alignment', 'N/A', result.spf_aligned),
            ('SPF Authentication', result.spf_status.upper(), result.spf_authenticated),
            ('DKIM Alignment', 'N/A', result.dkim_aligned),
            ('DKIM Authentication', result.dkim_status.upper(), result.dkim_authenticated)
        ]
        
        for check, status, passed in auth_checks:
            result_text = '✅ Pass' if passed else '❌ Fail'
            result_class = 'pass' if passed else 'fail'
            html += f"""
                <tr>
                    <td>{check}</td>
                    <td>{status}</td>
                    <td class="{result_class}">{result_text}</td>
                </tr>"""
        
        html += """
            </table>
            
            <h2>🌍 Sender Information</h2>"""
        
        # Add sender information
        if result.sender_ip:
            html += f"""
            <h3>IP Address: {result.sender_ip}</h3>
            <table>
                <tr>
                    <th>Property</th>
                    <th>Value</th>
                </tr>"""
            
            if result.ip_info and 'error' not in result.ip_info:
                ip_properties = [
                    ('Hostname', result.ip_info.get('hostname', 'N/A')),
                    ('City', result.ip_info.get('city', 'N/A')),
                    ('Region', result.ip_info.get('region', 'N/A')),
                    ('Country', result.ip_info.get('country', 'N/A')),
                    ('Organization', result.ip_info.get('org', 'N/A')),
                    ('Postal Code', result.ip_info.get('postal', 'N/A')),
                    ('Timezone', result.ip_info.get('timezone', 'N/A'))
                ]
                
                for prop, value in ip_properties:
                    if value and value != 'N/A':
                        html += f"""
                <tr>
                    <td>{prop}</td>
                    <td>{value}</td>
                </tr>"""
            
            html += """
            </table>"""
        
        # Add relay chain
        html += f"""
            
            <h2>📨 Email Relay Chain</h2>
            <p><strong>Total Delivery Time:</strong> {result.total_delay:.3f} seconds 
               <span class="badge badge-warning">{result.delay_source}</span></p>
            <p><strong>Number of Hops:</strong> {len(result.relays)}</p>"""
        
        if result.relays:
            html += """
            <table>
                <tr>
                    <th>Hop</th>
                    <th>Delay</th>
                    <th>From</th>
                    <th>By</th>
                    <th>Time</th>
                </tr>"""
            
            for relay in result.relays[:20]:  # Limit to 20 relays for HTML
                from_text = relay['from'][:50] + '...' if len(relay['from']) > 50 else relay['from']
                by_text = relay['by'][:30] + '...' if len(relay['by']) > 30 else relay['by']
                
                html += f"""
                <tr>
                    <td>{relay['hop']}</td>
                    <td>{relay['delay']:.2f}s</td>
                    <td title="{relay['from']}">{from_text}</td>
                    <td title="{relay['by']}">{by_text}</td>
                    <td>{relay['time']}</td>
                </tr>"""
            
            html += """
            </table>"""
            
            if len(result.relays) > 20:
                html += f"""
            <p><em>... and {len(result.relays) - 20} more relay hops not shown</em></p>"""
        
        # Add DNS records
        if result.dmarc_txt or result.spf_txt or result.dkim_info:
            html += """
            
            <h2>🔍 DNS Authentication Records</h2>"""
            
            if result.dmarc_txt:
                html += f"""
            <h3>DMARC Record</h3>
            <div class="dns-record">{self._html_escape(result.dmarc_txt)}</div>"""
            
            if result.spf_txt:
                html += f"""
            <h3>SPF Record</h3>
            <div class="dns-record">{self._html_escape(result.spf_txt)}</div>"""
            
            if result.dkim_info and result.dkim_info != "No DKIM-Signature found":
                dkim_display = result.dkim_info[:500] + '...' if len(result.dkim_info) > 500 else result.dkim_info
                html += f"""
            <h3>DKIM Information</h3>
            <div class="dns-record">{self._html_escape(dkim_display)}</div>"""
        
        # Add analysis summary
        html += """
            
            <h2>📊 Analysis Summary</h2>
            <div class="summary-box">"""
        
        # Generate summary points
        if result.dmarc_compliant and result.spf_authenticated and result.dkim_authenticated:
            html += """
                <div class="summary-item">
                    <strong style="color: #4caf50;">✅ All authentication checks passed successfully</strong>
                </div>"""
        else:
            if not result.dmarc_compliant:
                html += """
                <div class="summary-item">
                    <strong style="color: #f44336;">⚠️ DMARC compliance failed - email may be spoofed</strong>
                </div>"""
            if not result.spf_authenticated:
                html += """
                <div class="summary-item">
                    <strong style="color: #f44336;">⚠️ SPF authentication failed - sender server not authorized</strong>
                </div>"""
            if not result.dkim_authenticated:
                html += """
                <div class="summary-item">
                    <strong style="color: #f44336;">⚠️ DKIM authentication failed - message may be modified</strong>
                </div>"""
        
        # Delivery time assessment
        if result.total_delay < 10:
            html += f"""
                <div class="summary-item">
                    <strong style="color: #4caf50;">✅ Fast delivery: {result.total_delay:.2f} seconds</strong>
                </div>"""
        elif result.total_delay < 60:
            html += f"""
                <div class="summary-item">
                    <strong>⏱️ Normal delivery: {result.total_delay:.2f} seconds</strong>
                </div>"""
        else:
            html += f"""
                <div class="summary-item">
                    <strong style="color: #ff9800;">⚠️ Slow delivery: {result.total_delay:.2f} seconds</strong>
                </div>"""
        
        # Routing assessment
        if len(result.relays) < 5:
            html += f"""
                <div class="summary-item">
                    <strong style="color: #4caf50;">✅ Direct routing with {len(result.relays)} hops</strong>
                </div>"""
        elif len(result.relays) < 10:
            html += f"""
                <div class="summary-item">
                    <strong>📍 Standard routing with {len(result.relays)} hops</strong>
                </div>"""
        else:
            html += f"""
                <div class="summary-item">
                    <strong style="color: #ff9800;">⚠️ Complex routing with {len(result.relays)} hops</strong>
                </div>"""
        
        html += """
            </div>
            
            <h2>📋 Key Headers</h2>
            <table>
                <tr>
                    <th style="width: 25%;">Header</th>
                    <th>Value</th>
                </tr>"""
        
        # Add important headers
        important_headers = [
            'From', 'To', 'Subject', 'Date', 'Message-ID',
            'Return-Path', 'Reply-To', 'X-Originating-IP',
            'X-Mailer', 'User-Agent'
        ]
        
        for header in important_headers:
            if header in result.headers:
                value = str(result.headers[header])
                if len(value) > 200:
                    value = value[:200] + '...'
                value = self._html_escape(value)
                html += f"""
                <tr>
                    <td><strong>{header}</strong></td>
                    <td>{value}</td>
                </tr>"""
        
        html += """
            </table>
        </div>
        
        <div class="footer">
            <p>Generated by Email Forensics Analyzer Desktop v1.0</p>
            <p>Report created on """ + datetime.now().strftime('%B %d, %Y at %I:%M %p') + """</p>
        </div>
    </div>
</body>
</html>"""
        
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(html)
    
    def _html_escape(self, text: str) -> str:
        """Escape HTML special characters"""
        if not text:
            return ""
        
        escape_chars = {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#39;'
        }
        
        for char, escape in escape_chars.items():
            text = text.replace(char, escape)
        
        return text
    
    def export_to_markdown(self, result, file_path: str):
        """Export analysis results to Markdown format"""
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write("# Email Forensics Analysis Report\n\n")
            f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            # Table of Contents
            f.write("## Table of Contents\n\n")
            f.write("1. [Authentication Summary](#authentication-summary)\n")
            f.write("2. [Sender Information](#sender-information)\n")
            f.write("3. [Relay Chain](#relay-chain)\n")
            f.write("4. [DNS Records](#dns-records)\n")
            f.write("5. [Analysis Summary](#analysis-summary)\n\n")
            
            # Authentication Summary
            f.write("## Authentication Summary\n\n")
            f.write("| Check | Status | Result |\n")
            f.write("|-------|--------|--------|\n")
            
            auth_checks = [
                ('DMARC Compliance', result.dmarc_status.upper(), '✅ Pass' if result.dmarc_compliant else '❌ Fail'),
                ('SPF Alignment', 'N/A', '✅ Aligned' if result.spf_aligned else '❌ Not Aligned'),
                ('SPF Authentication', result.spf_status.upper(), '✅ Pass' if result.spf_authenticated else '❌ Fail'),
                ('DKIM Alignment', 'N/A', '✅ Aligned' if result.dkim_aligned else '❌ Not Aligned'),
                ('DKIM Authentication', result.dkim_status.upper(), '✅ Pass' if result.dkim_authenticated else '❌ Fail')
            ]
            
            for check, status, result_text in auth_checks:
                f.write(f"| {check} | {status} | {result_text} |\n")
            
            f.write("\n")
            
            # Sender Information
            if result.sender_ip:
                f.write("## Sender Information\n\n")
                f.write(f"**IP Address:** `{result.sender_ip}`\n\n")
                
                if result.ip_info and 'error' not in result.ip_info:
                    f.write("| Property | Value |\n")
                    f.write("|----------|-------|\n")
                    
                    for key in ['hostname', 'city', 'region', 'country', 'org', 'postal', 'timezone']:
                        if key in result.ip_info and result.ip_info[key]:
                            f.write(f"| {key.title()} | {result.ip_info[key]} |\n")
                    
                    f.write("\n")
            
            # Relay Chain
            f.write("## Relay Chain\n\n")
            f.write(f"**Total Delivery Time:** {result.total_delay:.3f} seconds\n")
            f.write(f"**Delay Source:** {result.delay_source}\n")
            f.write(f"**Number of Hops:** {len(result.relays)}\n\n")
            
            if result.relays:
                f.write("| Hop | Delay | From | Time |\n")
                f.write("|-----|-------|------|------|\n")
                
                for relay in result.relays[:15]:
                    from_text = relay['from'][:40] + '...' if len(relay['from']) > 40 else relay['from']
                    f.write(f"| {relay['hop']} | {relay['delay']:.2f}s | {from_text} | {relay['time']} |\n")
                
                if len(result.relays) > 15:
                    f.write(f"\n*... and {len(result.relays) - 15} more relay hops*\n")
                
                f.write("\n")
            
            # DNS Records
            if result.dmarc_txt or result.spf_txt or result.dkim_info:
                f.write("## DNS Records\n\n")
                
                if result.dmarc_txt:
                    f.write("### DMARC Record\n\n")
                    f.write(f"```\n{result.dmarc_txt}\n```\n\n")
                
                if result.spf_txt:
                    f.write("### SPF Record\n\n")
                    f.write(f"```\n{result.spf_txt}\n```\n\n")
                
                if result.dkim_info and result.dkim_info != "No DKIM-Signature found":
                    f.write("### DKIM Information\n\n")
                    dkim_display = result.dkim_info[:500] + '...' if len(result.dkim_info) > 500 else result.dkim_info
                    f.write(f"```\n{dkim_display}\n```\n\n")
            
            # Analysis Summary
            f.write("## Analysis Summary\n\n")
            
            if result.dmarc_compliant and result.spf_authenticated and result.dkim_authenticated:
                f.write("- ✅ **All authentication checks passed successfully**\n")
            else:
                if not result.dmarc_compliant:
                    f.write("- ❌ **DMARC compliance failed** - email may be spoofed\n")
                if not result.spf_authenticated:
                    f.write("- ❌ **SPF authentication failed** - sender server not authorized\n")
                if not result.dkim_authenticated:
                    f.write("- ❌ **DKIM authentication failed** - message may be modified\n")
            
            if result.total_delay < 10:
                f.write(f"- ✅ **Fast delivery time:** {result.total_delay:.2f} seconds\n")
            elif result.total_delay < 60:
                f.write(f"- ⏱️ **Normal delivery time:** {result.total_delay:.2f} seconds\n")
            else:
                f.write(f"- ⚠️ **Slow delivery time:** {result.total_delay:.2f} seconds\n")
            
            if len(result.relays) < 5:
                f.write(f"- ✅ **Direct routing:** {len(result.relays)} hops\n")
            elif len(result.relays) < 10:
                f.write(f"- 📍 **Standard routing:** {len(result.relays)} hops\n")
            else:
                f.write(f"- ⚠️ **Complex routing:** {len(result.relays)} hops\n")
            
            f.write("\n---\n\n")
            f.write("*Generated by Email Forensics Analyzer Desktop v1.0*\n")