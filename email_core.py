"""
Email Core Analysis Module
Handles email parsing, authentication checking, and relay chain analysis
"""

import email.parser
import email.utils
import re
import datetime
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Callable
import ipaddress

@dataclass
class EmailParseResult:
    """Data class for email analysis results"""
    # Authentication results
    dmarc_compliant: bool = False
    dmarc_status: str = "none"
    spf_aligned: bool = False
    spf_authenticated: bool = False
    spf_status: str = "none"
    dkim_aligned: bool = False
    dkim_authenticated: bool = False
    dkim_status: str = "none"
    
    # DNS records
    dmarc_txt: str = ""
    spf_txt: str = ""
    dkim_info: str = ""
    
    # Headers
    headers: Dict[str, str] = field(default_factory=dict)
    auth_results: str = ""
    spf_info: str = ""
    
    # IP and relay information
    sender_ip: Optional[str] = None
    ip_info: Dict = field(default_factory=dict)
    relays: List[Dict] = field(default_factory=list)
    
    # Timing
    total_delay: float = 0.0
    delay_source: str = "Calculated"
    end_to_end_latency_header: str = ""
    
    # Domains
    from_domain: str = ""
    return_path_domain: str = ""
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON export"""
        return {
            'authentication': {
                'dmarc': {
                    'compliant': self.dmarc_compliant,
                    'status': self.dmarc_status,
                    'record': self.dmarc_txt
                },
                'spf': {
                    'aligned': self.spf_aligned,
                    'authenticated': self.spf_authenticated,
                    'status': self.spf_status,
                    'record': self.spf_txt,
                    'info': self.spf_info
                },
                'dkim': {
                    'aligned': self.dkim_aligned,
                    'authenticated': self.dkim_authenticated,
                    'status': self.dkim_status,
                    'info': self.dkim_info
                }
            },
            'sender': {
                'ip': self.sender_ip,
                'info': self.ip_info,
                'from_domain': self.from_domain,
                'return_path_domain': self.return_path_domain
            },
            'delivery': {
                'total_delay': self.total_delay,
                'delay_source': self.delay_source,
                'relays': self.relays
            },
            'headers': self.headers
        }

class EmailAnalyzer:
    """Core email analysis engine"""
    
    def __init__(self):
        self.parser = email.parser.Parser()
        
    def analyze(self, header_text: str, progress_callback: Optional[Callable] = None) -> EmailParseResult:
        """Analyze email headers and return results"""
        result = EmailParseResult()
        
        # Parse email
        if progress_callback:
            progress_callback(20, "Parsing email structure...")
        msg = self.parser.parsestr(header_text)
        result.headers = dict(msg.items())
        
        # Extract domains
        if progress_callback:
            progress_callback(30, "Extracting domains...")
        result.from_domain, result.return_path_domain = self._extract_domains(msg)
        
        # Check authentication
        if progress_callback:
            progress_callback(40, "Checking authentication...")
        self._check_authentication(msg, result)
        
        # Process relay chain
        if progress_callback:
            progress_callback(60, "Analyzing relay chain...")
        self._process_relays(msg, result)
        
        # Extract sender IP
        if progress_callback:
            progress_callback(80, "Identifying sender IP...")
        self._extract_sender_ip(msg, result)
        
        # Calculate delays
        if progress_callback:
            progress_callback(90, "Calculating delivery times...")
        self._calculate_delays(msg, result)
        
        # Note: IP geolocation will be done in the main app after analysis
        # This keeps the core module independent of network calls
        
        if progress_callback:
            progress_callback(100, "Analysis complete")
        
        return result
    
    def _extract_domains(self, msg) -> Tuple[str, str]:
        """Extract from and return-path domains"""
        from_header = msg.get('From', '')
        from_domain = ''
        if from_header:
            addr = email.utils.parseaddr(from_header)[1]
            if '@' in addr:
                from_domain = addr.split('@')[-1]
        
        return_path = msg.get('Return-Path', '')
        rp_domain = ''
        if return_path:
            addr = email.utils.parseaddr(return_path)[1]
            if '@' in addr:
                rp_domain = addr.split('@')[-1]
        
        return from_domain, rp_domain
    
    def _check_authentication(self, msg, result: EmailParseResult):
        """Check email authentication (SPF, DKIM, DMARC)"""
        # Get authentication results header
        auth_results = msg.get('Authentication-Results', '')
        result.auth_results = auth_results
        
        # Check alignment
        result.spf_aligned = result.from_domain == result.return_path_domain if result.return_path_domain else False
        
        # Check DKIM signature
        dkim_signature = msg.get('DKIM-Signature', '')
        if dkim_signature:
            d_match = re.search(r'\bd=([^;]+)', dkim_signature)
            if d_match:
                d_domain = d_match.group(1).strip()
                result.dkim_aligned = result.from_domain == d_domain
            result.dkim_info = dkim_signature[:200] + "..." if len(dkim_signature) > 200 else dkim_signature
        else:
            result.dkim_info = "No DKIM-Signature found"
        
        # Parse authentication results
        if auth_results:
            # SPF
            spf_result = re.search(r'spf=([a-zA-Z]+)', auth_results)
            if spf_result:
                result.spf_status = spf_result.group(1)
                result.spf_authenticated = result.spf_status.lower() == 'pass'
            
            # Extract detailed SPF info
            spf_info_match = re.search(r'spf=[^;]+(?:;[^;]+)*', auth_results)
            if spf_info_match:
                result.spf_info = spf_info_match.group(0)
            
            # DKIM
            dkim_result = re.search(r'dkim=([a-zA-Z]+)', auth_results)
            if dkim_result:
                result.dkim_status = dkim_result.group(1)
                result.dkim_authenticated = result.dkim_status.lower() == 'pass'
            
            # DMARC
            dmarc_result = re.search(r'dmarc=([a-zA-Z]+)', auth_results)
            if dmarc_result:
                result.dmarc_status = dmarc_result.group(1)
                result.dmarc_compliant = result.dmarc_status.lower() == 'pass'
    
    def _process_relays(self, msg, result: EmailParseResult):
        """Process the relay chain from Received headers"""
        received_list = msg.get_all('Received', [])
        relays = []
        
        for idx, rec in enumerate(reversed(received_list), 1):
            relay = self._parse_received_header(rec, idx)
            relays.append(relay)
        
        # Check if we need to reverse the order based on timestamps
        if len(relays) > 1 and relays[0]['time_dt'] and relays[1]['time_dt']:
            if relays[1]['time_dt'] < relays[0]['time_dt']:
                relays = list(reversed(relays))
                for idx, r in enumerate(relays, 1):
                    r['hop'] = idx
        
        result.relays = relays
    
    def _parse_received_header(self, header: str, hop: int) -> Dict:
        """Parse a single Received header"""
        relay = {
            'hop': hop,
            'from': '',
            'by': '',
            'with': '',
            'time': '',
            'time_dt': None,
            'delay': 0,
            'blacklist': True,
            'ip': ''
        }
        
        # Extract components
        from_match = re.search(r'from\s+(.+?)\s+by', header, re.IGNORECASE | re.DOTALL)
        if from_match:
            relay['from'] = from_match.group(1).strip()
        
        by_match = re.search(r'by\s+(.+?)\s+(with|id|;|$)', header, re.IGNORECASE | re.DOTALL)
        if by_match:
            relay['by'] = by_match.group(1).strip()
        
        with_match = re.search(r'with\s+(.+?)\s+(id|;|$)', header, re.IGNORECASE | re.DOTALL)
        if with_match:
            relay['with'] = with_match.group(1).strip()
        
        # Extract timestamp
        time_match = re.search(r';\s*(.+)$', header)
        if time_match:
            time_str = time_match.group(1).strip()
            try:
                relay['time_dt'] = email.utils.parsedate_to_datetime(time_str)
                relay['time'] = relay['time_dt'].strftime('%m/%d/%Y %I:%M:%S %p')
            except:
                relay['time'] = time_str
        
        # Extract IP
        relay['ip'] = self._extract_ip_from_text(relay['from'])
        
        return relay
    
    def _extract_ip_from_text(self, text: str) -> str:
        """Extract IP address from text"""
        # IPv4 pattern
        ipv4_pattern = r'(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'
        # IPv6 pattern (simplified)
        ipv6_pattern = r'(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}'
        
        # Try IPv4 first
        ipv4_match = re.search(ipv4_pattern, text)
        if ipv4_match:
            return ipv4_match.group(0)
        
        # Try IPv6
        ipv6_match = re.search(ipv6_pattern, text)
        if ipv6_match:
            return ipv6_match.group(0)
        
        return ''
    
    def _extract_sender_ip(self, msg, result: EmailParseResult):
        """Extract sender IP address"""
        auth_results = result.auth_results
        
        # Try to find IP in authentication results
        ip_match = re.search(r'(?:sender\s*ip\s*is|client-ip=)\s*([\[\(]?[\d\.:a-fA-F]+[\]\)]?)', 
                            auth_results, re.IGNORECASE)
        if ip_match:
            candidate = ip_match.group(1).strip('[]()')
            if self._is_valid_ip(candidate) and not self._is_private_ip(candidate):
                result.sender_ip = candidate
                return
        
        # Fall back to first public IP in relay chain
        for relay in result.relays:
            if relay['ip'] and self._is_valid_ip(relay['ip']) and not self._is_private_ip(relay['ip']):
                result.sender_ip = relay['ip']
                return
    
    def _calculate_delays(self, msg, result: EmailParseResult):
        """Calculate delivery delays"""
        # Check for Exchange end-to-end latency header
        latency_header = msg.get('X-MS-Exchange-Transport-EndToEndLatency', '')
        if latency_header:
            result.end_to_end_latency_header = latency_header
            parsed_delay = self._parse_latency_header(latency_header)
            if parsed_delay is not None:
                result.total_delay = parsed_delay
                result.delay_source = "X-MS-Exchange-Transport-EndToEndLatency"
                return
        
        # Calculate from relay timestamps
        calculated_delay = 0
        relays = result.relays
        
        for i in range(1, len(relays)):
            if relays[i-1]['time_dt'] and relays[i]['time_dt']:
                delta = (relays[i]['time_dt'] - relays[i-1]['time_dt']).total_seconds()
                relays[i]['delay'] = max(delta, 0)
                calculated_delay += relays[i]['delay']
        
        result.total_delay = calculated_delay
        result.delay_source = "Calculated from Received headers"
    
    def _parse_latency_header(self, latency_header: str) -> Optional[float]:
        """Parse Exchange latency header to extract seconds"""
        if not latency_header:
            return None
        
        try:
            # Pattern: HH:MM:SS.fractional
            time_match = re.search(r'(\d{1,2}):(\d{2}):(\d{2})(?:\.(\d+))?', latency_header)
            if time_match:
                hours = int(time_match.group(1))
                minutes = int(time_match.group(2))
                seconds = int(time_match.group(3))
                fractional = time_match.group(4) or '0'
                fractional_value = int(fractional) / (10 ** len(fractional)) if fractional else 0
                return hours * 3600 + minutes * 60 + seconds + fractional_value
            
            # Pattern: seconds.fractional
            seconds_match = re.search(r'(\d+)\.(\d+)', latency_header)
            if seconds_match:
                seconds = int(seconds_match.group(1))
                fractional = seconds_match.group(2)
                fractional_value = int(fractional) / (10 ** len(fractional))
                return seconds + fractional_value
            
            # Pattern: integer seconds
            seconds_match = re.search(r'(\d+)', latency_header)
            if seconds_match:
                seconds = int(seconds_match.group(1))
                if seconds > 3600:  # Likely milliseconds
                    return seconds / 1000.0
                return float(seconds)
            
        except:
            pass
        
        return None
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Check if string is a valid IP address"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private or loopback"""
        if not ip:
            return True
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private or ip_obj.is_loopback
        except ValueError:
            return True