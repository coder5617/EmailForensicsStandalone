"""
DNS Lookup Service Module
Handles DNS queries for DMARC, SPF, DKIM records
"""

import dns.resolver
import dns.exception
from typing import Optional, List, Dict
from functools import lru_cache
import re

class DNSLookupService:
    """Service for DNS record lookups"""
    
    def __init__(self):
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 3
        self.resolver.lifetime = 5
        
    @lru_cache(maxsize=128)
    def get_dmarc_record(self, domain: str) -> Optional[str]:
        """Get DMARC record for a domain"""
        if not domain:
            return None
            
        try:
            # DMARC records are at _dmarc.domain
            dmarc_domain = f'_dmarc.{domain}'
            answers = self.resolver.resolve(dmarc_domain, 'TXT')
            
            for rdata in answers:
                txt_string = self._extract_txt_string(rdata)
                if txt_string and txt_string.startswith('v=DMARC1'):
                    return txt_string
                    
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            # Try organizational domain if subdomain fails
            if domain.count('.') > 1:
                parent_domain = '.'.join(domain.split('.')[1:])
                return self.get_dmarc_record(parent_domain)
        except dns.exception.DNSException:
            pass
            
        return None
    
    @lru_cache(maxsize=128)
    def get_spf_record(self, domain: str) -> Optional[str]:
        """Get SPF record for a domain"""
        if not domain:
            return None
            
        try:
            answers = self.resolver.resolve(domain, 'TXT')
            
            for rdata in answers:
                txt_string = self._extract_txt_string(rdata)
                if txt_string and txt_string.startswith('v=spf1'):
                    return txt_string
                    
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
            pass
            
        return None
    
    def get_dkim_selector_record(self, selector: str, domain: str) -> Optional[str]:
        """Get DKIM record for a specific selector and domain"""
        if not selector or not domain:
            return None
            
        try:
            dkim_domain = f'{selector}._domainkey.{domain}'
            answers = self.resolver.resolve(dkim_domain, 'TXT')
            
            for rdata in answers:
                txt_string = self._extract_txt_string(rdata)
                if txt_string:
                    return txt_string
                    
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
            pass
            
        return None
    
    def parse_dmarc_policy(self, dmarc_record: str) -> Dict[str, str]:
        """Parse DMARC record into components"""
        if not dmarc_record:
            return {}
            
        policy = {}
        
        # Parse key=value pairs
        parts = dmarc_record.split(';')
        for part in parts:
            part = part.strip()
            if '=' in part:
                key, value = part.split('=', 1)
                policy[key.strip()] = value.strip()
        
        return policy
    
    def parse_spf_record(self, spf_record: str) -> Dict[str, List[str]]:
        """Parse SPF record into components"""
        if not spf_record:
            return {}
            
        components = {
            'version': '',
            'mechanisms': [],
            'modifiers': [],
            'all': ''
        }
        
        parts = spf_record.split()
        
        for part in parts:
            if part.startswith('v='):
                components['version'] = part
            elif part in ['all', '+all', '-all', '~all', '?all']:
                components['all'] = part
            elif '=' in part:
                components['modifiers'].append(part)
            else:
                components['mechanisms'].append(part)
        
        return components
    
    def check_spf_alignment(self, spf_record: str, sender_ip: str) -> bool:
        """Check if sender IP is authorized by SPF record"""
        if not spf_record or not sender_ip:
            return False
            
        # Parse SPF mechanisms
        parts = spf_record.split()
        
        for part in parts:
            # Check IP4 mechanism
            if part.startswith('ip4:'):
                ip_range = part[4:]
                if self._ip_in_range(sender_ip, ip_range):
                    return True
            
            # Check IP6 mechanism
            elif part.startswith('ip6:'):
                ip_range = part[4:]
                if self._ip_in_range(sender_ip, ip_range):
                    return True
            
            # Include mechanism would require recursive lookup
            elif part.startswith('include:'):
                # This would require recursive SPF lookup
                pass
            
            # A mechanism
            elif part == 'a' or part.startswith('a:'):
                # This would require A record lookup
                pass
            
            # MX mechanism
            elif part == 'mx' or part.startswith('mx:'):
                # This would require MX record lookup
                pass
        
        return False
    
    def get_mx_records(self, domain: str) -> List[str]:
        """Get MX records for a domain"""
        if not domain:
            return []
            
        mx_records = []
        
        try:
            answers = self.resolver.resolve(domain, 'MX')
            
            for rdata in answers:
                mx_records.append({
                    'priority': rdata.preference,
                    'host': str(rdata.exchange).rstrip('.')
                })
            
            # Sort by priority
            mx_records.sort(key=lambda x: x['priority'])
            
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
            pass
        
        return mx_records
    
    def get_a_records(self, domain: str) -> List[str]:
        """Get A records for a domain"""
        if not domain:
            return []
            
        a_records = []
        
        try:
            answers = self.resolver.resolve(domain, 'A')
            
            for rdata in answers:
                a_records.append(str(rdata))
                
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
            pass
        
        return a_records
    
    def get_ptr_record(self, ip: str) -> Optional[str]:
        """Get PTR record for an IP address"""
        if not ip:
            return None
            
        try:
            # Convert IP to reverse DNS format
            parts = ip.split('.')
            reversed_ip = '.'.join(reversed(parts))
            ptr_domain = f'{reversed_ip}.in-addr.arpa'
            
            answers = self.resolver.resolve(ptr_domain, 'PTR')
            
            if answers:
                return str(answers[0]).rstrip('.')
                
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
            pass
        
        return None
    
    def verify_dkim_selector(self, dkim_signature: str) -> Dict[str, str]:
        """Extract and verify DKIM selector from signature"""
        result = {
            'selector': '',
            'domain': '',
            'record': None,
            'valid': False
        }
        
        if not dkim_signature:
            return result
        
        # Extract selector (s=) and domain (d=) from DKIM-Signature
        selector_match = re.search(r'\bs=([^;]+)', dkim_signature)
        domain_match = re.search(r'\bd=([^;]+)', dkim_signature)
        
        if selector_match and domain_match:
            result['selector'] = selector_match.group(1).strip()
            result['domain'] = domain_match.group(1).strip()
            
            # Try to fetch the DKIM record
            dkim_record = self.get_dkim_selector_record(result['selector'], result['domain'])
            if dkim_record:
                result['record'] = dkim_record
                result['valid'] = True
        
        return result
    
    def _extract_txt_string(self, rdata) -> str:
        """Extract text string from DNS TXT record data"""
        try:
            # Handle different formats of TXT records
            if hasattr(rdata, 'strings'):
                # Concatenate multiple strings in the TXT record
                return ''.join(s.decode('utf-8') if isinstance(s, bytes) else s 
                              for s in rdata.strings)
            else:
                return str(rdata).strip('"')
        except:
            return str(rdata)
    
    def _ip_in_range(self, ip: str, ip_range: str) -> bool:
        """Check if IP is in the specified range"""
        try:
            import ipaddress
            
            # Handle single IP or CIDR notation
            if '/' in ip_range:
                network = ipaddress.ip_network(ip_range, strict=False)
                ip_addr = ipaddress.ip_address(ip)
                return ip_addr in network
            else:
                return ip == ip_range
                
        except ValueError:
            return False

class DNSValidator:
    """Validator for DNS-based email authentication"""
    
    def __init__(self):
        self.dns_service = DNSLookupService()
    
    def validate_domain_authentication(self, domain: str) -> Dict[str, any]:
        """Validate all authentication records for a domain"""
        result = {
            'domain': domain,
            'has_dmarc': False,
            'has_spf': False,
            'has_mx': False,
            'dmarc_policy': None,
            'spf_record': None,
            'mx_records': [],
            'recommendations': []
        }
        
        # Check DMARC
        dmarc = self.dns_service.get_dmarc_record(domain)
        if dmarc:
            result['has_dmarc'] = True
            result['dmarc_policy'] = self.dns_service.parse_dmarc_policy(dmarc)
            
            # Check DMARC policy strength
            policy = result['dmarc_policy'].get('p', 'none')
            if policy == 'none':
                result['recommendations'].append(
                    "DMARC policy is set to 'none'. Consider using 'quarantine' or 'reject' for better protection."
                )
        else:
            result['recommendations'].append(
                "No DMARC record found. Consider implementing DMARC for email authentication."
            )
        
        # Check SPF
        spf = self.dns_service.get_spf_record(domain)
        if spf:
            result['has_spf'] = True
            result['spf_record'] = spf
            
            # Check SPF all mechanism
            if '-all' not in spf:
                if '~all' in spf:
                    result['recommendations'].append(
                        "SPF uses soft fail (~all). Consider using hard fail (-all) for stricter enforcement."
                    )
                elif '?all' in spf or '+all' in spf:
                    result['recommendations'].append(
                        "SPF has weak 'all' mechanism. Use -all or ~all for better protection."
                    )
        else:
            result['recommendations'].append(
                "No SPF record found. Implement SPF to specify authorized mail servers."
            )
        
        # Check MX records
        mx = self.dns_service.get_mx_records(domain)
        if mx:
            result['has_mx'] = True
            result['mx_records'] = mx
        else:
            result['recommendations'].append(
                "No MX records found. Domain may not be configured to receive email."
            )
        
        return result