"""
IP Lookup Service Module
Handles IP geolocation and blacklist checking
"""

import requests
import ipaddress
import dns.resolver
import dns.exception
from typing import Dict, Optional, List
from functools import lru_cache
import json
import os
from pathlib import Path

class IPLookupService:
    """Service for IP geolocation and reputation checking"""
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self.cache_dir = Path.home() / ".email_forensics" / "ip_cache"
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'EmailForensics/1.0'})
    
    @lru_cache(maxsize=256)
    def get_ip_info(self, ip: str) -> Dict:
        """Get geolocation information for an IP address"""
        if not self._is_valid_ip(ip) or self._is_private_ip(ip):
            return {'error': 'Invalid or private IP address'}
        
        # Check cache first
        cached = self._get_cached_ip_info(ip)
        if cached:
            return cached
        
        try:
            # Try IPInfo API
            url = f'https://ipinfo.io/{ip}/json'
            if self.api_key:
                url += f'?token={self.api_key}'
            
            response = self.session.get(url, timeout=5)
            
            if response.ok:
                data = response.json()
                # Cache the result
                self._cache_ip_info(ip, data)
                return data
            else:
                # Fall back to offline data or alternative service
                return self._get_fallback_ip_info(ip)
                
        except requests.exceptions.Timeout:
            return {'error': 'Request timed out', 'ip': ip}
        except requests.exceptions.RequestException as e:
            return {'error': f'Request failed: {str(e)}', 'ip': ip}
        except Exception as e:
            return {'error': f'Unexpected error: {str(e)}', 'ip': ip}
    
    def check_blacklists(self, ip: str) -> Dict[str, bool]:
        """Check if IP is on various blacklists"""
        if not self._is_valid_ip(ip) or self._is_private_ip(ip):
            return {}
        
        blacklists = {
            'spamhaus': self._check_spamhaus(ip),
            'barracuda': self._check_barracuda(ip),
            'spamcop': self._check_spamcop(ip)
        }
        
        return blacklists
    
    def _check_spamhaus(self, ip: str) -> bool:
        """Check Spamhaus blacklist"""
        try:
            parts = ip.split('.')
            reversed_ip = '.'.join(reversed(parts))
            query = f'{reversed_ip}.zen.spamhaus.org'
            dns.resolver.resolve(query, 'A')
            return True  # Listed
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            return False  # Not listed
        except Exception:
            return None  # Error
    
    def _check_barracuda(self, ip: str) -> bool:
        """Check Barracuda blacklist"""
        try:
            parts = ip.split('.')
            reversed_ip = '.'.join(reversed(parts))
            query = f'{reversed_ip}.b.barracudacentral.org'
            dns.resolver.resolve(query, 'A')
            return True  # Listed
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            return False  # Not listed
        except Exception:
            return None  # Error
    
    def _check_spamcop(self, ip: str) -> bool:
        """Check SpamCop blacklist"""
        try:
            parts = ip.split('.')
            reversed_ip = '.'.join(reversed(parts))
            query = f'{reversed_ip}.bl.spamcop.net'
            dns.resolver.resolve(query, 'A')
            return True  # Listed
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            return False  # Not listed
        except Exception:
            return None  # Error
    
    def get_asn_info(self, ip: str) -> Dict:
        """Get ASN information for an IP"""
        if not self._is_valid_ip(ip) or self._is_private_ip(ip):
            return {}
        
        try:
            # Use Team Cymru's IP to ASN mapping service
            parts = ip.split('.')
            reversed_ip = '.'.join(reversed(parts))
            query = f'{reversed_ip}.origin.asn.cymru.com'
            
            answers = dns.resolver.resolve(query, 'TXT')
            if answers:
                # Parse the response: "AS# | IP prefix | Country | Registry | Allocation date"
                txt = str(answers[0]).strip('"')
                parts = [p.strip() for p in txt.split('|')]
                if len(parts) >= 3:
                    return {
                        'asn': parts[0],
                        'prefix': parts[1],
                        'country': parts[2],
                        'registry': parts[3] if len(parts) > 3 else '',
                        'allocated': parts[4] if len(parts) > 4 else ''
                    }
        except Exception:
            pass
        
        return {}
    
    def get_ptr_record(self, ip: str) -> Optional[str]:
        """Get PTR (reverse DNS) record for an IP"""
        if not self._is_valid_ip(ip):
            return None
        
        try:
            import socket
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
        except Exception:
            return None
    
    def _get_cached_ip_info(self, ip: str) -> Optional[Dict]:
        """Get cached IP information"""
        cache_file = self.cache_dir / f"{ip.replace('.', '_')}.json"
        if cache_file.exists():
            try:
                with open(cache_file, 'r') as f:
                    data = json.load(f)
                    # Check if cache is still valid (7 days)
                    import time
                    if time.time() - data.get('_cached_at', 0) < 7 * 24 * 3600:
                        return data
            except:
                pass
        return None
    
    def _cache_ip_info(self, ip: str, data: Dict):
        """Cache IP information"""
        cache_file = self.cache_dir / f"{ip.replace('.', '_')}.json"
        try:
            import time
            data['_cached_at'] = time.time()
            with open(cache_file, 'w') as f:
                json.dump(data, f)
        except:
            pass
    
    def _get_fallback_ip_info(self, ip: str) -> Dict:
        """Get fallback IP information when API is unavailable"""
        info = {'ip': ip}
        
        # Try to get PTR record
        ptr = self.get_ptr_record(ip)
        if ptr:
            info['hostname'] = ptr
        
        # Try to get ASN info
        asn_info = self.get_asn_info(ip)
        if asn_info:
            info.update(asn_info)
        
        # Check if it's a known range
        try:
            ip_obj = ipaddress.ip_address(ip)
            
            # Check for known cloud providers
            cloud_ranges = {
                'Google': ['8.8.0.0/12', '35.0.0.0/8', '104.16.0.0/12'],
                'Amazon AWS': ['52.0.0.0/8', '54.0.0.0/8', '18.0.0.0/8'],
                'Microsoft Azure': ['13.64.0.0/11', '20.0.0.0/8', '40.0.0.0/8'],
                'Cloudflare': ['104.16.0.0/12', '172.64.0.0/13', '173.245.48.0/20']
            }
            
            for provider, ranges in cloud_ranges.items():
                for range_str in ranges:
                    if ip_obj in ipaddress.ip_network(range_str):
                        info['org'] = provider
                        break
        except:
            pass
        
        return info
    
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

class BlacklistChecker:
    """Dedicated blacklist checking service"""
    
    # Popular blacklists to check
    BLACKLISTS = [
        ('zen.spamhaus.org', 'Spamhaus ZEN'),
        ('b.barracudacentral.org', 'Barracuda'),
        ('bl.spamcop.net', 'SpamCop'),
        ('dnsbl.sorbs.net', 'SORBS'),
        ('cbl.abuseat.org', 'CBL'),
        ('psbl.surriel.com', 'PSBL'),
        ('all.s5h.net', 'S5H'),
        ('ix.dnsbl.manitu.net', 'Manitu'),
        ('dnsbl-1.uceprotect.net', 'UCEPROTECT-1'),
        ('dul.dnsbl.sorbs.net', 'SORBS DUL')
    ]
    
    def __init__(self):
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 2
        self.resolver.lifetime = 2
    
    def check_ip(self, ip: str) -> Dict[str, Optional[bool]]:
        """Check an IP against multiple blacklists"""
        if not self._is_valid_public_ip(ip):
            return {}
        
        results = {}
        reversed_ip = '.'.join(reversed(ip.split('.')))
        
        for bl_host, bl_name in self.BLACKLISTS:
            results[bl_name] = self._check_single_blacklist(reversed_ip, bl_host)
        
        return results
    
    def _check_single_blacklist(self, reversed_ip: str, blacklist: str) -> Optional[bool]:
        """Check a single blacklist"""
        try:
            query = f'{reversed_ip}.{blacklist}'
            self.resolver.resolve(query, 'A')
            return True  # Listed
        except dns.resolver.NXDOMAIN:
            return False  # Not listed
        except (dns.resolver.NoAnswer, dns.resolver.Timeout, dns.exception.DNSException):
            return None  # Error/timeout
    
    def _is_valid_public_ip(self, ip: str) -> bool:
        """Check if IP is valid and public"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return not (ip_obj.is_private or ip_obj.is_loopback or 
                       ip_obj.is_multicast or ip_obj.is_reserved)
        except ValueError:
            return False