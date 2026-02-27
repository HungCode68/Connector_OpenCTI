import base64
import logging
import random
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

import dns.resolver
import requests
import whois

# Khởi tạo logger cho file này
logger = logging.getLogger(__name__)

class ThreatAPIClient:
    def __init__(self, abuse_key: str, grey_key: str, threatfox_key: Optional[str] = None, vt_key: Optional[str] = None):
        self.abuse_key = abuse_key
        self.grey_key = grey_key
        self.threatfox_key = threatfox_key
        self.vt_key = vt_key
        
        # Cấu hình Header
        self.threatfox_headers = {'Content-Type': 'application/json'}
        if self.threatfox_key:
            self.threatfox_headers['API-KEY'] = self.threatfox_key

        self.vt_headers = {'x-apikey': self.vt_key} if self.vt_key else None

        # --- BẢNG DỊCH MÃ ABUSEIPDB ---
        self.category_map = {
            "3": "Fraud Orders", "4": "DDOS Attack", "5": "FTP Brute-Force", 
            "6": "Ping of Death", "7": "Phishing", "8": "Fraud VOIP", 
            "9": "Open Proxy", "10": "Web Spam", "11": "Email Spam", 
            "12": "Blog Spam", "13": "VPN IP", "14": "Port Scan", 
            "15": "Hacking", "16": "SQL Injection", "17": "Spoofing", 
            "18": "Brute Force", "19": "Bad Web Bot", "20": "Exploited Host", 
            "21": "Web App Attack", "22": "SSH", "23": "IoT Targeted"
        }

    # --- XỬ LÝ IP ---
    def check_abuseipdb(self, ip: str) -> Optional[Dict[str, Any]]:
        url = 'https://api.abuseipdb.com/api/v2/check'
        params = {
            'ipAddress': ip, 
            'maxAgeInDays': '90',
            'verbose': '' # Cần verbose để lấy reports categories
        }
        headers = {'Accept': 'application/json', 'Key': self.abuse_key}
        
        try:
            res = requests.get(url, headers=headers, params=params, timeout=10)
            res.raise_for_status() # Ném lỗi ngay nếu API trả về 4xx, 5xx
            data = res.json().get('data', {})
            
            # Logic bóc tách Category 
            raw_reports = data.get('reports', [])
            cat_ids = set()
            for report in raw_reports:
                for cid in report.get('categories', []):
                    cat_ids.add(str(cid)) 
            
            translated_categories = [
                self.category_map.get(cid, f"Unknown({cid})") for cid in cat_ids
            ]
            
            return {
                'score': data.get('abuseConfidenceScore', 0),
                'categories': sorted(list(set(translated_categories))), 
                'isp': data.get('isp', 'Unknown'),
                'usage_type': data.get('usageType', 'Unknown'),
                'country_code': data.get('countryCode')
            }
        except requests.RequestException as e:
            logger.warning(f"AbuseIPDB network error for IP {ip}: {e}")
        except Exception as e:
            logger.error(f"Unexpected error parsing AbuseIPDB for IP {ip}: {e}")
            
        return None

    def check_greynoise(self, ip: str) -> Optional[Dict[str, Any]]:
        url = f'https://api.greynoise.io/v3/community/{ip}'
        headers = {'key': self.grey_key}
        try:
            res = requests.get(url, headers=headers, timeout=5)
            res.raise_for_status()
            return res.json()
        except requests.RequestException as e:
            logger.warning(f"GreyNoise network error for IP {ip}: {e}")
        except Exception as e:
            logger.error(f"Unexpected error with GreyNoise for IP {ip}: {e}")
            
        return None

    # --- XỬ LÝ THREATFOX ---
    def check_threatfox(self, ioc: str) -> Optional[Dict[str, Any]]:
        url = 'https://threatfox-api.abuse.ch/api/v1/'
        payload = {
            "query": "search_ioc",
            "search_term": ioc
        }
        
        try:
            res = requests.post(url, json=payload, headers=self.threatfox_headers, timeout=10)
            res.raise_for_status()
            response_data = res.json()
            
            if response_data.get('query_status') == 'ok':
                data_list = response_data.get('data', [])
                if data_list:
                    latest_entry = data_list[0]
                    return {
                        'malware': latest_entry.get('malware_printable'),
                        'tags': latest_entry.get('tags', []),
                        'confidence': latest_entry.get('confidence_level'),
                        'reference': latest_entry.get('reference')
                    }
        except requests.RequestException as e:
            logger.warning(f"ThreatFox network error for IOC {ioc}: {e}")
        except Exception as e:
            logger.error(f"Unexpected error with ThreatFox for IOC {ioc}: {e}")
            
        return None

    # --- XỬ LÝ HASH/DRIVER ---
    def check_virustotal_hash(self, file_hash: str) -> Optional[Dict[str, Any]]:
        if not self.vt_key: 
            return None
        
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        try:
            res = requests.get(url, headers=self.vt_headers, timeout=15)
            res.raise_for_status()
            data = res.json().get('data', {}).get('attributes', {})
            stats = data.get('last_analysis_stats', {})
            
            return {
                'malicious_count': stats.get('malicious', 0),
                'meaningful_name': data.get('meaningful_name'),
                'tags': data.get('tags', []),
                'magic': data.get('magic', 'Unknown'),
                'product': data.get('signature_info', {}).get('product', 'Unknown'),
                'description': data.get('type_description')
            }
        except requests.RequestException as e:
            logger.warning(f"VirusTotal network error for hash {file_hash}: {e}")
        except Exception as e:
            logger.error(f"Unexpected error with VirusTotal for hash {file_hash}: {e}")
            
        return None
    
    def check_virustotal_url(self, url_str: str) -> Optional[Dict[str, Any]]:
        if not self.vt_key: 
            return None
            
        try:
            # Mã hóa URL sang Base64 chuẩn VT
            url_id = base64.urlsafe_b64encode(url_str.encode()).decode().strip("=")
            url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
            
            res = requests.get(url, headers=self.vt_headers, timeout=15)
            res.raise_for_status()
            data = res.json().get('data', {}).get('attributes', {})
            stats = data.get('last_analysis_stats', {})
            
            return {
                'malicious_count': stats.get('malicious', 0),
                'title': data.get('title'),
                'tags': data.get('tags', [])
            }
        except requests.RequestException as e:
            logger.warning(f"VirusTotal network error for URL {url_str}: {e}")
        except Exception as e:
            logger.error(f"Unexpected error with VirusTotal for URL {url_str}: {e}")
            
        return None

    # --- XỬ LÝ DOMAIN ---
    def check_domain_info(self, domain: str) -> Dict[str, Any]:
        info: Dict[str, Any] = {
            "creation_date": None, 
            "age_days": None, 
            "resolved_ips": [], 
            "registrar": "Unknown"
        }
        
        # 1. Whois Lookup
        try:
            time.sleep(random.uniform(1.0, 3.0))
            w = whois.whois(domain)
            c_date = w.creation_date
            
            if isinstance(c_date, list): 
                c_date = c_date[0]
            
            if c_date and isinstance(c_date, datetime):
                info["creation_date"] = c_date.isoformat()
                info["registrar"] = w.registrar
                info["age_days"] = (datetime.now() - c_date).days
                
        except Exception as e: 
            logger.warning(f"Whois lookup failed for domain {domain}: {e}")

        # 2. DNS Resolution
        try:
            answers = dns.resolver.resolve(domain, 'A')
            info["resolved_ips"] = [r.to_text() for r in answers]
        except dns.resolver.NXDOMAIN:
            logger.debug(f"DNS Resolve: NXDOMAIN (Không tồn tại) cho {domain}")
        except dns.resolver.Timeout:
            logger.warning(f"DNS Resolve: Timeout khi phân giải {domain}")
        except Exception as e: 
            logger.warning(f"DNS Resolve error cho {domain}: {e}")
        
        return info