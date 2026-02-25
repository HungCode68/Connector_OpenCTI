import requests
import json
import whois
import dns.resolver
from datetime import datetime
import time
import random
import base64

class ThreatAPIClient:
    def __init__(self, abuse_key, grey_key, threatfox_key=None, vt_key=None):
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
    def check_abuseipdb(self, ip):
        url = 'https://api.abuseipdb.com/api/v2/check'
        params = {
            'ipAddress': ip, 
            'maxAgeInDays': '90',
            'verbose': '' # Cần verbose để lấy reports categories
        }
        headers = {'Accept': 'application/json', 'Key': self.abuse_key}
        
        try:
            res = requests.get(url, headers=headers, params=params, timeout=10)
            if res.status_code == 200:
                data = res.json().get('data', {})
                
                # Logic bóc tách Category 
                raw_reports = data.get('reports', [])
                cat_ids = set()
                for report in raw_reports:
                    for cid in report.get('categories', []):
                        cat_ids.add(str(cid)) # Đảm bảo là string để map
                
                translated_categories = []
                for cid in cat_ids:
                    name = self.category_map.get(cid, f"Unknown({cid})")
                    translated_categories.append(name)
                
                return {
                    'score': data.get('abuseConfidenceScore', 0),
                    'categories': sorted(list(set(translated_categories))), 
                    'isp': data.get('isp', 'Unknown'),
                    'usage_type': data.get('usageType', 'Unknown'),
                    'country_code': data.get('countryCode')
                }
        except Exception as e:
            # print(f" [!] AbuseIPDB Error {ip}: {e}")
            pass
        return None

    def check_greynoise(self, ip):
        url = f'https://api.greynoise.io/v3/community/{ip}'
        headers = {'key': self.grey_key}
        try:
            res = requests.get(url, headers=headers, timeout=5)
            if res.status_code == 200:
                return res.json()
        except:
            pass
        return None

    # --- XỬ LÝ THREATFOX ---
    def check_threatfox(self, ioc):
        """
        Check IOC trên ThreatFox. 
        Input 'ioc' có thể là IP, Domain, hoặc Hash.
        """
        url = 'https://threatfox-api.abuse.ch/api/v1/'
        payload = {
            "query": "search_ioc",
            "search_term": ioc
        }
        
        try:
            res = requests.post(url, json=payload, headers=self.threatfox_headers, timeout=10)
            
            if res.status_code == 200:
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
        except Exception as e:
            pass
        return None

    # --- XỬ LÝ HASH/DRIVER ---
    def check_virustotal_hash(self, file_hash):
        if not self.vt_key: 
            return None
        
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        try:
            res = requests.get(url, headers=self.vt_headers, timeout=15)
            if res.status_code == 200:
                data = res.json().get('data', {}).get('attributes', {})
                stats = data.get('last_analysis_stats', {})
                
                return {
                    'malicious_count': stats.get('malicious', 0),
                    'meaningful_name': data.get('meaningful_name'),
                    'tags': data.get('tags', []),
                    'magic': data.get('magic', 'Unknown'), # Loại file thực tế
                    'product': data.get('signature_info', {}).get('product', 'Unknown'),
                    'description': data.get('type_description')
                }
        except Exception as e:
            pass
        return None
    

    def check_virustotal_url(self, url_str):
        if not self.vt_key: return None
        try:
            # Mã hóa URL sang Base64 chuẩn VT
            url_id = base64.urlsafe_b64encode(url_str.encode()).decode().strip("=")
            url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
            
            res = requests.get(url, headers=self.vt_headers, timeout=15)
            if res.status_code == 200:
                data = res.json().get('data', {}).get('attributes', {})
                stats = data.get('last_analysis_stats', {})
                return {
                    'malicious_count': stats.get('malicious', 0),
                    'title': data.get('title'),
                    'tags': data.get('tags', [])
                }
        except: pass
        return None

    # --- XỬ LÝ DOMAIN ---
    def check_domain_info(self, domain):
        info = {
            "creation_date": None, 
            "age_days": None, 
            "resolved_ips": [], 
            "registrar": "Unknown"
        }
        
        # Whois Lookup
        try:
            time.sleep(random.uniform(1.0, 3.0))
            w = whois.whois(domain)
            # Xử lý date (có thể trả về list hoặc datetime hoặc string)
            c_date = w.creation_date
            
            # Xử lý trường hợp trả về list ngày
            if isinstance(c_date, list): 
                c_date = c_date[0]
            
            # Kiểm tra xem c_date có phải là dữ liệu thời gian hợp lệ không
            if c_date and isinstance(c_date, datetime):
                info["creation_date"] = c_date.isoformat()
                info["registrar"] = w.registrar
                
                # Tính tuổi domain
                delta = datetime.now() - c_date
                info["age_days"] = delta.days
        except Exception as e: 
            # Có thể in lỗi ra để debug nếu cần
            # print(f"Whois Error {domain}: {e}")
            pass

        # DNS Resolution
        try:
            answers = dns.resolver.resolve(domain, 'A')
            for r in answers: 
                info["resolved_ips"].append(r.to_text())
        except: 
            pass
        
        return info