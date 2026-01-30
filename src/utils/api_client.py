import requests
import json

class ThreatAPIClient:
    def __init__(self, abuse_key, grey_key, threatfox_key=None):
        self.abuse_key = abuse_key
        self.grey_key = grey_key
        self.threatfox_key = threatfox_key
        
        # Cấu hình Header cho ThreatFox
        self.threatfox_headers = {'Content-Type': 'application/json'}
        if self.threatfox_key:
            self.threatfox_headers['API-KEY'] = self.threatfox_key

        # --- BẢNG DỊCH MÃ ABUSEIPDB ---
        self.category_map = {
            "3": "Fraud Orders",
            "4": "DDOS Attack",
            "5": "FTP Brute-Force",
            "6": "Ping of Death",
            "7": "Phishing",
            "8": "Fraud VOIP",
            "9": "Open Proxy",
            "10": "Web Spam",
            "11": "Email Spam",
            "12": "Blog Spam",
            "13": "VPN IP",
            "14": "Port Scan",
            "15": "Hacking",
            "16": "SQL Injection",
            "17": "Spoofing",
            "18": "Brute Force",
            "19": "Bad Web Bot",
            "20": "Exploited Host",
            "21": "Web App Attack",
            "22": "SSH",
            "23": "IoT Targeted",
        }

    def check_abuseipdb(self, ip):
        url = 'https://api.abuseipdb.com/api/v2/check'
        params = {
            'ipAddress': ip, 
            'maxAgeInDays': '90',
            'verbose': '' 
        }
        headers = {'Accept': 'application/json', 'Key': self.abuse_key}
        
        try:
            res = requests.get(url, headers=headers, params=params, timeout=10)
            if res.status_code == 200:
                data = res.json().get('data', {})
                
                
                raw_reports = data.get('reports', [])
                cat_ids = set()
                for report in raw_reports:
                    for cid in report.get('categories', []):
                        cat_ids.add(cid)
                
                # Dịch mã ID sang tên (Ví dụ: 18 -> "Brute-Force")
                translated_categories = []
                for cid in cat_ids:
                    name = self.category_map.get(int(cid), f"Unknown({cid})")
                    translated_categories.append(name)
                
                return {
                    'score': data.get('abuseConfidenceScore', 0),
                    'categories': sorted(list(set(translated_categories))), 
                    'isp': data.get('isp', 'Unknown'),
                    'country_code': data.get('countryCode')
                }
        except Exception as e:
            print(f" [!] AbuseIPDB Error {ip}: {e}")
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

    def check_threatfox(self, ip):
        url = 'https://threatfox-api.abuse.ch/api/v1/'
        payload = {
            "query": "search_ioc",
            "search_term": ip
        }
        
        try:
            res = requests.post(url, json=payload, headers=self.threatfox_headers, timeout=10)
            
            if res.status_code == 200:
                response_data = res.json()
                if response_data.get('query_status') == 'ok':
                    data_list = response_data.get('data', [])
                    if data_list:
                        # Lấy kết quả mới nhất
                        latest_entry = data_list[0]
                        return {
                            'malware': latest_entry.get('malware_printable'),
                            'malware_alias': latest_entry.get('malware_alias'),
                            'threat_type': latest_entry.get('threat_type'),
                            'tags': latest_entry.get('tags', []),
                            'confidence': latest_entry.get('confidence_level'),
                            'reference': latest_entry.get('reference')
                        }
        except Exception as e:
            print(f" [!] ThreatFox Error {ip}: {e}")
        
        return None