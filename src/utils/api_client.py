import requests

class ThreatAPIClient:
    def __init__(self, abuse_key, grey_key, threatfox_key=None):
        self.abuse_key = abuse_key
        self.grey_key = grey_key
        self.threatfox_key = threatfox_key
        self.threatfox_headers = {'Content-Type': 'application/json'}
        if self.threatfox_key:
            self.threatfox_headers['API-KEY'] = self.threatfox_key
        # Bảng ánh xạ mã lỗi từ AbuseIPDB
        self.category_map = {
            3: "Fraud Orders", 4: "DDoS Attack", 9: "HTTP Spam",
            10: "Web Spam", 11: "Email Spam", 14: "Port Scan",
            15: "Hacking", 18: "Brute-Force", 19: "Bad Web Bot",
            20: "Exploited Host", 21: "Web App Attack", 22: "SSH", 23: "IoT Targeted"
        }

    def check_abuseipdb(self, ip):
        url = 'https://api.abuseipdb.com/api/v2/check'
        headers = {'Accept': 'application/json', 'Key': self.abuse_key}
        # Thêm verbose để lấy danh sách categories chi tiết
        params = {'ipAddress': ip, 'maxAgeInDays': '90', 'verbose': ''}
        
        try:
            res = requests.get(url, headers=headers, params=params, timeout=7)
            if res.status_code == 200:
                data = res.json()['data']
                
                # Chuyển đổi danh sách mã số category sang tên hiển thị
                report_categories = []
                if 'reports' in data and data['reports']:
                    # Lấy các category duy nhất từ các báo cáo gần nhất
                    cat_ids = set()
                    for r in data['reports']:
                        cat_ids.update(r['categories'])
                    
                    # Dịch mã sang tên
                    report_categories = [self.category_map.get(cid, f"Unknown({cid})") for cid in cat_ids]

                return {
                    'score': data.get('abuseConfidenceScore'),
                    'total_reports': data.get('totalReports'),
                    'last_reported_at': data.get('lastReportedAt'),
                    'categories': report_categories,
                    'domain': data.get('domain'),
                    'is_whitelisted': data.get('isWhitelisted')
                }
        except Exception as e:
            print(f"Lỗi gọi AbuseIPDB cho {ip}: {e}")
            return None

    def check_greynoise(self, ip):
        url = f'https://api.greynoise.io/v3/community/{ip}'
        headers = {'key': self.grey_key}
        try:
            res = requests.get(url, headers=headers, timeout=5)
            if res.status_code == 200:
                data = res.json()
                return {
                    'noise': data.get('noise', False),
                    'riot': data.get('riot', False),
                    'classification': data.get('classification', 'unknown'),
                    'name': data.get('name', 'Unknown Actor'), # Tên của máy quét (vd: Censys)
                    'last_seen': data.get('last_seen')
                }
        except: return None

    def check_threatfox(self, ip):
        """
        Truy vấn thông tin mã độc từ ThreatFox
        """
        url = 'https://threatfox-api.abuse.ch/api/v1/'
        payload = {
            "query": "search_ioc",
            "search_term": ip
        }
        
        try:
            # Sử dụng self.threatfox_headers đã cấu hình ở trên
            res = requests.post(url, json=payload, headers=self.threatfox_headers, timeout=10)
            
            if res.status_code == 200:
                response_data = res.json()
                if response_data.get('query_status') == 'ok':
                    data_list = response_data.get('data', [])
                    if data_list:
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
            print(f"[ThreatFox] Error checking {ip}: {e}")
        
        return None