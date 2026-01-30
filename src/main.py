import os
import time
import json
import stix2
import geoip2.database
from datetime import datetime
from concurrent.futures import ProcessPoolExecutor

# Import các module đã tách
from utils.fetcher import parse_local_file
from utils.api_client import ThreatAPIClient
from utils.config_helper import ConfigLoader
from utils.converter import StixConverter

# --- WORKER GLOBAL VARIABLES ---
worker_api_client = None
worker_asn_reader = None
worker_city_reader = None
worker_converter = None

def init_worker(abuse_key, grey_key, threatfox_key, asn_path, city_path, author_id):
    """Hàm khởi tạo tài nguyên cho mỗi tiến trình con (Worker)"""
    global worker_api_client, worker_asn_reader, worker_city_reader, worker_converter
    
    # Khởi tạo API Client
    worker_api_client = ThreatAPIClient(abuse_key, grey_key, threatfox_key)
    
    # Khởi tạo Converter
    worker_converter = StixConverter(author_id)
    
    # Mở kết nối GeoIP 
    if os.path.exists(asn_path):
        worker_asn_reader = geoip2.database.Reader(asn_path)
    if os.path.exists(city_path):
        worker_city_reader = geoip2.database.Reader(city_path)

def process_single_ip(ip):
    """Hàm xử lý logic cho 1 IP"""
    global worker_api_client, worker_asn_reader, worker_city_reader, worker_converter
    ip_clean = ip.split('/')[0]
    time.sleep(1)
    try:
        # Thu thập dữ liệu (Enrichment)
        abuse_data = worker_api_client.check_abuseipdb(ip_clean) or {}
        threatfox_data = worker_api_client.check_threatfox(ip_clean)
        
        # Lấy thông tin địa lý
        geo_info = {"isp": "Unknown", "loc": "Unknown"}
        if worker_asn_reader:
            try: geo_info["isp"] = worker_asn_reader.asn(ip_clean).autonomous_system_organization
            except: pass
        if worker_city_reader:
            try: 
                r = worker_city_reader.city(ip_clean)
                geo_info["loc"] = f"{r.city.name}, {r.country.name}"
            except: pass

        # Tính điểm và Chuyển đổi sang STIX
        score = abuse_data.get('score', 0)
        if threatfox_data:
            score = max(score, 95)

        # Gọi Converter để tạo objects
        return worker_converter.create_stix_bundle(
            ip=ip_clean,
            score=score,
            categories=abuse_data.get('categories', []),
            threatfox_data=threatfox_data,
            geo_info=geo_info
        )

    except Exception as e:
        print(f" [Error] IP {ip}: {e}")
        return []

# --- CLASS CHÍNH ---
class ProductionConnector:
    def __init__(self):
        # Load Config thông minh
        self.cfg = ConfigLoader(os.path.dirname(os.path.abspath(__file__)))
        
        self.file_path = self.cfg.get_path(self.cfg.get('custom_feed', 'file_path'))
        self.output_path = self.cfg.get_path(self.cfg.get('custom_feed', 'output_path'))
        
        # Load các tham số
        self.abuse_key = self.cfg.get('custom_feed', 'abuseipdb_key')
        self.grey_key = self.cfg.get('custom_feed', 'greynoise_key')
        self.threatfox_key = self.cfg.get('custom_feed', 'threatfox_key')
        self.asn_path = self.cfg.get_path(self.cfg.get('custom_feed', 'geoip_asn_path'))
        self.city_path = self.cfg.get_path(self.cfg.get('custom_feed', 'geoip_city_path'))
        
        interval_str = self.cfg.get('connector', 'exposure_time') or '1h'
        self.interval = int(interval_str.replace('h', '')) * 3600

        print(f"DEBUG: Input Config: {self.file_path}")

    def run(self):
        while True:
            print(f"\n[{datetime.now()}] Bắt đầu chu kỳ quét...")
            self.process_data()
            print(f"Ngủ {self.interval} giây...")
            time.sleep(self.interval)

    def process_data(self):
        start_time = time.time()
        
        # Tạo Identity cho nguồn tin
        author = stix2.Identity(
            name=self.cfg.get('connector', 'name'),
            identity_class="organization",
            description="Production Grade Connector"
        )

        # Đọc dữ liệu đầu vào
        _, raw_ips = parse_local_file(self.file_path)
        print(f"-> Tìm thấy {len(raw_ips)} IP.")
        
        raw_ips = raw_ips[:20] 

        all_objects = [author]
        max_workers = os.cpu_count() or 4
        
        # Chạy đa luồng
        with ProcessPoolExecutor(
            max_workers=max_workers,
            initializer=init_worker,
            initargs=(self.abuse_key, self.grey_key, self.threatfox_key, self.asn_path, self.city_path, author.id)
        ) as executor:
            results = list(executor.map(process_single_ip, raw_ips))
            for res in results:
                all_objects.extend(res)

        # Xuất file
        print(f"-> Đóng gói {len(all_objects)} STIX objects...")
        bundle = stix2.Bundle(objects=all_objects, allow_custom=True)
        bundle_data = json.loads(bundle.serialize())
        
        with open(self.output_path, 'w', encoding='utf-8') as f:
            json.dump(bundle_data, f, indent=4, ensure_ascii=False)
            
        print(f"-> Xong! Thời gian: {time.time() - start_time:.2f}s")

if __name__ == "__main__":
    try:
        connector = ProductionConnector()
        connector.run()
    except Exception as e:
        print(f"CRITICAL ERROR: {e}")