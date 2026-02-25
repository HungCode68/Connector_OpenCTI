from multiprocessing import context
import os
import time
import json
from pycti import OpenCTIApiClient
from pycti import OpenCTIApiClient
import stix2
import geoip2.database
from datetime import datetime
from concurrent.futures import ProcessPoolExecutor

from utils.fetcher import parse_generic_file
from utils.api_client import ThreatAPIClient
from utils.config_helper import ConfigLoader
from utils.converter import StixConverter

from dotenv import load_dotenv
load_dotenv()

# --- WORKER GLOBAL VARIABLES ---
# Các biến này sẽ được khởi tạo riêng cho từng tiến trình con để tránh xung đột
worker_api_client = None
worker_asn_reader = None
worker_city_reader = None
worker_converter = None

def init_worker(keys, paths, author_id):
    """
    Hàm khởi tạo tài nguyên cho mỗi Worker.
    keys: Dict chứa API keys
    paths: Dict chứa đường dẫn GeoIP
    """
    global worker_api_client, worker_asn_reader, worker_city_reader, worker_converter
    
    # Khởi tạo API Client với đầy đủ key
    worker_api_client = ThreatAPIClient(
        abuse_key=keys.get('abuseipdb'),
        grey_key=keys.get('greynoise'),
        threatfox_key=keys.get('threatfox'),
        vt_key=keys.get('virustotal')
    )
    
    # Khởi tạo Converter
    worker_converter = StixConverter(author_id)
    
    # Mở kết nối GeoIP
    if paths.get('asn') and os.path.exists(paths['asn']):
        worker_asn_reader = geoip2.database.Reader(paths['asn'])
    if paths.get('city') and os.path.exists(paths['city']):
        worker_city_reader = geoip2.database.Reader(paths['city'])

def process_indicator(task_data):
    """
    Hàm xử lý logic cho 1 Indicator (IP, Hash, hoặc Domain).
    task_data bao gồm: (value, data_type, tags, source_desc)
    """
    item_obj = task_data['item']
    dtype = task_data['dtype']
    value = item_obj.get('value')
    csv_meta = item_obj.get('meta', {})
    global worker_api_client, worker_asn_reader, worker_city_reader, worker_converter
    
    # Chuẩn bị context dữ liệu để làm giàu
    context = {
        "score": 0,
        "tags": task_data['tags'].copy(),
        "source_desc": task_data['desc'],
        "categories": [],    # Dành cho AbuseIPDB categories
        "vt_data": None,     # Dành cho VirusTotal
        "domain_info": None, # Dành cho Domain Whois
        "threatfox": None,   # Dành cho ThreatFox
        "geo_info": {"isp": "Unknown", "loc": "Unknown"}
    }

    try:
        if csv_meta:
            # Xử lý Severity -> Score
            severity = csv_meta.get('metadata_severity', 'medium').lower()
            if severity == 'high': context['score'] = 90
            elif severity == 'medium': context['score'] = 60
            elif severity == 'low': context['score'] = 30

            severity_score = csv_meta.get('metadata_severity_score')
            if severity_score:
                try:
                    # Chuyển điểm từ thang 10 sang thang 100
                    context['score'] = int(float(severity_score) * 10)
                except ValueError:
                    pass
            
            # Bổ sung Tags từ Category
            if csv_meta.get('metadata_category'):
                context['tags'].append(csv_meta['metadata_category'].replace(" ", "-").lower())
                
            # Làm giàu Description
            extra_info = []
            if csv_meta.get('metadata_tool'): extra_info.append(f"Tool: {csv_meta['metadata_tool']}")
            if csv_meta.get('metadata_description'): extra_info.append(f"Desc: {csv_meta['metadata_description']}")
            if csv_meta.get('metadata_link'): extra_info.append(f"Ref: {csv_meta['metadata_link']}")
            
            if extra_info:
                context['source_desc'] += " | " + " | ".join(extra_info)

        # --- XỬ LÝ IP ---
        if dtype == 'ip':
            # Gọi AbuseIPDB
            abuse_res = worker_api_client.check_abuseipdb(value)
            if abuse_res:
                context['score'] = max(context['score'], abuse_res.get('score', 0))
                context['categories'] = abuse_res.get('categories', [])
                
                # Logic GeoIP Local (Ưu tiên local hơn API để tiết kiệm quota)
                if worker_asn_reader:
                    try: context["geo_info"]["isp"] = worker_asn_reader.asn(value).autonomous_system_organization
                    except: pass
                if worker_city_reader:
                    try: 
                        r = worker_city_reader.city(value)
                        context["geo_info"]["loc"] = f"{r.city.name}, {r.country.name}"
                    except: pass
            
            # Gọi GreyNoise (Optional)
            # gn_res = worker_api_client.check_greynoise(value)

        # --- XỬ LÝ HASH (SHA256/MD5) ---
        elif dtype in ['sha256', 'md5']:
            vt_res = worker_api_client.check_virustotal_hash(value)
            if vt_res:
                context['vt_data'] = vt_res
                # Nếu > 2 engine phát hiện thì tăng điểm cao
                if vt_res.get('malicious_count', 0) > 2:
                    context['score'] = max(context['score'], 85)

        # --- XỬ LÝ DOMAIN ---
        elif dtype == 'domain':
            dom_res = worker_api_client.check_domain_info(value)
            context['domain_info'] = dom_res
            # Nếu domain mới tạo < 30 ngày -> Đáng ngờ
            age = dom_res.get('age_days')
            if age is not None and age < 30:
                context['score'] = 70
                context['tags'].append("newly-registered-domain")
            elif age is None:
            # (Tùy chọn) Nếu không lấy được tuổi, có thể coi là đáng ngờ nhẹ hoặc bỏ qua
                context['source_desc'] += " | Whois Lookup Failed"

        # URL XỬ LÝ URL ---
        elif dtype == 'url':
            vt = worker_api_client.check_virustotal_url(value)
            if vt:
                context['vt_data'] = vt
                if vt.get('malicious_count', 0) > 2: context['score'] = 80
        
        # USER-AGENT / FILENAME / NAMED-PIPE 
        elif dtype in ['user-agent', 'filename', 'named-pipe']:
            # Chỉ gán điểm mặc định nếu chưa có điểm (từ metadata)
            if context['score'] == 0:
                context['score'] = 60

        # --- THREATFOX (Kiểm tra chéo cho tất cả các loại) ---
        tf_res = worker_api_client.check_threatfox(value)
        if tf_res:
            context['threatfox'] = tf_res
            context['score'] = max(context['score'], 95) # ThreatFox độ tin cậy rất cao

        # --- CHUYỂN ĐỔI SANG STIX ---
        # Hàm create_stix_bundle mới đã hỗ trợ nhận context tổng quát
        return worker_converter.create_stix_bundle(value, dtype, context)

    except Exception as e:
        print(f" [Error] {dtype} {value}: {e}") # Uncomment để debug
        return []

# --- CLASS CHÍNH ---
class ProductionConnector:

    def download_latest_feeds(self):
        """Tải dữ liệu mới nhất từ URL trong config.yml trước khi xử lý"""
        import requests
        print(">>> 🔄 ĐANG TẢI DỮ LIỆU MỚI NHẤT...")
        # Đảm bảo thư mục data tồn tại
        os.makedirs(self.cfg.get_path('../data'), exist_ok=True)
        
        for feed in self.feeds:
            url = feed.get('url')
            file_path = self.cfg.get_path(feed['path'])
            if url:
                try:
                    print(f" -> Đang tải: {url}")
                    response = requests.get(url, timeout=30)
                    response.raise_for_status()
                    with open(file_path, 'wb') as f:
                        f.write(response.content)
                except Exception as e:
                    print(f"    [!] Lỗi tải {url}: {e}")


    def __init__(self):
        # Load Config
        self.cfg = ConfigLoader(os.path.dirname(os.path.abspath(__file__)))
        
        # Load Keys & Paths
        self.keys = {
            'abuseipdb': self.cfg.get('keys', 'abuseipdb'),
            'greynoise': self.cfg.get('keys', 'greynoise'),
            'threatfox': self.cfg.get('keys', 'threatfox'),
            'virustotal': self.cfg.get('keys', 'virustotal')
        }
        
        self.paths = {
            'asn': self.cfg.get_path(self.cfg.get('keys', 'geoip_asn_path')),
            'city': self.cfg.get_path(self.cfg.get('keys', 'geoip_city_path'))
        }

        # Load danh sách nguồn dữ liệu (Feeds)
        self.feeds = self.cfg.get('feeds', default=[])
        
        # Load Output Path
        self.output_path = self.cfg.get_path(self.cfg.get('output', 'path'))
        
        # Cấu hình thời gian chạy định kỳ
        interval_str = self.cfg.get('connector', 'exposure_time') or '1h'
        try:
            self.interval = int(interval_str.replace('h', '')) * 3600
        except:
            self.interval = 3600 # Mặc định 1 giờ

    def run(self):
        self.download_latest_feeds()
        print(f"[*] Connector khởi động với {len(self.feeds)} nguồn dữ liệu.")
        print(f"\n[{datetime.now()}] >>> Bắt đầu chu kỳ quét...")
        self.process_data()
        print(f"[{datetime.now()}] >>> Hoàn thành chu kỳ chạy!")

    def process_data(self):
        start_time = time.time()
        
        # Tạo Identity
        author = stix2.Identity(
            name=self.cfg.get('connector', 'name'),
            identity_class="organization",
            description="Automated Threat Intelligence Connector"
        )
        
        all_objects = [author]
        all_tasks = []

        # GOM DỮ LIỆU TỪ TẤT CẢ CÁC NGUỒN
        for feed in self.feeds:
            f_path = self.cfg.get_path(feed['path'])
            f_type = feed['type']
            
            # Bỏ qua nếu cấu hình sai path
            if not f_path: continue
                
            print(f" -> Đang đọc nguồn: {os.path.basename(f_path)} ({f_type})...")
            
            # Sử dụng parse_generic_file thay vì parse_local_file cũ
            _, items = parse_generic_file(f_path, f_type)
            
            # (Tùy chọn) Giới hạn số lượng items mỗi feed để test
            items = items[:50] 
            
            for item in items:
                # Đóng gói task để gửi cho Worker
                all_tasks.append({
                    "item": item,
                    "dtype": f_type,
                    "tags": feed['tags'],
                    "desc": feed['description']
                })

        print(f" -> Tổng cộng: {len(all_tasks)} indicators cần xử lý.")
        if len(all_tasks) == 0:
            print(" [!] CẢNH BÁO: Không tìm thấy dữ liệu nào! Kiểm tra lại đường dẫn file CSV trong config.yml")

        # XỬ LÝ ĐA LUỒNG
        max_workers = os.cpu_count() or 4
        with ProcessPoolExecutor(
            max_workers=max_workers,
            initializer=init_worker,
            initargs=(self.keys, self.paths, author.id)
        ) as executor:
            # map sẽ trả về list các list STIX objects
            results = list(executor.map(process_indicator, all_tasks))
            
            for res in results:
                all_objects.extend(res)

        # XUẤT FILE JSON
        print(f" -> Đang đóng gói {len(all_objects)} STIX objects...")
        bundle = stix2.Bundle(objects=all_objects, allow_custom=True)
        bundle_json = bundle.serialize()
        
        #  Vẫn lưu file local để backup
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        backup_filename = f"backup_bundle_{timestamp}.json"
        
        try:
            with open(backup_filename, "w", encoding="utf-8") as f:
                f.write(bundle_json)
            print(f" 💾 Đã lưu file backup local tại: {backup_filename}")
        except Exception as e:
            print(f" [!] Lỗi lưu file backup: {e}")

        # ĐẨY DỮ LIỆU LÊN OPENCTI
        opencti_url = os.getenv('OPENCTI_URL') or self.cfg.get('opencti', 'url')
        opencti_token = os.getenv('OPENCTI_TOKEN') or self.cfg.get('opencti', 'token')

        if opencti_url and opencti_token:
            print(f" -> 🚀 Đang kết nối tới OpenCTI: {opencti_url}")
            try:
                # Khởi tạo Client
                client = OpenCTIApiClient(opencti_url, opencti_token)
                
                # Chuyển đổi từ String sang Dictionary trước khi upload
                bundle_dict = json.loads(bundle_json) 
                
                print(" -> 📡 Đang đẩy dữ liệu lên hệ thống... Vui lòng chờ...")
                
                # Gửi Dictionary vào thay vì gửi String
                client.stix2.import_bundle(bundle_dict) 

                print(" ✅ THÀNH CÔNG! Dữ liệu đã được cập nhật lên OpenCTI.")
            except Exception as e:
                print(f" ❌ LỖI UPLOAD OPENCTI: {e}")
                # In chi tiết lỗi để debug nếu cần
                import traceback
                traceback.print_exc()
        else:
            print(" [!] Bỏ qua bước upload vì chưa cấu hình 'opencti' trong config.yml")
            
        end_time = time.time()
        print(f"=== Hoàn thành trong {round(end_time - start_time, 2)} giây ===")

if __name__ == "__main__":
    try:
        connector = ProductionConnector()
        connector.run()
    except Exception as e:
        print(f"CRITICAL ERROR: {e}")