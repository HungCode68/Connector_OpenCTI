import os
import yaml
import time
import json
import stix2
import geoip2.database
from datetime import datetime
from concurrent.futures import ProcessPoolExecutor

# Import logic cũ của bạn
from utils.fetcher import parse_local_file
from utils.api_client import ThreatAPIClient

# --- TỪ ĐIỂN MAPPING (AbuseIPDB -> MITRE ATT&CK) ---
ATTACK_PATTERN_MAPPING = {
    "SSH": {
        "name": "Brute Force: Password Guessing",
        "id": "attack-pattern--9dbf9f63-ea71-4d2c-9828-56455eb37d4d", # T1110.001
        "description": "Kẻ tấn công cố gắng đoán mật khẩu SSH để giành quyền truy cập."
    },
    "Brute-Force": {
        "name": "Brute Force",
        "id": "attack-pattern--f3c544dc-673c-4ef3-accb-53229f1ae077", # T1110
        "description": "Thực hiện tấn công dò mật khẩu (Brute-Force)."
    },
    "DDoS Attack": {
        "name": "Network Denial of Service",
        "id": "attack-pattern--c696e810-6366-4554-b4ce-35324d2627c2", # T1498
        "description": "Tấn công từ chối dịch vụ (DDoS) làm tê liệt hệ thống mạng."
    },
    "Port Scan": {
        "name": "Active Scanning: Scanning IP Blocks",
        "id": "attack-pattern--41865230-0714-4e36-9304-f584443015ec", # T1595.001
        "description": "Quét cổng để tìm kiếm các dịch vụ đang mở và điểm yếu."
    },
    "Web App Attack": {
        "name": "Exploit Public Facing Application",
        "id": "attack-pattern--3f886f2a-874f-4333-b794-60ef52956f27", # T1190
        "description": "Tấn công vào các lỗ hổng của ứng dụng web."
    },
    "SQL Injection": {
        "name": "Exploit Public Facing Application",
        "id": "attack-pattern--3f886f2a-874f-4333-b794-60ef52956f27",
        "description": "Tấn công tiêm nhiễm SQL (SQLi)."
    }
}

# --- HÀM HỖ TRỢ ĐỌC CONFIG ---
def get_config_variable(env_var, yaml_path, config):
    if os.getenv(env_var):
        return os.getenv(env_var)
    result = config
    for key in yaml_path:
        if result and key in result:
            result = result[key]
        else:
            return None
    return result

# --- WORKER FUNCTIONS ---
worker_api_client = None
worker_asn_reader = None
worker_city_reader = None
worker_author_id = None

def init_worker(abuse_key, grey_key, threatfox_key, asn_path, city_path, author_id):
    global worker_api_client, worker_asn_reader, worker_city_reader, worker_author_id
    worker_api_client = ThreatAPIClient(abuse_key, grey_key, threatfox_key)
    worker_author_id = author_id
    
    if os.path.exists(asn_path):
        worker_asn_reader = geoip2.database.Reader(asn_path)
    if os.path.exists(city_path):
        worker_city_reader = geoip2.database.Reader(city_path)

def process_single_ip(ip):
    global worker_api_client, worker_asn_reader, worker_city_reader, worker_author_id
    
    ip_clean = ip.split('/')[0]
    stix_objects = []
    
    try:
        # 1. Gọi API thu thập dữ liệu
        abuse_data = worker_api_client.check_abuseipdb(ip_clean) or {}
        score = abuse_data.get('score', 0)
        # Lấy danh sách hành vi (SSH, DDoS...) để map vào Attack Pattern và Labels
        categories = abuse_data.get('categories', [])
        
        threatfox_data = worker_api_client.check_threatfox(ip_clean)
        
        # Nếu ThreatFox phát hiện (Malware/Botnet), ưu tiên nâng điểm
        if threatfox_data:
            score = max(score, 95)

        # 2. Tra cứu GeoIP và ASN (Đã khôi phục)
        isp_name = "Unknown ISP"
        location_text = "Unknown Location"
        
        if worker_asn_reader:
            try:
                asn_res = worker_asn_reader.asn(ip_clean)
                isp_name = asn_res.autonomous_system_organization or "Unknown"
            except: pass
            
        if worker_city_reader:
            try:
                city_res = worker_city_reader.city(ip_clean)
                city = city_res.city.name
                country = city_res.country.name
                if city and country:
                    location_text = f"{city}, {country}"
                elif country:
                    location_text = country
            except: pass

        # --- A. CORE OBJECTS ---
        
        # Tạo Observable (Vật thể IP)
        observable = stix2.IPv4Address(
            value=ip_clean,
            custom_properties={
                "x_opencti_score": score,
                "x_opencti_description": f"ISP: {isp_name}. Location: {location_text}"
            }
        )
        stix_objects.append(observable)

        # Chuẩn bị thông tin cho Indicator
        desc_parts = [f"Abuse Score: {score}"]
        if isp_name != "Unknown ISP":
            desc_parts.append(f"ISP: {isp_name}")
        if location_text != "Unknown Location":
            desc_parts.append(f"Loc: {location_text}")
        if categories:
            desc_parts.append(f"Behaviors: {', '.join(categories)}")
            
        labels = ["malicious-activity"]
        # Thêm các hành vi vào Label (Ví dụ: SSH, Brute-Force) - Đã khôi phục
        labels.extend([cat.replace(" ", "-").lower() for cat in categories])
        
        if threatfox_data:
            malware_name = threatfox_data.get('malware', 'Unknown Malware')
            desc_parts.append(f"ThreatFox: {malware_name} ({threatfox_data.get('threat_type')})")
            labels.append("threat-intelligence-feed")
            if threatfox_data.get('tags'):
                labels.extend(threatfox_data.get('tags'))

        # Tạo Indicator (Cảnh báo)
        indicator = stix2.Indicator(
            name=f"Malicious IP: {ip_clean}",
            description=" | ".join(desc_parts),
            pattern=f"[ipv4-addr:value = '{ip_clean}']",
            pattern_type="stix",
            valid_from=datetime.now(),
            labels=list(set(labels)), # Loại bỏ label trùng lặp
            created_by_ref=worker_author_id,
            custom_properties={
                "x_opencti_score": score,
                "x_opencti_main_observable_type": "IPv4-Addr"
            }
        )
        stix_objects.append(indicator)
        
        # Mối quan hệ Indicator -> Observable
        stix_objects.append(stix2.Relationship(
            relationship_type="based-on", 
            source_ref=indicator.id, 
            target_ref=observable.id,
            created_by_ref=worker_author_id
        ))

        # --- B. ENRICHMENT: ATTACK PATTERNS (Đã khôi phục) ---
        # Duyệt qua các category từ AbuseIPDB để tạo Attack Pattern
        mapped_patterns = set()
        for cat in categories:
            if cat in ATTACK_PATTERN_MAPPING:
                mapping = ATTACK_PATTERN_MAPPING[cat]
                pattern_name = mapping["name"]
                
                # Tránh tạo trùng lặp trong cùng 1 bundle
                if pattern_name not in mapped_patterns:
                    attack_pattern = stix2.AttackPattern(
                        name=pattern_name,
                        description=mapping["description"],
                        external_references=[{
                            "source_name": "mitre-attack", 
                            "external_id": mapping["id"].split('--')[1]
                        }],
                        created_by_ref=worker_author_id
                    )
                    stix_objects.append(attack_pattern)
                    
                    # Indicator -> Indicates -> Attack Pattern
                    stix_objects.append(stix2.Relationship(
                        relationship_type="indicates",
                        source_ref=indicator.id,
                        target_ref=attack_pattern.id,
                        created_by_ref=worker_author_id
                    ))
                    mapped_patterns.add(pattern_name)

        # --- C. ENRICHMENT: THREATFOX (Giữ nguyên logic mới) ---
        if threatfox_data:
            malware_name = threatfox_data.get('malware')
            tags = threatfox_data.get('tags', [])
            
            if malware_name:
                malware = stix2.Malware(
                    name=malware_name,
                    is_family=True,
                    description=f"Phát hiện tại {ip_clean}. Loại: {threatfox_data.get('threat_type')}",
                    labels=tags,
                    created_by_ref=worker_author_id
                )
                stix_objects.append(malware)
                
                stix_objects.append(stix2.Relationship(
                    relationship_type="indicates",
                    source_ref=indicator.id,
                    target_ref=malware.id,
                    created_by_ref=worker_author_id
                ))
                
            # Suy luận Threat Actor từ tags
            potential_actors = [t for t in tags if "APT" in t.upper() or "GROUP" in t.upper() or "TA" in t.upper()]
            for actor_name in potential_actors:
                actor = stix2.ThreatActor(
                    name=actor_name,
                    threat_actor_types=["nation-state", "criminal"],
                    created_by_ref=worker_author_id
                )
                stix_objects.append(actor)
                
                stix_objects.append(stix2.Relationship(
                    relationship_type="attributed-to",
                    source_ref=indicator.id,
                    target_ref=actor.id,
                    created_by_ref=worker_author_id
                ))

        return stix_objects

    except Exception as e:
        print(f"Lỗi xử lý {ip_clean}: {e}")
        return []

# --- CLASS CONNECTOR CHÍNH ---
class OfflineThreatConnector:
    def __init__(self):
        self.src_dir = os.path.dirname(os.path.abspath(__file__))
        config_path = os.path.join(self.src_dir, "config.yml")

        if os.path.isfile(config_path):
            with open(config_path, 'r', encoding='utf-8') as f:
                self.config = yaml.load(f, Loader=yaml.FullLoader)
        else:
            raise Exception(f"Không tìm thấy file cấu hình tại: {config_path}")

        def resolve_path(relative_path):
            return os.path.normpath(os.path.join(self.src_dir, relative_path))

        cf = self.config.get('custom_feed', {})
        
        self.file_path = resolve_path(cf.get('file_path'))
        self.output_path = resolve_path(cf.get('output_path'))
        self.asn_path = resolve_path(cf.get('geoip_asn_path'))
        self.city_path = resolve_path(cf.get('geoip_city_path'))
        
        self.abuse_key = cf.get('abuseipdb_key')
        self.grey_key = cf.get('greynoise_key')
        self.threatfox_key = cf.get('threatfox_key')
        
        interval_str = self.config.get('connector', {}).get('exposure_time', '1h')
        self.interval = int(interval_str.replace('h', '')) * 3600

        print(f"DEBUG: Input: {self.file_path}")
        print(f"DEBUG: Output: {self.output_path}")

    def process_data(self):
        print(f"\n[{datetime.now()}] Bắt đầu xử lý dữ liệu...")
        start_time = time.time()

        author = stix2.Identity(
            name=self.config['connector']['name'],
            identity_class="organization",
            description="Offline Enrichment Connector"
        )

        _, raw_ips = parse_local_file(self.file_path)
        print(f"-> Tìm thấy {len(raw_ips)} IP.")
        
        raw_ips = raw_ips[:50] # Uncomment để test nhanh

        all_objects = [author]
        max_workers = os.cpu_count() or 4
        
        with ProcessPoolExecutor(
            max_workers=max_workers,
            initializer=init_worker,
            initargs=(self.abuse_key, self.grey_key, self.threatfox_key, self.asn_path, self.city_path, author.id)
        ) as executor:
            results = list(executor.map(process_single_ip, raw_ips))
            for res in results:
                all_objects.extend(res)

        print(f"-> Đóng gói {len(all_objects)} đối tượng...")
        bundle = stix2.Bundle(objects=all_objects, allow_custom=True)
        bundle_data = json.loads(bundle.serialize())
        
        with open(self.output_path, 'w', encoding='utf-8') as f:
           json.dump(bundle_data, f, indent=4, ensure_ascii=False)

        print(f"[{datetime.now()}] Hoàn tất! Thời gian: {time.time() - start_time:.2f}s")

    def run(self):
        while True:
            self.process_data()
            print(f"Ngủ {self.interval}s...")
            time.sleep(self.interval)

if __name__ == "__main__":
    try:
        connector = OfflineThreatConnector()
        connector.run()
    except Exception as e:
        print(f"CRITICAL ERROR: {e}")