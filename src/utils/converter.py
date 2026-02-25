import stix2
import uuid
from datetime import datetime
from .constants import ATTACK_PATTERN_MAPPING
from pycti import Malware, ThreatActor, Indicator

class StixConverter:
    def __init__(self, author_id):
        self.author_id = author_id

    def _generate_pattern(self, value, data_type):
        """Helper tạo STIX Pattern dựa trên loại dữ liệu"""
        value = value.strip()
        if data_type == 'ip':
            return f"[ipv4-addr:value = '{value}']"
        elif data_type == 'domain':
            return f"[domain-name:value = '{value}']"
        elif data_type == 'sha256':
            return f"[file:hashes.'SHA-256' = '{value}']"
        elif data_type == 'md5':
            return f"[file:hashes.MD5 = '{value}']"
        elif data_type == 'url':
            return f"[url:value = '{value}']"
        elif data_type == 'user-agent':
            return f"[network-traffic:extensions.'http-request-ext'.request_header.'User-Agent' = '{value}']"
        elif data_type == 'filename':
            return f"[file:name = '{value}']"
        elif data_type == 'named-pipe':
            clean_val = value.lstrip('\\')
            
            # Escape dấu \ thành \\ cho STIX Pattern
            # Ví dụ: pipe\name -> pipe\\name
            clean_val = clean_val.replace('\\', '\\\\')
            
            # Định nghĩa Prefix chuẩn Windows: \\.\pipe\
            # Trong STIX Pattern string, nó phải là: \\\\.\\\\pipe\\\\
            prefix = "\\\\\\\\.\\\\pipe\\\\"

            if '*' in clean_val:
                # Dùng LIKE cho wildcard, đổi * thành %
                val_wildcard = clean_val.replace('*', '%')
                return f"[file:name LIKE '{prefix}{val_wildcard}']"
            else:
                # Dùng = cho so sánh chính xác
                return f"[file:name = '{prefix}{clean_val}']"
            
        elif data_type == 'mutex':
            # Escape dấu backslash \ thành \\ để không bị lỗi cú pháp STIX
            clean_val = value.replace('\\', '\\\\')
            
            # Xử lý Wildcard (*) giống như Named Pipe và Filename
            if '*' in clean_val:
                val_wildcard = clean_val.replace('*', '%')
                return f"[mutex:name LIKE '{val_wildcard}']"
            else:
                return f"[mutex:name = '{clean_val}']"
            
        elif data_type == 'command-line':
            clean_val = value.replace('\\', '\\\\')
            clean_val = clean_val.replace("'", "\\'")
            if '*' in clean_val:
                val_wildcard = clean_val.replace('*', '%')
                return f"[process:command_line LIKE '{val_wildcard}']"
            else:
                return f"[process:command_line LIKE '%{clean_val}%']"
        return None

    def create_stix_bundle(self, value, data_type, context):
        """
        Hàm tạo STIX Bundle tổng quát.
        context bao gồm: score, tags, categories, threatfox, vt_data, domain_info, geo_info...
        """
        stix_objects = []
        
        # Lấy dữ liệu từ context
        score = context.get('score', 0)
        tags = context.get('tags', [])
        categories = context.get('categories', []) # Chỉ có nếu là IP
        threatfox_data = context.get('threatfox')
        vt_data = context.get('vt_data') # Chỉ có nếu là Hash
        domain_info = context.get('domain_info') # Chỉ có nếu là Domain
        geo_info = context.get('geo_info', {})

        # TẠO OBSERVABLE (SỰ VẬT)
        observable = None
        custom_props = {
            "x_opencti_score": score,
            "x_opencti_description": context.get('source_desc', '')
        }

        if data_type == 'named-pipe':
            pipe_val_clean = value.lstrip('\\')
            full_pipe_name = f"\\\\.\\pipe\\{pipe_val_clean}"
            observable = stix2.File(name=full_pipe_name, custom_properties=custom_props)

        elif data_type == 'ip':
            # Thêm thông tin địa lý vào description của observable
            loc_str = f"ISP: {geo_info.get('isp', 'Unknown')}. Loc: {geo_info.get('loc', 'Unknown')}"
            custom_props["x_opencti_description"] += f" | {loc_str}"
            observable = stix2.IPv4Address(value=value, custom_properties=custom_props)
            
        elif data_type == 'domain':
            observable = stix2.DomainName(value=value, custom_properties=custom_props)

        elif data_type == 'url':
            observable = stix2.URL(value=value, custom_properties=custom_props)
            
        elif data_type in ['sha256', 'md5']:
            hashes = {'SHA-256': value} if data_type == 'sha256' else {'MD5': value}
            observable = stix2.File(hashes=hashes, custom_properties=custom_props)

        elif data_type == 'filename':
            observable = stix2.File(name=value, custom_properties=custom_props)

        elif data_type == 'mutex':
            observable = stix2.Mutex(name=value, custom_properties=custom_props)

        elif data_type == 'command-line':
            observable = stix2.Process(command_line=value, custom_properties=custom_props)

        if observable:
            stix_objects.append(observable)

        # CHUẨN BỊ DESCRIPTION & LABELS CHO INDICATOR
        desc_parts = [f"Source Description: {context.get('source_desc')}"]
        
        # -- Logic cho IP --
        if data_type == 'ip':
            desc_parts.append(f"Abuse Score: {score}")
            if geo_info:
                desc_parts.append(f"ISP: {geo_info.get('isp')} | Loc: {geo_info.get('loc')}")
            if categories:
                desc_parts.append(f"Behaviors: {', '.join(categories)}")
                for cat in categories:
                    tags.append(str(cat).lower().replace(" ", "-"))

        # -- Logic cho Hash (VirusTotal) --
        if vt_data:
            desc_parts.append(f"VT Score: {vt_data.get('malicious_count')}")
            desc_parts.append(f"Product: {vt_data.get('product')}")
            desc_parts.append(f"Magic: {vt_data.get('magic')}")
            if vt_data.get('meaningful_name'):
                tags.append(f"filename:{vt_data['meaningful_name']}")

        # -- Logic cho Domain (Whois) --
        if domain_info:
            desc_parts.append(f"Registrar: {domain_info.get('registrar')}")
            desc_parts.append(f"Age: {domain_info.get('age_days')} days")

        # -- Logic ThreatFox (Chung) --
        if threatfox_data:
            desc_parts.append(f"ThreatFox Malware: {threatfox_data.get('malware')}")
            tags.append("threat-intelligence")
            tags.extend(threatfox_data.get('tags', []))

        # TẠO INDICATOR
        pattern = self._generate_pattern(value, data_type)
        if pattern:
            obs_mapping = {
                'ip': 'IPv4-Addr',
                'domain': 'Domain-Name',
                'url': 'URL',
                'sha256': 'StixFile',
                'md5': 'StixFile',
                'filename': 'StixFile',
                'named-pipe': 'StixFile',
                'mutex': 'Mutex',
                'command-line': 'Process',
                'user-agent': 'Network-Traffic'
            }
            main_obs_type = obs_mapping.get(data_type, "Unknown")
            indicator_id = Indicator.generate_id(pattern=pattern)
            indicator = stix2.Indicator(
                id=indicator_id,
                name=f"Malicious {data_type.upper()}: {value}",
                description=" | ".join(desc_parts),
                pattern=pattern,
                pattern_type="stix",
                valid_from=datetime.now(),
                labels=list(set(tags)), # Deduplicate tags
                created_by_ref=self.author_id,
                custom_properties={
                    "x_opencti_score": score,
                    "x_opencti_main_observable_type": main_obs_type
                }
            )
            stix_objects.append(indicator)

            # Link Indicator -> Observable
            if observable:
                stix_objects.append(stix2.Relationship(
                    relationship_type="based-on",
                    source_ref=indicator.id,
                    target_ref=observable.id,
                    created_by_ref=self.author_id
                ))

            # XỬ LÝ ATTACK PATTERNS (Chỉ áp dụng nếu có categories)
            if categories:
                processed_patterns = set()
                for cat in categories:
                    if cat in ATTACK_PATTERN_MAPPING:
                        mapping = ATTACK_PATTERN_MAPPING[cat]
                        pat_name = mapping["name"]
                        
                        if pat_name not in processed_patterns:
                            ap = stix2.AttackPattern(
                                id=mapping["id"],
                                name=pat_name,
                                description=mapping["description"],
                                external_references=[{
                                    "source_name": "mitre-attack", 
                                    "external_id": mapping["id"].split('--')[1]
                                }],
                                created_by_ref=self.author_id
                            )
                            # Lưu ý: STIX2 lib tự handle việc trùng ID nếu object giống nhau
                            stix_objects.append(ap)
                            
                            stix_objects.append(stix2.Relationship(
                                relationship_type="indicates",
                                source_ref=indicator.id,
                                target_ref=ap.id,
                                created_by_ref=self.author_id
                            ))
                            processed_patterns.add(pat_name)

            # XỬ LÝ THREATFOX ENRICHMENT 
            if threatfox_data:
                self._enrich_threatfox(stix_objects, indicator, threatfox_data)

            # XỬ LÝ VIRUSTOTAL MALWARE (Tạo Malware Object từ Hash)
            if vt_data and vt_data.get('malicious_count', 0) > 3:
                malware_name = vt_data.get('meaningful_name') or f"Unknown Binary ({value[:8]})"
                vt_malware_id = Malware.generate_id(name=malware_name)
                malware = stix2.Malware(
                    id=vt_malware_id,
                    name=malware_name,
                    is_family=False,
                    description=f"VT Identification. Product: {vt_data.get('product')}",
                    labels=vt_data.get('tags', []),
                    created_by_ref=self.author_id
                )
                stix_objects.append(malware)
                stix_objects.append(stix2.Relationship(
                    relationship_type="indicates",
                    source_ref=indicator.id,
                    target_ref=vt_malware_id,
                    created_by_ref=self.author_id
                ))

            # XỬ LÝ DOMAIN RESOLUTION (Mới - Link Domain -> IP)
            if domain_info and domain_info.get('resolved_ips'):
                for rip in domain_info['resolved_ips']:
                    ip_obs = stix2.IPv4Address(value=rip)
                    stix_objects.append(ip_obs)
                    # Quan hệ Domain (Observable) resolves-to IP
                    if observable: 
                        stix_objects.append(stix2.Relationship(
                            relationship_type="resolves-to",
                            source_ref=observable.id,
                            target_ref=ip_obs.id,
                            created_by_ref=self.author_id
                        ))

        return stix_objects

    def _enrich_threatfox(self, objects_list, indicator, data):
        """Logic xử lý ThreatFox của bạn: Tạo Malware Family & Threat Actor"""
        malware_name = data.get('malware')
        tags = data.get('tags', [])

        if malware_name:
            malware_id = Malware.generate_id(name=malware_name)
            # Tạo Malware Object
            malware = stix2.Malware(
                id=malware_id,
                name=malware_name,
                is_family=True, # ThreatFox thường trả về tên dòng họ mã độc
                labels=tags,
                created_by_ref=self.author_id
            )
            objects_list.append(malware)
            
            # Indicator -> indicates -> Malware
            objects_list.append(stix2.Relationship(
                relationship_type="indicates",
                source_ref=indicator.id,
                target_ref=malware_id,
                created_by_ref=self.author_id
            ))
            
            # Tìm kiếm tên Threat Actor trong tags
            potential_actors = [t for t in tags if "APT" in t.upper() or "GROUP" in t.upper()]
            for actor_name in potential_actors:
                actor_id = ThreatActor.generate_id(name=actor_name)
                actor = stix2.ThreatActor(
                    id=actor_id,
                    name=actor_name,
                    created_by_ref=self.author_id
                )
                objects_list.append(actor)
                
                # Actor -> uses -> Malware
                objects_list.append(stix2.Relationship(
                    relationship_type="uses",
                    source_ref=actor_id,
                    target_ref=malware_id,
                    created_by_ref=self.author_id
                ))