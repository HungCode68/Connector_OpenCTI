import logging
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

import stix2
from pycti import Indicator, Malware, ThreatActor

from .constants import ATTACK_PATTERN_MAPPING

logger = logging.getLogger(__name__)

class StixConverter:
    # Bảng dịch chuẩn xác các type mà OpenCTI hỗ trợ
    OBS_MAPPING = {
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

    def __init__(self, author_id: str):
        self.author_id = author_id

    def _generate_pattern(self, value: str, data_type: str) -> Optional[str]:
        """Tạo STIX Pattern dựa trên loại dữ liệu"""
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
            clean_val = value.lstrip('\\').replace('\\', '\\\\')
            prefix = "\\\\\\\\.\\\\pipe\\\\"
            if '*' in clean_val:
                return f"[file:name LIKE '{prefix}{clean_val.replace('*', '%')}']"
            return f"[file:name = '{prefix}{clean_val}']"
        elif data_type == 'mutex':
            clean_val = value.replace('\\', '\\\\')
            if '*' in clean_val:
                return f"[mutex:name LIKE '{clean_val.replace('*', '%')}']"
            return f"[mutex:name = '{clean_val}']"
        elif data_type == 'command-line':
            clean_val = value.replace('\\', '\\\\').replace("'", "\\'")
            if '*' in clean_val:
                return f"[process:command_line LIKE '{clean_val.replace('*', '%')}']"
            return f"[process:command_line LIKE '%{clean_val}%']"
            
        return None

    def _create_observable(self, value: str, data_type: str, score: int, context: Dict[str, Any]) -> Optional[Any]:
        """Khởi tạo Observable (Thực thể bị theo dõi)"""
        custom_props = {
            "x_opencti_score": score,
            "x_opencti_description": context.get('source_desc', '')
        }
        geo_info = context.get('geo_info', {})

        if data_type == 'named-pipe':
            return stix2.File(name=f"\\\\.\\pipe\\{value.lstrip('\\')}", custom_properties=custom_props)
        elif data_type == 'ip':
            loc_str = f"ISP: {geo_info.get('isp', 'Unknown')}. Loc: {geo_info.get('loc', 'Unknown')}"
            custom_props["x_opencti_description"] += f" | {loc_str}"
            return stix2.IPv4Address(value=value, custom_properties=custom_props)
        elif data_type == 'domain':
            return stix2.DomainName(value=value, custom_properties=custom_props)
        elif data_type == 'url':
            return stix2.URL(value=value, custom_properties=custom_props)
        elif data_type in ['sha256', 'md5']:
            hashes = {'SHA-256': value} if data_type == 'sha256' else {'MD5': value}
            return stix2.File(hashes=hashes, custom_properties=custom_props)
        elif data_type == 'filename':
            return stix2.File(name=value, custom_properties=custom_props)
        elif data_type == 'mutex':
            return stix2.Mutex(name=value, custom_properties=custom_props)
        elif data_type == 'command-line':
            return stix2.Process(command_line=value, custom_properties=custom_props)
            
        return None

    def _build_indicator_context(self, data_type: str, context: Dict[str, Any]) -> Tuple[str, List[str]]:
        """Gom nhóm Description và Tags từ các nguồn Enrichments"""
        tags = context.get('tags', [])
        desc_parts = [f"Source Description: {context.get('source_desc')}"]
        
        if data_type == 'ip':
            desc_parts.append(f"Abuse Score: {context.get('score', 0)}")
            geo = context.get('geo_info', {})
            if geo:
                desc_parts.append(f"ISP: {geo.get('isp')} | Loc: {geo.get('loc')}")
            categories = context.get('categories', [])
            if categories:
                desc_parts.append(f"Behaviors: {', '.join(categories)}")
                tags.extend([str(cat).lower().replace(" ", "-") for cat in categories])

        vt_data = context.get('vt_data')
        if vt_data:
            desc_parts.extend([
                f"VT Score: {vt_data.get('malicious_count')}",
                f"Product: {vt_data.get('product')}",
                f"Magic: {vt_data.get('magic')}"
            ])
            if vt_data.get('meaningful_name'):
                tags.append(f"filename:{vt_data['meaningful_name']}")

        domain_info = context.get('domain_info')
        if domain_info:
            desc_parts.extend([
                f"Registrar: {domain_info.get('registrar')}",
                f"Age: {domain_info.get('age_days')} days"
            ])

        threatfox_data = context.get('threatfox')
        if threatfox_data:
            desc_parts.append(f"ThreatFox Malware: {threatfox_data.get('malware')}")
            tags.append("threat-intelligence")
            tags.extend(threatfox_data.get('tags', []))

        return " | ".join(desc_parts), list(set(tags))

    def _process_attack_patterns(self, indicator_id: str, categories: List[str]) -> List[Any]:
        """Tạo MITRE Attack Patterns nếu có categories"""
        objects = []
        processed_patterns = set()
        
        for cat in categories:
            mapping = ATTACK_PATTERN_MAPPING.get(cat)
            if mapping and mapping["name"] not in processed_patterns:
                ap = stix2.AttackPattern(
                    id=mapping["id"],
                    name=mapping["name"],
                    description=mapping["description"],
                    external_references=[{
                        "source_name": "mitre-attack", 
                        "external_id": mapping["id"].split('--')[1]
                    }],
                    created_by_ref=self.author_id
                )
                rel = stix2.Relationship(
                    relationship_type="indicates",
                    source_ref=indicator_id,
                    target_ref=ap.id,
                    created_by_ref=self.author_id
                )
                objects.extend([ap, rel])
                processed_patterns.add(mapping["name"])
                
        return objects

    def _process_virustotal(self, indicator_id: str, value: str, vt_data: Dict[str, Any]) -> List[Any]:
        """Tạo Malware Object từ dữ liệu VirusTotal"""
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
        rel = stix2.Relationship(
            relationship_type="indicates",
            source_ref=indicator_id,
            target_ref=vt_malware_id,
            created_by_ref=self.author_id
        )
        return [malware, rel]

    def _process_domain_resolution(self, observable_id: Optional[str], domain_info: Dict[str, Any]) -> List[Any]:
        """Tạo liên kết giữa Domain và IP đã phân giải"""
        objects = []
        for rip in domain_info.get('resolved_ips', []):
            ip_obs = stix2.IPv4Address(value=rip)
            objects.append(ip_obs)
            if observable_id:
                rel = stix2.Relationship(
                    relationship_type="resolves-to",
                    source_ref=observable_id,
                    target_ref=ip_obs.id,
                    created_by_ref=self.author_id
                )
                objects.append(rel)
        return objects

    def _enrich_threatfox(self, indicator_id: str, data: Dict[str, Any]) -> List[Any]:
        """Tạo Malware Family & Threat Actor từ ThreatFox"""
        objects = []
        malware_name = data.get('malware')
        tags = data.get('tags', [])

        if malware_name:
            malware_id = Malware.generate_id(name=malware_name)
            malware = stix2.Malware(
                id=malware_id,
                name=malware_name,
                is_family=True,
                labels=tags,
                created_by_ref=self.author_id
            )
            rel_indicates = stix2.Relationship(
                relationship_type="indicates",
                source_ref=indicator_id,
                target_ref=malware_id,
                created_by_ref=self.author_id
            )
            objects.extend([malware, rel_indicates])
            
            potential_actors = [t for t in tags if "APT" in t.upper() or "GROUP" in t.upper()]
            for actor_name in potential_actors:
                actor_id = ThreatActor.generate_id(name=actor_name)
                actor = stix2.ThreatActor(
                    id=actor_id,
                    name=actor_name,
                    created_by_ref=self.author_id
                )
                rel_uses = stix2.Relationship(
                    relationship_type="uses",
                    source_ref=actor_id,
                    target_ref=malware_id,
                    created_by_ref=self.author_id
                )
                objects.extend([actor, rel_uses])
                
        return objects

    def create_stix_bundle(self, value: str, data_type: str, context: Dict[str, Any]) -> List[Any]:
        """Hàm chính: Điều phối việc tạo STIX Bundle từ các hàm Helper"""
        stix_objects = []
        score = context.get('score', 0)

        # Khởi tạo Observable
        observable = self._create_observable(value, data_type, score, context)
        if observable:
            stix_objects.append(observable)

        # Tạo Pattern (Nếu không có pattern thì bỏ qua indicator)
        pattern = self._generate_pattern(value, data_type)
        if not pattern:
            return stix_objects

        # Tạo Indicator
        description, tags = self._build_indicator_context(data_type, context)
        main_obs_type = self.OBS_MAPPING.get(data_type, "Unknown")
        indicator_id = Indicator.generate_id(pattern=pattern)
        
        indicator = stix2.Indicator(
            id=indicator_id,
            name=f"Malicious {data_type.upper()}: {value}",
            description=description,
            pattern=pattern,
            pattern_type="stix",
            valid_from=datetime.now(),
            labels=tags,
            created_by_ref=self.author_id,
            custom_properties={
                "x_opencti_score": score,
                "x_opencti_main_observable_type": main_obs_type
            }
        )
        stix_objects.append(indicator)

        # Liên kết Indicator với Observable
        if observable:
            stix_objects.append(stix2.Relationship(
                relationship_type="based-on",
                source_ref=indicator.id,
                target_ref=observable.id,
                created_by_ref=self.author_id
            ))

        # Các luồng làm giàu dữ liệu (Enrichments)
        categories = context.get('categories', [])
        if categories:
            stix_objects.extend(self._process_attack_patterns(indicator.id, categories))

        threatfox_data = context.get('threatfox')
        if threatfox_data:
            stix_objects.extend(self._enrich_threatfox(indicator.id, threatfox_data))

        vt_data = context.get('vt_data')
        if vt_data and vt_data.get('malicious_count', 0) > 3:
            stix_objects.extend(self._process_virustotal(indicator.id, value, vt_data))

        domain_info = context.get('domain_info')
        if domain_info:
            obs_id = observable.id if observable else None
            stix_objects.extend(self._process_domain_resolution(obs_id, domain_info))

        return stix_objects