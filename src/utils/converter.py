import stix2
from datetime import datetime
from .constants import ATTACK_PATTERN_MAPPING

class StixConverter:
    def __init__(self, author_id):
        self.author_id = author_id

    def create_stix_bundle(self, ip, score, categories, threatfox_data, geo_info):
        stix_objects = []
        
        # Observable
        observable = stix2.IPv4Address(
            value=ip,
            custom_properties={
                "x_opencti_score": score,
                "x_opencti_description": f"ISP: {geo_info.get('isp')}. Location: {geo_info.get('loc')}"
            }
        )
        stix_objects.append(observable)

        # Chuẩn bị thông tin cho Indicator
        clean_labels = ["malicious-activity"]
        for cat in categories:
            # Chuyển label sang dạng lowercase 
            clean_labels.append(str(cat).lower().replace(" ", "-"))
        
        # Tạo description chi tiết 
        desc_parts = [
            f"Abuse Score: {score}",
            f"ISP: {geo_info.get('isp')}",
            f"Loc: {geo_info.get('loc')}"
        ]
        if categories:
            desc_parts.append(f"Behaviors: {', '.join(categories)}")
            
        if threatfox_data:
            desc_parts.append(f"Malware: {threatfox_data.get('malware')}")
            clean_labels.append("threat-intelligence")
            clean_labels.extend(threatfox_data.get('tags', []))

        # Tạo Indicator
        indicator = stix2.Indicator(
            name=f"Malicious IP: {ip}",
            description=" | ".join(desc_parts), # Ghép các phần bằng dấu gạch đứng
            pattern=f"[ipv4-addr:value = '{ip}']",
            pattern_type="stix",
            valid_from=datetime.now(),
            labels=list(set(clean_labels)),
            created_by_ref=self.author_id,
            custom_properties={
                "x_opencti_score": score, 
                "x_opencti_main_observable_type": "IPv4-Addr"
            }
        )
        stix_objects.append(indicator)

        #  Relationship: Indicator -> Observable
        stix_objects.append(stix2.Relationship(
            relationship_type="based-on",
            source_ref=indicator.id,
            target_ref=observable.id,
            created_by_ref=self.author_id
        ))

        #  Attack Patterns 
        processed_patterns = set()
        for cat in categories:
            # Kiểm tra mapping 
            if cat in ATTACK_PATTERN_MAPPING:
                mapping = ATTACK_PATTERN_MAPPING[cat]
                pat_name = mapping["name"]
                
                if pat_name not in processed_patterns:
                    ap = stix2.AttackPattern(
                        name=pat_name,
                        description=mapping["description"],
                        external_references=[{
                            "source_name": "mitre-attack", 
                            "external_id": mapping["id"].split('--')[1]
                        }],
                        created_by_ref=self.author_id
                    )
                    stix_objects.append(ap)
                    
                    # Tạo quan hệ: Indicator -> indicates -> Attack Pattern
                    stix_objects.append(stix2.Relationship(
                        relationship_type="indicates",
                        source_ref=indicator.id,
                        target_ref=ap.id,
                        created_by_ref=self.author_id
                    ))
                    processed_patterns.add(pat_name)

        #  ThreatFox Data
        if threatfox_data:
            self._enrich_threatfox(stix_objects, indicator, threatfox_data)

        return stix_objects

    def _enrich_threatfox(self, objects_list, indicator, data):
        malware_name = data.get('malware')
        tags = data.get('tags', [])

        if malware_name:
            malware = stix2.Malware(
                name=malware_name,
                is_family=True,
                labels=tags,
                created_by_ref=self.author_id
            )
            objects_list.append(malware)
            objects_list.append(stix2.Relationship(
                relationship_type="indicates",
                source_ref=indicator.id,
                target_ref=malware.id,
                created_by_ref=self.author_id
            ))
            
            potential_actors = [t for t in tags if "APT" in t.upper() or "GROUP" in t.upper()]
            for actor_name in potential_actors:
                actor = stix2.ThreatActor(
                    name=actor_name,
                    created_by_ref=self.author_id
                )
                objects_list.append(actor)
                objects_list.append(stix2.Relationship(
                    relationship_type="uses",
                    source_ref=actor.id,
                    target_ref=malware.id,
                    created_by_ref=self.author_id
                ))