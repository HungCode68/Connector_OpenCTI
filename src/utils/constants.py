# --- MAPPING SANG STIX/MITRE ATT&CK ---
ATTACK_PATTERN_MAPPING = {
    "SSH": {
        "name": "Brute Force: Password Guessing",
        "id": "attack-pattern--9dbf9f63-ea71-4d2c-9828-56455eb37d4d",
        "description": "Kẻ tấn công cố gắng đoán mật khẩu SSH."
    },
    "FTP Brute-Force": {
        "name": "Brute Force: Password Guessing",
        "id": "attack-pattern--9dbf9f63-ea71-4d2c-9828-56455eb37d4d",
        "description": "Tấn công dò mật khẩu FTP."
    },
    "Brute-Force": {
        "name": "Brute Force",
        "id": "attack-pattern--f3c544dc-673c-4ef3-accb-53229f1ae077",
        "description": "Thực hiện tấn công dò mật khẩu."
    },
    "DDoS Attack": {
        "name": "Network Denial of Service",
        "id": "attack-pattern--c696e810-6366-4554-b4ce-35324d2627c2",
        "description": "Tấn công từ chối dịch vụ (DDoS)."
    },
    "Port Scan": {
        "name": "Active Scanning: Scanning IP Blocks",
        "id": "attack-pattern--41865230-0714-4e36-9304-f584443015ec",
        "description": "Quét cổng để tìm kiếm các dịch vụ đang mở."
    },
    "Web App Attack": {
        "name": "Exploit Public Facing Application",
        "id": "attack-pattern--3f886f2a-874f-4333-b794-60ef52956f27",
        "description": "Tấn công vào các lỗ hổng của ứng dụng web."
    },
    "SQL Injection": {
        "name": "Exploit Public Facing Application",
        "id": "attack-pattern--3f886f2a-874f-4333-b794-60ef52956f27",
        "description": "Tấn công tiêm nhiễm SQL."
    },
    "Hacking": {
        "name": "Exploitation",
        "id": "attack-pattern--be29737e-61e3-48c9-8d2b-4d92418e977f",
        "description": "Hành vi tấn công xâm nhập hệ thống trái phép."
    },
    "IoT Targeted": {
        "name": "Exploit Public Facing Application", 
        "id": "attack-pattern--3f886f2a-874f-4333-b794-60ef52956f27",
        "description": "Tấn công nhắm vào thiết bị IoT."
    },
    "Exploited Host": {
        "name": "Compromise Infrastructure",
        "id": "attack-pattern--86f04b6a-8e78-46ca-98a9-bc32e683c2b1",
        "description": "Máy chủ đã bị xâm nhập và lợi dụng."
    }
}