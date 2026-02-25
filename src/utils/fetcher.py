import re
import os
import csv

def parse_generic_file(file_path, data_type):
    """
    Đọc file và bóc tách dữ liệu dựa trên data_type (ip, domain, sha256...)
    """
    valid_indicators = []
    metadata = {}
    
    if not os.path.exists(file_path):
        print(f" [!] File not found: {file_path}")
        return metadata, []

    # Regex patterns cho các loại dữ liệu
    patterns = {
        'ip': r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
        'sha256': r'\b[A-Fa-f0-9]{64}\b',
        'md5': r'\b[A-Fa-f0-9]{32}\b',
        'domain': r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}',
        'url': r'(https?:\/\/(?:www\.|(?!www))[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\.[^\s]{2,}|www\.[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\.[^\s]{2,}|https?:\/\/[^\s]+)',
        'user-agent': None,
        'filename': None,
        'named-pipe': None,
        'mutex': None,
        'command-line': None
    }

    regex = patterns.get(data_type)
    
    try:
        # Kiểm tra header CSV
        has_header = False
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            first_line = f.readline()
            if first_line and ',' in first_line and 'metadata_' in first_line:
                has_header = True

        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            # TRƯỜNG HỢP 1: File CSV giàu dữ liệu
            if has_header and not regex:
                reader = csv.DictReader(f)
                for row in reader:
                    if not reader.fieldnames: continue
                    key_col = reader.fieldnames[0]
                    if key_col in row and row[key_col]:
                        valid_indicators.append({
                            "value": row[key_col].strip(),
                            "meta": row
                        })

            # TRƯỜNG HỢP 2: File Text thường
            else:
                f.seek(0)
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'): continue
                    
                    val = None
                    if regex:
                        match = re.search(regex, line)
                        if match:
                            val = match.group(0).lower() if data_type != 'url' else match.group(0)
                    else:
                        val = line.split(',')[0].strip('"').strip("'")
                    
                    if val:
                        valid_indicators.append({"value": val})
                    
    except Exception as e:
        print(f" [!] Error reading {file_path}: {e}")
        
    # Khử trùng lặp thủ công cho danh sách Dictionary
    unique_indicators = []
    seen_values = set()
    
    for item in valid_indicators:
        val = item['value']
        if val not in seen_values:
            seen_values.add(val)
            unique_indicators.append(item)

    return metadata, unique_indicators