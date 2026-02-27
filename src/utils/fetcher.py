import csv
import logging
import os
import re
from typing import Any, Dict, List, Tuple

# Khởi tạo logger
logger = logging.getLogger(__name__)

# Đưa regex patterns lên làm hằng số (Constants) để không khởi tạo lại nhiều lần
REGEX_PATTERNS = {
    'ip': r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
    'sha256': r'\b[A-Fa-f0-9]{64}\b',
    'md5': r'\b[A-Fa-f0-9]{32}\b',
    'domain': r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}',
    'url': r'(https?:\/\/(?:www\.|(?!www))[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\.[^\s]{2,}|www\.[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\.[^\s]{2,}|https?:\/\/(?:www\.|(?!www))[a-zA-Z0-9]+\.[^\s]{2,}|www\.[a-zA-Z0-9]+\.[^\s]{2,})'
}

def parse_generic_file(file_path: str, data_type: str) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """
    Đọc file và bóc tách dữ liệu dựa trên data_type (ip, domain, sha256...).
    Hỗ trợ cả file CSV (có metadata) và file Text thường.
    """
    valid_indicators: List[Dict[str, Any]] = []
    metadata: Dict[str, Any] = {}
    
    if not os.path.exists(file_path):
        logger.warning(f"Không tìm thấy file dữ liệu: {file_path}")
        return metadata, []

    regex = REGEX_PATTERNS.get(data_type)
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            # Kiểm tra nhanh xem có phải file CSV có header chuẩn không
            header = f.readline()
            is_csv = 'metadata_' in header or ',' in header
            f.seek(0)

            # TRƯỜNG HỢP 1: File CSV
            if is_csv and data_type != 'command-line':
                reader = csv.DictReader(f)
                for row in reader:
                    if not reader.fieldnames: 
                        continue
                        
                    key_col = reader.fieldnames[0]
                    if key_col in row and row[key_col]:
                        valid_indicators.append({
                            "value": row[key_col].strip(),
                            "meta": row
                        })

            # TRƯỜNG HỢP 2: File Text thường
            else:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'): 
                        continue
                    
                    val = None
                    if regex:
                        match = re.search(regex, line)
                        if match:
                            val = match.group(0).lower() if data_type != 'url' else match.group(0)
                    else:
                        # Bóc tách đơn giản bằng dấu phẩy nếu không có regex
                        val = line.split(',')[0].strip('"').strip("'")
                    
                    if val:
                        valid_indicators.append({"value": val})
                        
    except Exception as e:
        logger.error(f"Lỗi không xác định khi đọc file {file_path}: {e}")
        
    # Khử trùng lặp siêu tốc độ bằng Dictionary Comprehension
    # Lấy 'value' làm key để tự động ghi đè và loại bỏ các item trùng lặp
    unique_dict = {item['value']: item for item in valid_indicators}
    unique_indicators = list(unique_dict.values())

    return metadata, unique_indicators