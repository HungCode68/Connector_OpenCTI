import re
import os

def parse_local_file(file_path):
    """Bóc tách IP/CIDR từ một file nội bộ và giữ nguyên thứ tự"""
    ordered_ips = []  # list để giữ thứ tự
    seen_ips = set()  # Dùng set phụ để kiểm tra trùng lặp 
    metadata = {}
    
    if not os.path.exists(file_path):
        print(f"Lỗi: Không tìm thấy file {file_path}")
        return metadata, []

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line: continue
                
                # Bóc tách Metadata
                if line.startswith('#'):
                    if ':' in line:
                        parts = line.lstrip('#').split(':', 1)
                        metadata[parts[0].strip()] = parts[1].strip()
                    continue
                
                # Regex tìm IP
                match = re.match(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?)', line)
                if match:
                    ip = match.group(1)
                    # Chỉ thêm vào nếu IP này chưa từng xuất hiện trước đó
                    if ip not in seen_ips:
                        ordered_ips.append(ip)
                        seen_ips.add(ip) # Đánh dấu là đã thấy IP này rồi
                    
    except Exception as e:
        print(f"Lỗi khi đọc file: {e}")
        
    return metadata, ordered_ips # Trả về list đã đúng thứ tự