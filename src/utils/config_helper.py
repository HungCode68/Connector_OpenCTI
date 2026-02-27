import logging
import os
from typing import Any, Dict, Optional

import yaml

# Khởi tạo logger
logger = logging.getLogger(__name__)

class ConfigLoader:
    def __init__(self, base_path: str):
        self.base_path = base_path
        self.config_path = os.path.join(base_path, "config.yml")
        self.config: Dict[str, Any] = self._load_config()

    def _load_config(self) -> Dict[str, Any]:
        """Đọc và parse file YAML an toàn"""
        if not os.path.isfile(self.config_path):
            error_msg = f"CRITICAL: Không tìm thấy file cấu hình tại {self.config_path}"
            logger.error(error_msg)
            raise FileNotFoundError(error_msg)
        
        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                # Dùng safe_load tối ưu và an toàn hơn
                parsed_config = yaml.safe_load(f)
                return parsed_config if parsed_config is not None else {}
        except yaml.YAMLError as e:
            logger.error(f"CRITICAL: Lỗi cú pháp trong file YAML {self.config_path}: {e}")
            raise ValueError(f"File cấu hình không hợp lệ: {e}")

    def get_path(self, relative_path: Optional[str]) -> Optional[str]:
        """Chuyển đường dẫn tương đối sang tuyệt đối"""
        if not relative_path:
            return None
            
        # Trả về luôn nếu path đã là tuyệt đối
        if os.path.isabs(relative_path):
            return relative_path
            
        return os.path.normpath(os.path.join(self.base_path, relative_path))

    def get(self, section: str, key: Optional[str] = None, default: Any = None) -> Any:
        """
        Lấy giá trị config an toàn.
        - Lấy cả section: cfg.get('feeds')
        - Lấy key trong section: cfg.get('connector', 'name')
        """
        # Nếu chỉ truyền section, trả về toàn bộ block đó
        if key is None:
            return self.config.get(section, default)

        # Nếu truyền cả key, truy xuất sâu vào trong dictionary
        section_data = self.config.get(section, {})
        
        if isinstance(section_data, dict):
            return section_data.get(key, default)
            
        return default