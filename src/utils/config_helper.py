import os
import yaml

class ConfigLoader:
    def __init__(self, base_path):
        # base_path là thư mục chứa file main.py 
        self.base_path = base_path
        self.config_path = os.path.join(base_path, "config.yml")
        self.config = self._load_config()

    def _load_config(self):
        if not os.path.isfile(self.config_path):
            raise Exception(f"CRITICAL: Không tìm thấy file cấu hình tại {self.config_path}")
        
        with open(self.config_path, 'r', encoding='utf-8') as f:
            return yaml.load(f, Loader=yaml.FullLoader)

    def get_path(self, relative_path):
        """Chuyển đường dẫn tương đối sang tuyệt đối"""
        if not relative_path:
            return None
        return os.path.normpath(os.path.join(self.base_path, relative_path))

    def get(self, section, key, default=None):
        """Lấy giá trị config an toàn"""
        return self.config.get(section, {}).get(key, default)