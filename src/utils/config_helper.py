import os
import yaml

class ConfigLoader:
    def __init__(self, base_path):
        self.base_path = base_path
        self.config_path = os.path.join(base_path, "config.yml")
        self.config = self._load_config()

    def _load_config(self):
        if not os.path.isfile(self.config_path):
            raise Exception(f"CRITICAL: Không tìm thấy file cấu hình tại {self.config_path}")
        
        with open(self.config_path, 'r', encoding='utf-8') as f:
            return yaml.load(f, Loader=yaml.SafeLoader)

    def get_path(self, relative_path):
        """Chuyển đường dẫn tương đối sang tuyệt đối"""
        if not relative_path:
            return None
        # Xử lý nếu path đã là tuyệt đối hoặc path rỗng
        if os.path.isabs(relative_path):
            return relative_path
        return os.path.normpath(os.path.join(self.base_path, relative_path))

    def get(self, section, key=None, default=None):
        """
        Lấy giá trị config an toàn.
        Hỗ trợ gọi: cfg.get('section', 'key') hoặc cfg.get('section')
        """
        # Nếu chỉ truyền 1 tham số (VD: lấy toàn bộ list 'feeds')
        if key is None:
            return self.config.get(section, default)

        # Nếu truyền 2 tham số (VD: lấy 'connector' -> 'name')
        section_data = self.config.get(section, {})
        
        # Kiểm tra xem section_data có phải là dict không
        if isinstance(section_data, dict):
            return section_data.get(key, default)
        
        # Nếu section_data là list hoặc kiểu khác mà user lại cố .get(key)
        # thì trả về default để tránh crash
        return default