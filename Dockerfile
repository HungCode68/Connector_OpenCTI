# Sử dụng phiên bản Python nhẹ gọn để tối ưu dung lượng
FROM python:3.10-slim

# Thiết lập thư mục làm việc bên trong container
WORKDIR /app

# Khắc phục lỗi in log bị chậm trong môi trường Docker
ENV PYTHONUNBUFFERED=1

# Cài đặt các gói hệ thống cơ bản (nếu cần thiết cho một số thư viện Python)
RUN apt-get update && apt-get install -y --no-install-recommends gcc && rm -rf /var/lib/apt/lists/*

# Copy file requirements và cài đặt thư viện trước (giúp tận dụng cache của Docker)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Tạo thư mục data để chứa các file CSV tải về
RUN mkdir -p /app/data

# Copy toàn bộ mã nguồn và cấu hình vào container
COPY src/ ./src/
COPY utils/ ./utils/
COPY config.yml .

# Lệnh sẽ được thực thi khi container khởi chạy
CMD ["python", "src/main.py"]