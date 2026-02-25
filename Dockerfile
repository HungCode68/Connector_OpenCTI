# Sử dụng phiên bản Python nhẹ gọn để tối ưu dung lượng
FROM python:3.10-slim

# Thiết lập thư mục làm việc bên trong container
WORKDIR /app

# Khắc phục lỗi in log bị chậm trong môi trường Docker
ENV PYTHONUNBUFFERED=1

# Cài đặt gcc và libmagic1 (bắt buộc cho thư viện pycti)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libmagic1 \
    && rm -rf /var/lib/apt/lists/*

# Copy file requirements và cài đặt thư viện trước (giúp tận dụng cache của Docker)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Tạo thư mục data để chứa các file CSV tải về
RUN mkdir -p /app/data

# Copy toàn bộ mã nguồn và cấu hình vào container
COPY src/ ./src/

# Lệnh sẽ được thực thi khi container khởi chạy
CMD ["python", "src/main.py"]