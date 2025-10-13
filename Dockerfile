FROM python:3.10-slim

# ติดตั้งเครื่องมือพื้นฐาน + chromium + chromedriver
RUN apt-get update && apt-get install -y \
    build-essential \
    git \
    curl \
    chromium \
    chromium-driver \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# อัปเกรด pip และติดตั้ง dependencies
COPY requirements.txt .
RUN python -m pip install --upgrade pip \
 && pip install --no-cache-dir -r requirements.txt \
 && pip install scikit-learn==1.6.1   # ✅ lock version ให้ตรงกับตอน train

# คัดลอกโค้ดเข้าอิมเมจ
COPY . .

# สร้าง user ที่ไม่ใช่ root และรันด้วย user นี้
RUN useradd -m sandbox
USER sandbox

EXPOSE 5000
CMD ["python", "python/app.py"]
