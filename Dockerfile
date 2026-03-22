# ใช้ base image ที่ใหม่และปลอดภัยขึ้น
FROM python:3.10-slim-bookworm

# ปิด buffer log (ดีสำหรับ Render)
ENV PYTHONUNBUFFERED=1

# ติดตั้ง system dependencies (จำเป็น + cleanup)
RUN apt-get update && apt-get upgrade -y && apt-get install -y \
    build-essential \
    curl \
    git \
    chromium \
    chromium-driver \
    && rm -rf /var/lib/apt/lists/*

# ตั้ง working directory
WORKDIR /app

# copy requirements ก่อน (ใช้ cache ได้เร็วขึ้น)
COPY requirements.txt .

# install python dependencies
RUN python -m pip install --upgrade pip \
 && pip install --no-cache-dir -r requirements.txt \
 && pip install scikit-learn==1.6.1

# copy project ทั้งหมด
COPY . .

# ตั้งค่า environment สำหรับ chromium (ถ้าใช้)
ENV CHROME_BIN=/usr/bin/chromium
ENV CHROMEDRIVER_PATH=/usr/bin/chromedriver

# สร้าง user ไม่ใช้ root
RUN useradd -m sandbox
USER sandbox

# Render จะ inject PORT มาให้
ENV PORT=10000
EXPOSE 10000

# run app
CMD ["python", "python/app.py"]