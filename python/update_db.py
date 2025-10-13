import requests
import json
import asyncio
from fastapi import FastAPI, BackgroundTasks

app = FastAPI()

async def update_database():
    """ ดึงข้อมูลฟิชชิ่งจาก OpenPhish และ URLhaus อัตโนมัติ """
    sources = {
        "openphish": "https://openphish.com/feed.txt",
        "urlhaus": "https://urlhaus.abuse.ch/downloads/json/"
    }
    
    for name, url in sources.items():
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            data = response.text if name == "openphish" else response.json()

            with open(f"database/{name}.json", "w", encoding="utf-8") as f:
                json.dump(data, f, indent=4)

            print(f"✅ {name.capitalize()} database updated!")
        except Exception as e:
            print(f"❌ Error updating {name}: {e}")

@app.on_event("startup")
async def start_background_tasks():
    """ เมื่อ API Start ให้เริ่ม Background Task อัตโนมัติ """
    while True:
        await update_database()
        await asyncio.sleep(86400)  # อัปเดตทุกวัน (86400 วินาที)
