# preview_capture.py
import os
import base64
import time

from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager

from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC


def _build_options(width: int, height: int, headless_new: bool = True) -> Options:
    chrome_options = Options()

    # ===== Headless =====
    # บางเครื่อง/บางเว็บ headless=new มีปัญหา → เราจะมี fallback ไป headless แบบเก่า
    if headless_new:
        chrome_options.add_argument("--headless=new")
    else:
        chrome_options.add_argument("--headless")

    # ===== จำเป็นมาก (กัน crash / server) =====
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    chrome_options.add_argument("--disable-gpu")

    # ===== ลด noise =====
    chrome_options.add_argument("--log-level=3")
    chrome_options.add_argument("--disable-extensions")
    chrome_options.add_argument("--disable-infobars")

    # ===== ป้องกันบางเว็บ detect automation (ช่วยได้บางเว็บ) =====
    chrome_options.add_argument("--disable-blink-features=AutomationControlled")

    # ===== ตั้ง viewport =====
    chrome_options.add_argument(f"--window-size={width},{height}")

    # ===== user-agent จริง (ช่วยเว็บที่บล็อก headless บางส่วน) =====
    chrome_options.add_argument(
        "user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    )

    # ===== กันปัญหา SSL/https บางเคส =====
    chrome_options.add_argument("--ignore-certificate-errors")
    chrome_options.add_argument("--allow-insecure-localhost")

    return chrome_options


def _create_driver(width: int, height: int):
    """
    สร้าง driver โดยพยายามใช้ headless=new ก่อน
    ถ้า fail ให้ fallback ไป --headless (แบบเก่า)
    """
    last_err = None
    for headless_new in (True, False):
        try:
            options = _build_options(width, height, headless_new=headless_new)
            driver = webdriver.Chrome(
                service=Service(ChromeDriverManager().install()),
                options=options
            )

            # ลดการ detect เพิ่ม (ไม่รับประกัน 100% แต่ช่วยได้)
            try:
                driver.execute_cdp_cmd(
                    "Page.addScriptToEvaluateOnNewDocument",
                    {
                        "source": """
                            Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
                        """
                    }
                )
            except Exception:
                pass

            return driver
        except Exception as e:
            last_err = e

    raise last_err


def capture_preview(
    url: str,
    out_dir: str,
    filename: str = "preview.png",
    width: int = 1280,
    height: int = 800,
    wait_sec: int = 3,
    page_load_timeout: int = 25,
):
    """
    เปิดเว็บไซต์ด้วย headless Chrome แล้วถ่าย screenshot "หน้าแรก" หลังเข้า URL นั้น
    return dict:
    {
        "path": ".../preview.png",
        "base64": "iVBORw0KGgoAAA..."
    }
    """

    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, filename)

    driver = _create_driver(width, height)

    try:
        driver.set_page_load_timeout(page_load_timeout)
        driver.get(url)

        # ✅ 1) รอให้มี body จริงก่อน (กันหน้า blank)
        WebDriverWait(driver, max(5, wait_sec)).until(
            EC.presence_of_element_located((By.TAG_NAME, "body"))
        )

        # ✅ 2) รอ document.readyState = complete (กันเว็บโหลดไม่เสร็จ)
        try:
            WebDriverWait(driver, max(8, wait_sec + 5)).until(
                lambda d: d.execute_script("return document.readyState") == "complete"
            )
        except Exception:
            # บางเว็บไม่ยอม complete (ยิง request ต่อเนื่อง) → ไม่ต้อง fail
            pass

        # ✅ 3) รอเพิ่มนิดนึง ให้รูป/JS render (SPA/React/Angular)
        time.sleep(wait_sec)

        # ✅ 4) ถ่าย screenshot
        driver.save_screenshot(out_path)

    finally:
        try:
            driver.quit()
        except Exception:
            pass

    # ===== แปลงเป็น base64 =====
    with open(out_path, "rb") as f:
        img_bytes = f.read()
        img_base64 = base64.b64encode(img_bytes).decode("utf-8")

    return {
        "path": out_path,
        "base64": img_base64
    }
