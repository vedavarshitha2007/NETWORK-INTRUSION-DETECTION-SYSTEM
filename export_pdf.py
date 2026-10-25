
from playwright.sync_api import sync_playwright
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.utils import ImageReader
from PIL import Image
from io import BytesIO
import math

URL = "http://localhost:8501"
OUTPUT = "SENTINEL_AI_Report.pdf"

# A4 landscape dimensions
PAGE_WIDTH, PAGE_HEIGHT = landscape(A4)

# Browser screenshot dimensions
VIEW_WIDTH = 1440
VIEW_HEIGHT = 1020

with sync_playwright() as p:

    browser = p.chromium.launch(headless=True)

    page = browser.new_page(
        viewport={
            "width": VIEW_WIDTH,
            "height": VIEW_HEIGHT
        },
        device_scale_factor=1
    )

    print("Opening SENTINEL AI...")

    page.goto(URL, wait_until="domcontentloaded")
    page.wait_for_selector(".stApp")
    page.wait_for_timeout(4000)

    # Scroll to the top
    page.evaluate("window.scrollTo(0, 0)")
    page.wait_for_timeout(500)

    # Get complete webpage height
    total_height = page.evaluate(
        "document.documentElement.scrollHeight"
    )

    print("Capturing webpage...")

    pdf = canvas.Canvas(OUTPUT, pagesize=landscape(A4))

    previous_end = 0
    page_number = 1

    while previous_end < total_height:

        # Scroll to the next section
        scroll_position = min(
            (page_number - 1) * VIEW_HEIGHT,
            total_height - VIEW_HEIGHT
        )

        page.evaluate(
            f"window.scrollTo(0, {scroll_position})"
        )
        page.wait_for_timeout(400)

        actual_position = page.evaluate("window.scrollY")

        # Capture the visible screen, including its background
        screenshot = page.screenshot(full_page=False)

        image = Image.open(BytesIO(screenshot)).convert("RGB")

        # Remove any overlapping area from the previous page
        overlap = max(0, previous_end - actual_position)

        remaining_height = total_height - previous_end

        crop = image.crop((
            0,
            overlap,
            image.width,
            min(image.height, overlap + remaining_height)
        ))

        # Place screenshot on the PDF page
        buffer = BytesIO()
        crop.save(buffer, format="PNG")
        buffer.seek(0)

        draw_height = crop.height * PAGE_WIDTH / crop.width

        pdf.drawImage(
            ImageReader(buffer),
            0,
            PAGE_HEIGHT - draw_height,
            width=PAGE_WIDTH,
            height=draw_height
        )

        pdf.showPage()

        previous_end = actual_position + image.height
        page_number += 1

        print(f"Captured PDF page {page_number - 1}")

        if actual_position + image.height >= total_height:
            break

    pdf.save()
    browser.close()

print(f"\nPDF created successfully: {OUTPUT}")
