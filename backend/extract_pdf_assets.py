import fitz
import os

pdf_path = r'C:\Users\SUDHARSAN\.gemini\antigravity-ide\brain\da36d046-63db-4c17-b4ef-702b6f6dfb82\.user_uploaded\media_1793507002715.pdf'
doc = fitz.open(pdf_path)
out_dir = os.path.abspath('report_assets')
os.makedirs(out_dir, exist_ok=True)

print(f"Total pages: {len(doc)}")
extracted = {}

for pno in range(len(doc)):
    page = doc[pno]
    il = page.get_images()
    for img_info in il:
        xref = img_info[0]
        rects = page.get_image_rects(xref)
        if rects:
            for r in rects:
                if r.width > 20 and r.height > 20:
                    base_img = doc.extract_image(xref)
                    ext = base_img["ext"]
                    filename = f"page_{pno+1}_xref_{xref}.{ext}"
                    filepath = os.path.join(out_dir, filename)
                    if not os.path.exists(filepath):
                        with open(filepath, "wb") as f:
                            f.write(base_img["image"])
                    print(f"Page {pno+1}: rect={r}, xref={xref}, saved {filename}")
                    extracted[pno+1] = filepath
