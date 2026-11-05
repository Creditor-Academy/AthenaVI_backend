"""Rasterize every page of a PDF to PNG (fallback for export-fidelity.js when pdftoppm is missing).

    python -I rasterize_pdf.py <file.pdf> <out_dir> <width_px>

Needs `pip install pypdfium2`. Writes page-001.png, page-002.png, … and prints the page count.
"""
import os
import sys

import pypdfium2 as pdfium


def main():
    pdf_path, out_dir, width = sys.argv[1], sys.argv[2], int(sys.argv[3])
    os.makedirs(out_dir, exist_ok=True)
    doc = pdfium.PdfDocument(pdf_path)
    for i in range(len(doc)):
        page = doc[i]
        page_width, _ = page.get_size()
        page.render(scale=width / page_width).to_pil().save(os.path.join(out_dir, f"page-{i + 1:03d}.png"))
    print(len(doc))


if __name__ == "__main__":
    main()
