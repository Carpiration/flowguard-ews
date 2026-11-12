"""Проверка: ни одна таблица не разрывается между страницами (по PDF-рендеру)."""
import re, subprocess
from docx import Document
doc = Document("out/Диплом_FlowGuard.docx"); pdf = "out/Диплом_FlowGuard.pdf"
N = int(re.search(r"Pages:\s+(\d+)", subprocess.run(["pdfinfo", pdf], capture_output=True, text=True).stdout).group(1))
pages = [re.sub(r"\s+", "", subprocess.run(["pdftotext", "-f", str(i), "-l", str(i), pdf, "-"], capture_output=True, text=True).stdout) for i in range(1, N + 1)]
key = lambda c: re.sub(r"\s+", "", c.text)[:24]
bad = chk = 0
for t in doc.tables:
    if len(t.rows) < 3 or len(t.columns) < 2:
        continue
    chk += 1
    span = set()
    for row in t.rows:
        hits = None
        for c in row.cells:
            k = key(c)
            if len(k) < 4: continue
            h = {i + 1 for i, p in enumerate(pages) if k in p}
            hits = h if hits is None else (hits & h or hits)
        if hits and len(hits) == 1: span |= hits
    if len(span) != 1:
        bad += 1; print("РАЗРЫВ?", t.cell(0, 0).text[:20], sorted(span))
print("таблиц проверено:", chk, "| с разрывом:", bad, "| страниц:", N)
