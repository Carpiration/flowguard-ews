#!/usr/bin/env bash
# Полная сборка: docx → pdf → номера страниц оглавления → docx → pdf
set -e
cd "$(dirname "$0")/.."
python3 build.py "${1:-}" >/dev/null
for i in 1 2; do
  (cd out && soffice --headless --convert-to pdf Диплом_FlowGuard.docx >/dev/null 2>&1)
  P=$(python3 tools/toc.py)
  python3 build.py "$P" >/dev/null
done
(cd out && soffice --headless --convert-to pdf Диплом_FlowGuard.docx >/dev/null 2>&1)
echo "TOC: $P"; echo "check: $(python3 tools/toc.py)"; pdfinfo out/Диплом_FlowGuard.pdf | grep Pages
