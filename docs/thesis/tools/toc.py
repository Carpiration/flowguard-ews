import re, subprocess, sys
pdf = "out/Диплом_FlowGuard.pdf"
n = int(re.search(r"Pages:\s+(\d+)", subprocess.run(["pdfinfo", pdf], capture_output=True, text=True).stdout).group(1))
pages = [re.sub(r"\s+", " ", subprocess.run(["pdftotext", "-f", str(i), "-l", str(i), "-layout", pdf, "-"], capture_output=True, text=True).stdout) for i in range(1, n + 1)]
heads = open("out/toc.txt", encoding="utf-8").read().splitlines()
toc_page = next(i for i, p in enumerate(pages) if "СОДЕРЖАНИЕ" in p)
res, start = [], toc_page + 1
for h in heads:
    key = re.sub(r"\s+", " ", h)[:38]
    for i in range(start, n):
        if key in pages[i]:
            res.append(i + 1); start = i; break
    else:
        res.append(0)
print(",".join(map(str, res)))
