#!/usr/bin/env python3
"""Сборка пояснительной записки из текстовых исходников (src/*.txt) в .docx.

Разметка исходников (построчно):
  # ЗАГОЛОВОК            — глава / структурный раздел (с новой страницы)
  ## 1.1. Заголовок      — подглава
  ### Текст              — ненумерованный полужирный подзаголовок
  !t Таблица 1.1.|Название   далее строки | a | b | — таблица (первая строка — шапка)
  !f файл|Рисунок 3.1 – Подпись|ширина_см
  !e формула|(2.1)
  - пункт                — перечисление
  [@key] / [@a,@b]       — ссылка на источник из refs.txt
"""
import re
import sys
from pathlib import Path

from docx import Document
from docx.enum.section import WD_SECTION
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_BREAK, WD_LINE_SPACING, WD_TAB_ALIGNMENT, WD_TAB_LEADER
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Cm, Pt, RGBColor

ROOT = Path(__file__).parent
SRC = ROOT / "src"
IMG = ROOT / "img"
FONT = "Times New Roman"
TOPIC = "Разработка модели раннего выявления рисков путем обнаружения аномалий сетевого трафика в кибербезопасности"

# ---------- источники ----------
refs = []
ref_no = {}
for line in (SRC / "refs.txt").read_text(encoding="utf-8").splitlines():
    line = line.strip()
    if not line:
        continue
    key, text = line.split("|", 1)
    refs.append(text.strip())
    ref_no[key.strip()] = len(refs)


def cite(m):
    keys = [k.strip().lstrip("@") for k in m.group(1).split(",")]
    nums = sorted(ref_no[k] for k in keys)
    out, i = [], 0
    while i < len(nums):
        j = i
        while j + 1 < len(nums) and nums[j + 1] == nums[j] + 1:
            j += 1
        out.append(f"{nums[i]}–{nums[j]}" if j - i >= 2 else ", ".join(str(n) for n in nums[i : j + 1]))
        i = j + 1
    return "[" + ", ".join(out) + "]"


def resolve(text):
    return re.sub(r"\[((?:@[\w-]+\s*,?\s*)+)\]", cite, text)


# ---------- документ и стили ----------
doc = Document()
sec = doc.sections[0]
sec.page_width, sec.page_height = Cm(21), Cm(29.7)
sec.left_margin, sec.right_margin, sec.top_margin, sec.bottom_margin = Cm(3), Cm(1.5), Cm(2), Cm(2)


def set_font(style_or_run, size=14, bold=None, italic=None):
    f = style_or_run.font
    f.name = FONT
    f.size = Pt(size)
    f.color.rgb = RGBColor(0, 0, 0)
    if bold is not None:
        f.bold = bold
    if italic is not None:
        f.italic = italic
    rpr = style_or_run.element.get_or_add_rPr() if hasattr(style_or_run.element, "get_or_add_rPr") else style_or_run._element.get_or_add_rPr()
    rfonts = rpr.find(qn("w:rFonts"))
    if rfonts is None:
        rfonts = OxmlElement("w:rFonts")
        rpr.append(rfonts)
    for a in ("w:ascii", "w:hAnsi", "w:cs", "w:eastAsia"):
        rfonts.set(qn(a), FONT)


normal = doc.styles["Normal"]
set_font(normal, 14)
pf = normal.paragraph_format
pf.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
pf.line_spacing_rule = WD_LINE_SPACING.ONE_POINT_FIVE
pf.first_line_indent = Cm(1.25)
pf.space_before = pf.space_after = Pt(0)

for name, before, after in (("Heading 1", 12, 10), ("Heading 2", 9, 7)):
    st = doc.styles[name]
    set_font(st, 14, bold=True, italic=False)
    st.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.CENTER
    st.paragraph_format.first_line_indent = Cm(0)
    st.paragraph_format.space_before = Pt(before)
    st.paragraph_format.space_after = Pt(after)
    st.paragraph_format.keep_with_next = True
    st.paragraph_format.keep_together = True
    st.paragraph_format.line_spacing_rule = WD_LINE_SPACING.ONE_POINT_FIVE

def page_number_footer(section):
    section.footer.is_linked_to_previous = False
    fp = section.footer.paragraphs[0]
    fp.alignment = WD_ALIGN_PARAGRAPH.CENTER
    fp.paragraph_format.first_line_indent = Cm(0)
    r = fp.add_run()
    for tag, txt in (("begin", None), (None, "PAGE"), ("end", None)):
        if tag:
            el = OxmlElement("w:fldChar")
            el.set(qn("w:fldCharType"), tag)
        else:
            el = OxmlElement("w:instrText")
            el.set(qn("xml:space"), "preserve")
            el.text = txt
        r._r.append(el)
    set_font(r, 12)


def body_section():
    """Новый раздел с новой страницы: с него начинается нумерация в колонтитуле."""
    new = doc.add_section(WD_SECTION.NEW_PAGE)
    new.left_margin, new.right_margin, new.top_margin, new.bottom_margin = Cm(3), Cm(1.5), Cm(2), Cm(2)
    new.header_distance = new.footer_distance = Cm(1.25)
    page_number_footer(new)


sec.header_distance = sec.footer_distance = Cm(1.25)
STATE = {"after_block": False, "first_h1": True}

INLINE = re.compile(r"(\*\*.+?\*\*|\*.+?\*)")


def add_runs(p, text, size=14, bold=None, italic=None):
    for part in INLINE.split(text):
        if not part:
            continue
        b, i = bold, italic
        if part.startswith("**") and part.endswith("**"):
            part, b = part[2:-2], True
        elif part.startswith("*") and part.endswith("*") and len(part) > 2:
            part, i = part[1:-1], True
        run = p.add_run(part)
        set_font(run, size, bold=b, italic=i)
    return p


def para(text="", align=None, indent=True, size=14, bold=None, italic=None, keep=False, before=0, after=0, spacing=None):
    p = doc.add_paragraph()
    if STATE["after_block"] and not before:
        before = 8
    STATE["after_block"] = False
    if align is not None:
        p.alignment = align
    if not indent:
        p.paragraph_format.first_line_indent = Cm(0)
    if keep:
        p.paragraph_format.keep_with_next = True
    if before:
        p.paragraph_format.space_before = Pt(before)
    if after:
        p.paragraph_format.space_after = Pt(after)
    if spacing:
        p.paragraph_format.line_spacing_rule = spacing
    add_runs(p, text, size, bold, italic)
    return p


def page_break():
    doc.add_paragraph().add_run().add_break(WD_BREAK.PAGE)


def no_split(row):
    trpr = row._tr.get_or_add_trPr()
    el = OxmlElement("w:cantSplit")
    trpr.append(el)


def cell_text(cell, text, size=11.5, bold=False, align=WD_ALIGN_PARAGRAPH.LEFT, keep=True, italic=None):
    p = cell.paragraphs[0]
    p.alignment = align
    p.paragraph_format.first_line_indent = Cm(0)
    p.paragraph_format.line_spacing = 1.03
    p.paragraph_format.space_before = p.paragraph_format.space_after = Pt(0)
    tcpr = cell._tc.get_or_add_tcPr()
    mar = OxmlElement("w:tcMar")
    for side, w in (("top", 70), ("left", 80), ("bottom", 70), ("right", 80)):
        el = OxmlElement(f"w:{side}")
        el.set(qn("w:w"), str(w)); el.set(qn("w:type"), "dxa")
        mar.append(el)
    tcpr.append(mar)
    va = OxmlElement("w:vAlign"); va.set(qn("w:val"), "center"); tcpr.append(va)
    p.paragraph_format.keep_with_next = keep
    add_runs(p, text, size, bold or None, italic)


toc = []  # (уровень, текст)


def heading(text, level):
    toc.append((level, text))
    if level == 1:
        if STATE["first_h1"]:
            STATE["first_h1"] = False
            body_section()
            h = doc.add_heading(level=1)
        else:
            h = doc.add_heading(level=1)
            h.paragraph_format.page_break_before = True
    else:
        h = doc.add_heading(level=2)
    add_runs(h, text, 14, True)


def table(num, title, rows):
    STATE["after_block"] = False
    para(num, align=WD_ALIGN_PARAGRAPH.RIGHT, indent=False, keep=True)
    para(title, align=WD_ALIGN_PARAGRAPH.CENTER, indent=False, keep=True)
    n = len(rows[0])
    t = doc.add_table(rows=len(rows), cols=n)
    t.style = "Table Grid"
    t.alignment = WD_TABLE_ALIGNMENT.CENTER
    t.autofit = False
    clean = lambda v: re.sub(r"\*", "", v)
    weights = []
    for ci in range(n):
        col = [clean(r[ci]) if ci < len(r) else "" for r in rows]
        longest_word = max((len(w) for v in col for w in re.split(r"[\s/]+", v)), default=1)
        avg = sum(len(v) for v in col) / len(col)
        weights.append(max(longest_word * 1.15 + 1.5, min(avg, 46) ** 0.85 + 2))
    total = sum(weights)
    widths = [Cm(16.5 * w / total) for w in weights]
    tblpr = t._tbl.tblPr
    lay = tblpr.find(qn("w:tblLayout"))
    if lay is None:
        lay = OxmlElement("w:tblLayout")
        look = tblpr.find(qn("w:tblLook"))
        (look.addprevious(lay) if look is not None else tblpr.append(lay))
    lay.set(qn("w:type"), "fixed")
    for ri, row in enumerate(rows):
        for ci in range(n):
            t.cell(ri, ci).width = widths[ci]
    for gc, wd in zip(t._tbl.tblGrid.findall(qn("w:gridCol")), widths):
        gc.set(qn("w:w"), str(int(wd.twips)))
    for ri, row in enumerate(rows):
        no_split(t.rows[ri])
        for ci in range(n):
            val = row[ci] if ci < len(row) else ""
            numeric = bool(re.fullmatch(r"[\d\s.,%±–—−-]+|—", val)) and ri > 0
            cell_text(t.cell(ri, ci), val, size=(10.5 if n >= 7 else 11.5), bold=(ri == 0), align=WD_ALIGN_PARAGRAPH.CENTER if (ri == 0 or numeric) else WD_ALIGN_PARAGRAPH.LEFT, keep=(ri < len(rows) - 1))
    hdr = OxmlElement("w:tblHeader")
    t.rows[0]._tr.get_or_add_trPr().append(hdr)
    STATE["after_block"] = True


def figure(fname, caption, width):
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.paragraph_format.first_line_indent = Cm(0)
    p.paragraph_format.keep_with_next = True
    p.paragraph_format.line_spacing_rule = WD_LINE_SPACING.SINGLE
    p.add_run().add_picture(str(IMG / fname), width=Cm(float(width)))
    STATE["after_block"] = False
    para(caption, align=WD_ALIGN_PARAGRAPH.CENTER, indent=False, before=3, after=4)


M_NS = 'xmlns:m="http://schemas.openxmlformats.org/officeDocument/2006/math" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"'
M_RPR = '<w:rPr><w:rFonts w:ascii="Cambria Math" w:hAnsi="Cambria Math"/><w:sz w:val="28"/><w:szCs w:val="28"/></w:rPr>'


def _esc(t):
    return t.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _mrun(t):
    return f'<m:r>{M_RPR}<m:t xml:space="preserve">{_esc(t)}</m:t></m:r>' if t else ""


def _group(src, i):
    """Содержимое {…} начиная с позиции i (src[i] == '{'); возвращает (текст, позиция после)."""
    depth, j = 0, i
    while j < len(src):
        if src[j] == "{":
            depth += 1
        elif src[j] == "}":
            depth -= 1
            if depth == 0:
                return src[i + 1 : j], j + 1
        j += 1
    raise ValueError("незакрытая скобка в формуле: " + src)


def omml(src):
    """Мини-разметка: _{…}, ^{…}, \frac{…}{…}; остальное — текст."""
    out, buf, i = [], "", 0

    def flush():
        nonlocal buf
        if buf:
            out.append(("t", buf))
            buf = ""

    def take_base():
        flush()
        if out and out[-1][0] == "x":
            return out.pop()[1]
        if out and out[-1][0] == "t":
            text = out.pop()[1]
            m = re.search(r"([A-Za-zА-Яа-яΑ-Ωα-ωµ′∑∏Δ]+|\)|\d+(?:,\d+)?)$", text)
            cut = m.start() if m else len(text) - 1
            if text[:cut]:
                out.append(("t", text[:cut]))
            return _mrun(text[cut:])
        return _mrun("")

    while i < len(src):
        if src.startswith("\\frac", i):
            flush()
            num, i = _group(src, i + 5)
            den, i = _group(src, i)
            out.append(("x", f"<m:f><m:num>{omml(num)}</m:num><m:den>{omml(den)}</m:den></m:f>"))
        elif src[i] in "_^" and i + 1 < len(src) and src[i + 1] == "{":
            base = take_base()
            arg, j = _group(src, i + 1)
            tag, inner = ("sSub", "sub") if src[i] == "_" else ("sSup", "sup")
            out.append(("x", f"<m:{tag}><m:e>{base}</m:e><m:{inner}>{omml(arg)}</m:{inner}></m:{tag}>"))
            i = j
        else:
            buf += src[i]
            i += 1
    flush()
    return "".join(_mrun(v) if k == "t" else v for k, v in out)


def equation(formula, num):
    from docx.oxml import parse_xml

    t = doc.add_table(rows=1, cols=2)
    t.alignment = WD_TABLE_ALIGNMENT.CENTER
    t.autofit = False
    widths = (Cm(14.3), Cm(2.2))
    for i, w in enumerate(widths):
        t.cell(0, i).width = w
    c0, c1 = t.cell(0, 0), t.cell(0, 1)
    for c in (c0, c1):
        va = OxmlElement("w:vAlign"); va.set(qn("w:val"), "center"); c._tc.get_or_add_tcPr().append(va)
    p = c0.paragraphs[0]
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.paragraph_format.first_line_indent = Cm(0)
    p.paragraph_format.line_spacing_rule = WD_LINE_SPACING.SINGLE
    p.paragraph_format.space_before = p.paragraph_format.space_after = Pt(4)
    p._p.append(parse_xml(f"<m:oMathPara {M_NS}><m:oMath>{omml(formula)}</m:oMath></m:oMathPara>"))
    p1 = c1.paragraphs[0]
    p1.alignment = WD_ALIGN_PARAGRAPH.RIGHT
    p1.paragraph_format.first_line_indent = Cm(0)
    p1.paragraph_format.line_spacing_rule = WD_LINE_SPACING.SINGLE
    add_runs(p1, num)
    no_split(t.rows[0])
    STATE["after_block"] = True


def render(path):
    lines = path.read_text(encoding="utf-8").splitlines()
    i = 0
    while i < len(lines):
        line = resolve(lines[i].rstrip())
        i += 1
        if not line.strip():
            continue
        if line.startswith("### "):
            para(line[4:], bold=True, keep=True, before=6)
        elif line.startswith("## "):
            heading(line[3:], 2)
        elif line.startswith("# "):
            heading(line[2:], 1)
        elif line.startswith("!t "):
            num, title = line[3:].split("|", 1)
            rows = []
            while i < len(lines) and lines[i].startswith("|"):
                rows.append([resolve(c.strip()) for c in lines[i].strip().strip("|").split("|")])
                i += 1
            table(num.strip(), title.strip(), rows)
        elif line.startswith("!f "):
            fname, cap, width = line[3:].split("|")
            figure(fname.strip(), cap.strip(), width.strip())
        elif line.startswith("!e "):
            formula, num = line[3:].rsplit("|", 1)
            equation(formula.strip(), num.strip())
        elif line.startswith("- "):
            para("– " + line[2:])
        else:
            para(line)


# ---------- титульный лист, задание, аннотация ----------
C = WD_ALIGN_PARAGRAPH.CENTER


def front():
    for t in ("МИНИСТЕРСТВО ЦИФРОВЫХ ТЕХНОЛОГИЙ", "РЕСПУБЛИКИ УЗБЕКИСТАН", "ТАШКЕНТСКИЙ УНИВЕРСИТЕТ ИНФОРМАЦИОННЫХ ТЕХНОЛОГИЙ ИМЕНИ МУХАММАДА АЛ-ХОРАЗМИЙ", "ФАКУЛЬТЕТ ____________________"):
        para(t, align=C, indent=False, bold=True)
    para("")
    for t in ("**Допустить к защите**", "Заведующий кафедрой «____________________»", "__________ ____________________", "«___» ____________ 20__ г."):
        para(t, align=WD_ALIGN_PARAGRAPH.RIGHT, indent=False)
    para("")
    para("")
    para("ДИПЛОМНЫЙ ПРОЕКТ", align=C, indent=False, bold=True, size=16)
    para("")
    para(f"Тема: {TOPIC}", align=C, indent=False, bold=True)
    para("")
    para("")
    t = doc.add_table(rows=8, cols=3)
    roles = ["Выпускник", "Руководитель", "Рецензент", "Консультант по БЖД"]
    for k, role in enumerate(roles):
        cell_text(t.cell(2 * k, 0), role, size=14, bold=(k == 0), keep=False)
        cell_text(t.cell(2 * k, 1), "_______________", size=14, align=C, keep=False)
        cell_text(t.cell(2 * k, 2), "_________________", size=14, align=C, keep=False)
        cell_text(t.cell(2 * k + 1, 1), "(подпись)", size=10, align=C, keep=False)
        cell_text(t.cell(2 * k + 1, 2), "(ФИО)", size=10, align=C, keep=False)
    para("")
    para("Ташкент – 20__", align=C, indent=False, bold=True)
    page_break()

    for t in ("МИНИСТЕРСТВО ЦИФРОВЫХ ТЕХНОЛОГИЙ", "РЕСПУБЛИКИ УЗБЕКИСТАН", "ТАШКЕНТСКИЙ УНИВЕРСИТЕТ ИНФОРМАЦИОННЫХ ТЕХНОЛОГИЙ ИМЕНИ МУХАММАДА АЛ-ХОРАЗМИЙ"):
        para(t, align=C, indent=False, bold=True)
    for t in ("Факультет: ____________________", "Кафедра: ____________________", "Направление (специальность): ____________________"):
        para(t, indent=False)
    for t in ("**УТВЕРЖДАЮ**", "Заведующий кафедрой «____________________»", "___________ ____________________", "«___» ____________ 20__ г."):
        para(t, align=WD_ALIGN_PARAGRAPH.RIGHT, indent=False)
    para("ЗАДАНИЕ", align=C, indent=False, bold=True, before=6)
    para("на дипломный проект", align=C, indent=False)
    para("__________________________________________________________________", align=C, indent=False)
    para("(фамилия, имя, отчество)", align=C, indent=False, size=10)
    items = [
        f"**1. Тема ДП:** {TOPIC}",
        "**2. Утверждена приказом по университету от:** «___» ____________ 20__ г. № ______",
        "**3. Срок сдачи законченной работы:** ____________",
        "**4. Исходные данные к работе:** научно-техническая литература по теме, открытые наборы данных сетевого трафика, информация в Интернете.",
        "**5. Содержание расчетно-пояснительной записки:** введение; теоретические основы обнаружения аномалий сетевого трафика; разработка модели раннего выявления рисков; реализация и экспериментальная проверка модели; безопасность жизнедеятельности; заключение; список использованных источников.",
        "**6. Перечень графического материала:** презентация Microsoft PowerPoint.",
        "**7. Дата выдачи задания:** ____________",
    ]
    for t in items:
        para(t, indent=False)
    para("Руководитель: ________________          Задание принял: ________________", indent=False, before=6)
    para("**8. Консультанты по отдельным разделам ВКР:**", indent=False, before=6, keep=True)
    rows = [["Раздел", "ФИО руководителя", "Задание выдал (дата, подпись)", "Задание принял (дата, подпись)"]]
    for name in ("Введение", "Глава 1", "Глава 2", "Глава 3", "Глава 4 (БЖД)", "Заключение"):
        rows.append([name, "", "", ""])
    tb = doc.add_table(rows=len(rows), cols=4)
    tb.style = "Table Grid"
    for ri, row in enumerate(rows):
        no_split(tb.rows[ri])
        for ci, v in enumerate(row):
            cell_text(tb.cell(ri, ci), v, bold=(ri == 0), align=C if ri == 0 else WD_ALIGN_PARAGRAPH.LEFT, keep=ri < len(rows) - 1)
    para("**9. График выполнения работы:**", indent=False, before=8, keep=True)
    rows = [["№", "Наименование раздела", "Срок выполнения", "Руководитель (консультант), подпись"]]
    plan = [
        "Теоретические основы обнаружения аномалий сетевого трафика и раннего выявления рисков",
        "Разработка модели раннего выявления рисков",
        "Реализация и экспериментальная проверка модели",
        "Безопасность жизнедеятельности",
        "Заключение",
        "Разработка слайдов презентации",
        "Предварительная защита",
    ]
    for k, name in enumerate(plan, 1):
        rows.append([str(k), name, "", ""])
    tb = doc.add_table(rows=len(rows), cols=4)
    tb.style = "Table Grid"
    for ri, row in enumerate(rows):
        no_split(tb.rows[ri])
        for ci, v in enumerate(row):
            cell_text(tb.cell(ri, ci), v, bold=(ri == 0), align=C if (ri == 0 or ci == 0) else WD_ALIGN_PARAGRAPH.LEFT, keep=ri < len(rows) - 1)
    para("Выпускник ______________          «____» ______________ 20__ г.", indent=False, before=8)
    para("Руководитель ______________       «____» ______________ 20__ г.", indent=False)
    page_break()

    para("Аннотация", align=C, indent=False, bold=True, after=6)
    for t in (SRC / "annotation.txt").read_text(encoding="utf-8").split("\n\n"):
        if t.strip():
            para(t.strip(), indent=False)
            para("")


def toc_page(pages):
    h = para("СОДЕРЖАНИЕ", align=C, indent=False, bold=True, after=11, spacing=WD_LINE_SPACING.SINGLE)
    h.paragraph_format.page_break_before = True
    for (level, text), pg in zip(TOC_ITEMS, pages):
        p = doc.add_paragraph()
        p.alignment = WD_ALIGN_PARAGRAPH.LEFT
        p.paragraph_format.first_line_indent = Cm(0)
        p.paragraph_format.left_indent = Cm(0 if level == 1 else 0.5)
        p.paragraph_format.tab_stops.add_tab_stop(Cm(16.5), WD_TAB_ALIGNMENT.RIGHT, WD_TAB_LEADER.DOTS)
        p.paragraph_format.line_spacing = 1.2
        p.paragraph_format.space_after = Pt(2 if level == 1 else 0)
        add_runs(p, text, 12, bold=(level == 1) or None)
        add_runs(p, "\t" + str(pg), 12, bold=(level == 1) or None)


# ---------- сборка ----------
FILES = ["intro.txt", "ch1.txt", "ch2.txt", "ch3.txt", "ch4.txt", "concl.txt"]
pages_arg = sys.argv[1] if len(sys.argv) > 1 else ""

# предварительный проход по заголовкам для оглавления
TOC_ITEMS = []
for f in FILES:
    for line in (SRC / f).read_text(encoding="utf-8").splitlines():
        if line.startswith("## "):
            TOC_ITEMS.append((2, line[3:].strip()))
        elif line.startswith("# "):
            TOC_ITEMS.append((1, line[2:].strip()))
TOC_ITEMS.append((1, "СПИСОК ИСПОЛЬЗОВАННЫХ ИСТОЧНИКОВ"))
pages = pages_arg.split(",") if pages_arg else ["0"] * len(TOC_ITEMS)

front()
toc_page(pages)
for f in FILES:
    render(SRC / f)
heading("СПИСОК ИСПОЛЬЗОВАННЫХ ИСТОЧНИКОВ", 1)
for k, text in enumerate(refs, 1):
    rp = para(f"{k}. {text}")
    rp.paragraph_format.left_indent = Cm(0.75)
    rp.paragraph_format.first_line_indent = Cm(-0.75)

zoom = doc.settings.element.find(qn("w:zoom"))
if zoom is not None and zoom.get(qn("w:percent")) is None:
    zoom.set(qn("w:percent"), "100")
out = ROOT / "out" / "Диплом_FlowGuard.docx"
out.parent.mkdir(exist_ok=True)
doc.save(out)
(ROOT / "out" / "toc.txt").write_text("\n".join(t for _, t in TOC_ITEMS), encoding="utf-8")
print("saved", out, "| headings:", len(TOC_ITEMS), "| refs:", len(refs))
