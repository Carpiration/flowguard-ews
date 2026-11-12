import json
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch, Rectangle, Circle

import os
HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "img") + os.sep
R = json.load(open(os.path.join(HERE, "..", "..", "experiments", "results.json")))
plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 10, "axes.spines.top": False, "axes.spines.right": False})
INK, BLUE, RED, GREY, AMBER = "#1b1b1b", "#1f5fb4", "#c0392b", "#8a8a8a", "#b9770e"

def box(ax, x, y, w, h, text, fc="#f3f3f3", ec=INK, fs=9.5, bold=False):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.02,rounding_size=0.08", fc=fc, ec=ec, lw=1))
    ax.text(x + w / 2, y + h / 2, text, ha="center", va="center", fontsize=fs, color=INK, fontweight="bold" if bold else "normal")

def arrow(ax, x1, y1, x2, y2, color=INK, style="-|>", ls="-"):
    ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2), arrowstyle=style, mutation_scale=12, lw=1.1, color=color, ls=ls))

def canvas(w, h, xs, ys):
    fig, ax = plt.subplots(figsize=(w, h))
    ax.set_xlim(0, xs); ax.set_ylim(0, ys); ax.axis("off")
    return fig, ax

def save(fig, name):
    fig.savefig(OUT + name, dpi=200, bbox_inches="tight", facecolor="white"); plt.close(fig)

# 1.1 стадии атаки
fig, ax = canvas(9, 3.3, 18, 6.6)
stages = ["Разведка\nсети", "Сканирование\nпортов", "Получение\nдоступа", "Управление\n(маяк)", "Вывод\nданных", "Воздействие\n(DDoS)"]
for i, s in enumerate(stages):
    box(ax, 0.3 + i * 2.95, 3.6, 2.5, 1.5, s, fc="#eef3fb" if i < 4 else "#fbecea", fs=8.2)
    if i: arrow(ax, 0.3 + i * 2.95 - 0.45, 4.35, 0.3 + i * 2.95, 4.35)
ax.plot([0.3, 17.7], [2.6, 2.6], color=INK, lw=1); arrow(ax, 17.2, 2.6, 17.8, 2.6)
ax.text(17.7, 2.15, "время", ha="right", fontsize=9, color=GREY)
ax.add_patch(Rectangle((0.3, 2.75), 11.6, 0.35, fc=BLUE, alpha=0.25, ec="none"))
ax.text(6.1, 3.22, "«тихие» стадии: меняется структура трафика", ha="center", fontsize=8.5, color=BLUE)
ax.add_patch(Rectangle((12.1, 2.75), 5.6, 0.35, fc=RED, alpha=0.25, ec="none"))
ax.text(14.9, 3.22, "«громкие»: растёт объём", ha="center", fontsize=8.5, color=RED)
arrow(ax, 1.6, 1.2, 1.6, 2.55, color=BLUE); ax.text(1.6, 0.75, "раннее выявление", ha="center", fontsize=9.5, color=BLUE, fontweight="bold")
arrow(ax, 15.2, 1.2, 15.2, 2.55, color=RED); ax.text(15.2, 0.75, "пороговое обнаружение", ha="center", fontsize=9.5, color=RED, fontweight="bold")
ax.annotate("", xy=(15.0, 1.45), xytext=(1.8, 1.45), arrowprops=dict(arrowstyle="<->", color=GREY, lw=1))
ax.text(8.4, 1.62, "выигрыш во времени", ha="center", fontsize=9, color=GREY)
ax.text(0.3, 5.6, "Стадии атаки", fontsize=9.5, color=GREY)
save(fig, "fig-1-1.png")

# 1.2 классификация методов
fig, ax = canvas(9, 4.2, 18, 8.4)
box(ax, 4.5, 7.0, 9, 1.0, "Методы обнаружения сетевых атак", bold=True, fc="#e9e9e9")
box(ax, 0.6, 5.0, 5.2, 1.0, "Сигнатурные"); box(ax, 9.2, 5.0, 8.2, 1.0, "Обнаружение аномалий")
arrow(ax, 9, 7.0, 3.2, 6.0); arrow(ax, 9, 7.0, 13.3, 6.0)
box(ax, 0.6, 3.0, 5.2, 1.0, "Правила по содержимому\n(Snort, Suricata)", fs=8.5)
box(ax, 0.6, 1.2, 5.2, 1.0, "Поведенческие сигнатуры", fs=8.5, fc="#eef3fb", ec=BLUE)
arrow(ax, 3.2, 5.0, 3.2, 4.0); arrow(ax, 3.2, 3.0, 3.2, 2.2)
box(ax, 6.6, 3.0, 5.0, 1.0, "Статистические"); box(ax, 12.4, 3.0, 5.0, 1.0, "Машинное обучение")
arrow(ax, 13.3, 5.0, 9.1, 4.0); arrow(ax, 13.3, 5.0, 14.9, 4.0)
for i, (t, hl) in enumerate([("Порог\nμ+3σ", False), ("EWMA", True), ("CUSUM", True)]):
    box(ax, 6.6 + i * 1.72, 1.2, 1.56, 1.0, t, fs=7.6, fc="#eef3fb" if hl else "#f3f3f3", ec=BLUE if hl else INK)
    arrow(ax, 9.1, 3.0, 7.38 + i * 1.72, 2.2)
for i, (t, hl) in enumerate([("С учителем", False), ("Isolation\nForest", True)]):
    box(ax, 12.4 + i * 2.6, 1.2, 2.4, 1.0, t, fs=8, fc="#eef3fb" if hl else "#f3f3f3", ec=BLUE if hl else INK)
    arrow(ax, 14.9, 3.0, 13.6 + i * 2.6, 2.2)
ax.add_patch(Rectangle((0.6, 0.25), 0.5, 0.35, fc="#eef3fb", ec=BLUE)); ax.text(1.3, 0.42, "использовано в разрабатываемой модели", va="center", fontsize=8.5, color=INK)
save(fig, "fig-1-2.png")

# 2.2 CUSUM
k, h = 0.8, 7.0
z = [0.2, -0.4, 0.5, -0.1, 0.3, -0.6, 0.1, 0.4] + [1.5 + d for d in (0.1, -0.2, 0.15, -0.1, 0.05, -0.15, 0.2, 0.0, -0.05, 0.1, -0.1, 0.05)] + [0.2, -0.3, 0.1, -0.2]
S, s = [], 0.0
for v in z:
    s = min(1.2 * h, max(0.0, s + v - k)); S.append(s)
t = [5 * (i + 1) for i in range(len(z))]
fig, (a1, a2) = plt.subplots(2, 1, figsize=(8, 4.6), sharex=True)
a1.axvspan(40, 100, color="#e9e9e9"); a2.axvspan(40, 100, color="#e9e9e9")
a1.plot(t, z, color=INK, marker="o", ms=3.5, lw=1.2); a1.axhline(3, color=RED, ls="--", lw=1); a1.text(t[-1], 3.12, "порог z₀ = 3", ha="right", color=RED, fontsize=9)
a1.axhline(k, color=GREY, ls=":", lw=1); a1.text(t[-1], k + 0.12, "k = 0,8", ha="right", color=GREY, fontsize=9)
a1.set_ylabel("z-оценка признака"); a1.set_ylim(-1, 3.8); a1.text(42, 3.35, "атака", fontsize=9, color=GREY)
a2.plot(t, S, color=BLUE, marker="o", ms=3.5, lw=1.4); a2.axhline(h, color=RED, ls="--", lw=1); a2.text(2, h + 0.25, "порог h = 7", ha="left", color=RED, fontsize=9)
a2.axhline(h / 2, color=AMBER, ls="--", lw=1); a2.text(2, h / 2 + 0.25, "предупреждение: S = h/2", ha="left", color=AMBER, fontsize=9)
a2.set_ylabel("сумма CUSUM, S"); a2.set_xlabel("время, с"); a2.set_ylim(0, 9.5)
save(fig, "fig-2-2.png")

# 2.3 состояния
fig, ax = canvas(8.4, 3.2, 16.8, 6.4)
box(ax, 0.6, 2.4, 3.8, 1.6, "НОРМА\nR < 25", fc="#eef6ee", ec="#2e7d32", bold=True)
box(ax, 6.5, 2.4, 3.8, 1.6, "ПРЕДУПРЕЖДЕНИЕ\n25 ≤ R < τ", fc="#fdf3e0", ec=AMBER, bold=True, fs=9)
box(ax, 12.4, 2.4, 3.8, 1.6, "ТРЕВОГА\nR ≥ τ (τ = 50)", fc="#fbecea", ec=RED, bold=True)
arrow(ax, 4.4, 3.6, 6.5, 3.6); ax.text(5.45, 3.95, "R ≥ 25 или\ns_C ≥ 0,5", ha="center", fontsize=8.2)
arrow(ax, 10.3, 3.6, 12.4, 3.6); ax.text(11.35, 3.85, "R ≥ τ", ha="center", fontsize=8.2)
arrow(ax, 12.4, 2.8, 10.3, 2.8); ax.text(11.35, 2.2, "R < τ", ha="center", fontsize=8.2)
arrow(ax, 6.5, 2.8, 4.4, 2.8); ax.text(5.45, 1.85, "R < 25 и\ns_C < 0,5", ha="center", fontsize=8.2)
ax.add_patch(FancyArrowPatch((2.5, 4.0), (14.3, 4.0), connectionstyle="arc3,rad=-0.32", arrowstyle="-|>", mutation_scale=12, lw=1.1, color=INK))
ax.text(8.4, 5.95, "резкая атака: R ≥ τ в одном окне", ha="center", fontsize=8.5)
ax.text(8.4, 0.7, "спад риска сглажен: R_t = max(R_raw, R_{t−1}·d), полуспад 20 с", ha="center", fontsize=8.5, color=GREY)
save(fig, "fig-2-3.png")

# 3.10 порог
th = R["sensitivity"]["threshold"]
x = [r["threshold"] for r in th]
fig, a1 = plt.subplots(figsize=(7.2, 3.6))
a1.plot(x, [r["f1"] for r in th], color=BLUE, marker="o", lw=1.6, label="F1")
a1.plot(x, [r["recall"] for r in th], color=INK, marker="s", lw=1.2, ls="--", label="Полнота")
a1.plot(x, [r["precision"] for r in th], color=GREY, marker="^", lw=1.2, ls=":", label="Точность")
a1.set_ylim(0.7, 1.02); a1.set_xlabel("порог тревоги τ"); a1.set_ylabel("доля"); a1.set_xticks(x)
a2 = a1.twinx(); a2.spines["right"].set_visible(True)
a2.plot(x, [r["delaySec"] for r in th], color=RED, marker="D", lw=1.4, label="Задержка, с")
a2.set_ylabel("задержка обнаружения, с", color=RED); a2.set_ylim(0, 20); a2.tick_params(axis="y", colors=RED)
a1.axvline(50, color="#cfcfcf", lw=1, zorder=0)
h1, l1 = a1.get_legend_handles_labels(); h2, l2 = a2.get_legend_handles_labels()
a1.legend(h1 + h2, l1 + l2, loc="lower left", frameon=False, fontsize=9)
save(fig, "fig-3-10.png")

# 3.11 реальные данные
order = ["34-1", "20-1", "21-1", "44-1", "42-1"]
names = {"34-1": "Malware-34-1\n(Mirai)", "20-1": "Malware-20-1\n(Torii)", "21-1": "Malware-21-1\n(Torii)", "44-1": "Malware-44-1\n(Mirai)", "42-1": "Malware-42-1\n(троян)"}
rows = {o: next(f for f in R["real"] if f"Malware-Capture-{o}" in f["file"]) for o in order}
get = lambda o, vid: next(v for v in rows[o]["variants"] if v["id"] == vid)["auc"]
fig, ax = plt.subplots(figsize=(8, 3.6))
w = 0.26
for j, (vid, lab, col, hatch) in enumerate([("full", "Ансамбль", BLUE, None), ("static", "Порог μ+3σ", "#bdbdbd", "//"), ("iforest", "Только Isolation Forest", "#5b5b5b", None)]):
    vals = [get(o, vid) for o in order]
    bars = ax.bar([i + (j - 1) * w for i in range(len(order))], vals, w * 0.92, label=lab, color=col, hatch=hatch, edgecolor="white")
    for b, v in zip(bars, vals): ax.text(b.get_x() + b.get_width() / 2, v + 0.015, f"{v:.2f}".replace(".", ","), ha="center", fontsize=7.5)
ax.axhline(0.5, color=GREY, ls=":", lw=1, label="Случайное ранжирование (0,5)")
ax.set_xticks(range(len(order))); ax.set_xticklabels([names[o] for o in order], fontsize=8.5)
ax.set_ylim(0, 1.12); ax.set_ylabel("ROC-AUC"); ax.legend(frameon=False, fontsize=8.5, ncol=4, loc="upper center", bbox_to_anchor=(0.5, 1.16))
save(fig, "fig-3-11.png")

# 4.1 рабочее место
fig, ax = canvas(7.5, 4.2, 15, 8.4)
ax.plot([0.5, 14.5], [0.6, 0.6], color=INK, lw=1.2)                       # пол
ax.add_patch(Rectangle((7.2, 4.0), 6.4, 0.25, fc="#d9d9d9", ec=INK))       # стол
ax.plot([13.2, 13.2], [0.6, 4.0], color=INK, lw=1.2); ax.plot([7.6, 7.6], [0.6, 4.0], color=INK, lw=1.2)
ax.add_patch(Rectangle((11.0, 4.9), 0.3, 2.3, fc="#bfc9d9", ec=INK)); ax.add_patch(Rectangle((11.05, 4.25), 0.2, 0.65, fc=INK))  # монитор
ax.add_patch(Rectangle((8.2, 4.25), 1.8, 0.15, fc="#8a8a8a", ec=INK))      # клавиатура
ax.add_patch(Rectangle((3.2, 2.6), 2.6, 0.3, fc="#d9d9d9", ec=INK)); ax.add_patch(Rectangle((3.0, 2.9), 0.3, 3.0, fc="#d9d9d9", ec=INK))  # кресло
ax.plot([4.5, 4.5], [0.6, 2.6], color=INK, lw=1.2)
ax.add_patch(Circle((4.4, 7.0), 0.55, fc="#f0d9c4", ec=INK))               # голова
ax.plot([4.2, 4.0, 5.9, 5.9], [6.4, 3.0, 3.0, 0.9], color=INK, lw=3, solid_capstyle="round")  # спина, бедро, голень
ax.plot([5.9, 6.7], [0.9, 0.9], color=INK, lw=3, solid_capstyle="round")
ax.plot([4.25, 5.0, 8.3], [5.7, 4.6, 4.5], color=INK, lw=2.4, solid_capstyle="round")       # рука
ax.plot([4.95, 11.0], [7.0, 6.9], color=BLUE, ls="--", lw=1)
ax.annotate("", xy=(11.0, 7.75), xytext=(4.95, 7.75), arrowprops=dict(arrowstyle="<->", color=BLUE, lw=1))
ax.text(8.0, 7.9, "60–70 см", ha="center", fontsize=9, color=BLUE)
ax.text(11.6, 7.0, "верх экрана на уровне\nглаз или чуть ниже", fontsize=8.2, va="center")
ax.text(10.4, 2.5, "предплечья на опоре,\nугол в локте около 90°", fontsize=8.2, ha="center")
ax.text(1.4, 4.6, "спина опирается\nна спинку кресла", fontsize=8.2, ha="center")
ax.text(6.2, 0.15, "ступни полностью на полу", fontsize=8.2, ha="center")
ax.text(1.4, 7.6, "свет сбоку,\nбез бликов", fontsize=8.2, ha="center", color=AMBER)
arrow(ax, 1.4, 7.1, 3.6, 6.6, color=AMBER)
save(fig, "fig-4-1.png")

# 4.2 огнетушители
fig, ax = canvas(9, 3.9, 18, 7.8)
cols = [("Углекислотный\n(ОУ)", "углекислый газ", ["B", "C", "E"], "Основной для\nкомпьютерной техники:\nне оставляет следов", "#eef6ee", "#2e7d32"),
        ("Порошковый\n(ОП)", "порошок", ["A", "B", "C", "E"], "Универсален,\nно порошок загрязняет\nаппаратуру", "#fdf3e0", AMBER),
        ("Газовый\n(хладоновый)", "газовый состав", ["B", "C", "E"], "Для ценного\nоборудования: не\nповреждает электронику", "#eef6ee", "#2e7d32"),
        ("Водный и\nвоздушно-пенный", "вода, пена", ["A", "B"], "Только после\nотключения\nэлектропитания", "#fbecea", RED)]
for i, (name, agent, cls, note, fc, ec) in enumerate(cols):
    x = 0.4 + i * 4.35
    box(ax, x, 5.9, 4.0, 1.4, name, fc="#e9e9e9", bold=True, fs=9)
    ax.text(x + 2.0, 5.35, agent, ha="center", fontsize=8.5, color=GREY)
    for j, c in enumerate("ABCDE"):
        on = c in cls
        ax.add_patch(Circle((x + 0.55 + j * 0.72, 4.45), 0.3, fc=INK if on else "white", ec=INK if on else "#bdbdbd"))
        ax.text(x + 0.55 + j * 0.72, 4.45, c, ha="center", va="center", fontsize=8, color="white" if on else "#bdbdbd", fontweight="bold")
    box(ax, x, 1.7, 4.0, 1.9, note, fc=fc, ec=ec, fs=8)
ax.text(0.4, 0.75, "Классы пожара: A — твёрдые вещества, B — жидкости, C — газы, D — металлы, E — электроустановки.", fontsize=8, color=INK)
ax.text(0.4, 0.2, "Тёмный кружок — огнетушитель применим для данного класса.", fontsize=8.2, color=GREY)
save(fig, "fig-4-2.png")
print("ok")
