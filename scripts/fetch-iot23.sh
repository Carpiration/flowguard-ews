#!/usr/bin/env bash
# Скачивает размеченные потоки IoT-23 (Stratosphere Laboratory) из открытого
# репозитория aucad/sensor-data в каталог data/iot23 (в git не добавляется).
set -euo pipefail
dir="${1:-data/iot23}"
tmp="$(mktemp -d)"
git clone --depth 1 https://github.com/aucad/sensor-data "$tmp/sensor-data"
mkdir -p "$dir"
cp "$tmp"/sensor-data/iot-23/CTU-*-labeled.csv "$dir"/
rm -rf "$tmp"
echo "Готово: $(ls "$dir" | wc -l) файлов в $dir"
echo "Проверка: node scripts/eval-dataset.mjs $dir/*.csv"
