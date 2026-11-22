#!/usr/bin/env bash
set -euo pipefail

TARGET="${1:-example.com}"

if ! command -v python3 >/dev/null 2>&1; then
  echo "Ошибка: python3 не найден. Установите Python 3.10+."
  exit 1
fi

if [ ! -f ".env" ] && [ -f ".env.example" ]; then
  cp .env.example .env
  echo "Создан файл конфигурации .env из .env.example"
fi

chmod +x netpulse.py
echo "Запуск NetPulse CLI для цели: ${TARGET}"
python3 netpulse.py "${TARGET}"
