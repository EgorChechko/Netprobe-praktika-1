#!/bin/bash
set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}=== NetProbe Docker Demonstration ===${NC}"

echo -e "${YELLOW}[1/7] TCP сканирование nginx:80${NC}"
/app/netprobe nginx --tcp -p 80 --banner --service-detect --color

echo -e "\n${YELLOW}[2/7] TCP сканирование postgres:5432${NC}"
/app/netprobe postgres --tcp -p 5432 --banner --service-detect

echo -e "\n${YELLOW}[3/7] TCP сканирование mysql:3306${NC}"
/app/netprobe mysql --tcp -p 3306 --banner --service-detect

echo -e "\n${YELLOW}[4/7] TCP сканирование mock-ssh:22${NC}"
/app/netprobe test-ssh --tcp -p 22 --banner --service-detect

echo -e "\n${YELLOW}[5/7] UDP сканирование udp-echo:9999${NC}"
/app/netprobe test-udp --udp -p 9999

echo -e "\n${YELLOW}[6/7] ICMP проверка контейнеров${NC}"
/app/netprobe nginx --icmp
/app/netprobe postgres --icmp

echo -e "\n${YELLOW}[7/7] Генерация HTML-отчёта в ./reports/report.html${NC}"
mkdir -p /app/reports
/app/netprobe nginx,postgres --tcp -p 80,5432 --banner --service-detect --html /app/reports/report.html

# Дополнительно: тест SQLite и уведомлений (первый запуск)
echo -e "\n${YELLOW}[+] Тест SQLite: первый запуск (создание базы)${NC}"
/app/netprobe nginx --tcp -p 80 --db /app/test.db

echo -e "\n${YELLOW}[+] Второй запуск с уведомлением (no changes)${NC}"
/app/netprobe nginx --tcp -p 80 --db /app/test.db --notify

echo -e "\n${GREEN}=== Демонстрация завершена. Отчёт HTML: ./reports/report.html ===${NC}"