#!/bin/bash
set -e

# Путь к скомпилированному netprobe (измените, если нужно)
NETPROBE="./netprobe"

# Цветной вывод
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}=== NetProbe Demo Script ===${NC}"

# Запускаем тестовые контейнеры
echo -e "${YELLOW}[1/7] Запуск тестовых контейнеров...${NC}"
docker-compose up -d

sleep 3

# IP-адреса контейнеров (фиксированные)
NGINX_IP="172.25.0.10"
POSTGRES_IP="172.25.0.11"
MYSQL_IP="172.25.0.12"
SSH_IP="172.25.0.13"
UDP_IP="172.25.0.14"

echo -e "IP: nginx=$NGINX_IP, postgres=$POSTGRES_IP, mysql=$MYSQL_IP, ssh=$SSH_IP, udp=$UDP_IP"

# Тест 1: TCP с баннером и определением сервиса
echo -e "\n${YELLOW}[2/7] TCP сканирование nginx: порт 80 (баннер + сервис)${NC}"
$NETPROBE "$NGINX_IP/32" --tcp -p 80 --banner --service-detect --color

echo -e "\n${YELLOW}[3/7] TCP сканирование postgres: порт 5432${NC}"
$NETPROBE "$POSTGRES_IP/32" --tcp -p 5432 --banner --service-detect

echo -e "\n${YELLOW}[4/7] TCP сканирование mysql: порт 3306${NC}"
$NETPROBE "$MYSQL_IP/32" --tcp -p 3306 --banner --service-detect

echo -e "\n${YELLOW}[5/7] TCP сканирование mock-ssh: порт 22${NC}"
$NETPROBE "$SSH_IP/32" --tcp -p 22 --banner --service-detect

# Тест 2: UDP
echo -e "\n${YELLOW}[6/7] UDP сканирование udp-echo: порт 9999${NC}"
$NETPROBE "$UDP_IP/32" --udp -p 9999

# Тест 3: ICMP (требует прав root)
echo -e "\n${YELLOW}[7/7] ICMP проверка доступности контейнеров${NC}"
sudo $NETPROBE "$NGINX_IP/32" --icmp
sudo $NETPROBE "$POSTGRES_IP/32" --icmp

# Дополнительно: JSON и HTML
echo -e "\n${YELLOW}Дополнительно: JSON вывод и HTML отчёт${NC}"
$NETPROBE "$NGINX_IP/32" --tcp -p 80 --json | jq .
$NETPROBE "$NGINX_IP/32,$POSTGRES_IP/32" --tcp -p 80,5432 --html /tmp/netprobe_report.html
echo -e "HTML отчёт сохранён в /tmp/netprobe_report.html"

echo -e "\n${GREEN}=== Тесты завершены ===${NC}"
echo "Остановка контейнеров: docker-compose down"