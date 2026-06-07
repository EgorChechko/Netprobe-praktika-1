markdown
# NetProbe – многопоточный сетевой сканер с уведомлениями

NetProbe – консольная утилита на языке C для аудита доступности сети и сервисов.  
Поддерживает **TCP**, **UDP**, **ICMP**, снятие баннеров, определение сервисов, генерацию HTML-отчётов и **уведомления об изменениях** (рабочий стол + syslog).

## Сборка на хосте (Linux)

### 1. Установите зависимости

```bash
sudo apt update
sudo apt install -y libsqlite3-dev libnotify-bin build-essential
```

### 2. Скомпилируйте программу

```bash
gcc -Wall -Wextra -pthread -lm -O2 -o netprobe netprobe.c -lsqlite3
```

> Если возникает ошибка линковки sqlite3, попробуйте указать путь явно:  
> `gcc ... -L/usr/lib/x86_64-linux-gnu -lsqlite3`  
> или используйте статическую линковку:  
> `gcc ... /usr/lib/x86_64-linux-gnu/libsqlite3.a`

## Проверка уведомлений (основная цель этого README)

Уведомления работают через `notify-send` (библиотека `libnotify-bin`).  
Они появляются при изменении состояния порта: открыт → закрыт, закрыт → открыт.

### 1. Убедитесь, что уведомления работают

```bash
notify-send "Тест" "Привет из NetProbe"
```

Если всплывающего окна нет – установите `libnotify-bin` и проверьте переменную `DISPLAY` (`echo $DISPLAY`).

### 2. Запустите тестовый сервис (например, на порту 8888)

```bash
socat TCP-LISTEN:8888,fork,reuseaddr EXEC:'echo "Hello from test service"' &
```

### 3. Первое сканирование – создаём базу данных (сохраняем состояние «порт открыт»)

```bash
./netprobe 127.0.0.1/32 --tcp -p 8888 --db test.db --banner --service-detect
```

Вы увидите `OPEN/UP`.

### 4. Остановите сервис (изменим состояние)

```bash
killall socat
```

### 5. Запустите сканирование с опцией `--notify`

```bash
./netprobe 127.0.0.1/32 --tcp -p 8888 --db test.db --notify
```

**Результат:**  
- В консоли появится строка `CLOSED`.  
- В правом верхнем углу экрана должно появиться уведомление:  
  `CHANGE: 127.0.0.1 TCP/8888 OPEN -> CLOSED`

### 6. Запустите сервис снова и повторите шаг 5

```bash
socat TCP-LISTEN:8888,fork,reuseaddr EXEC:'echo "Back online"' &
./netprobe 127.0.0.1/32 --tcp -p 8888 --db test.db --notify
```

Уведомление: `CHANGE: 127.0.0.1 TCP/8888 CLOSED -> OPEN`

### 7. Периодический мониторинг с уведомлениями

```bash
./netprobe 127.0.0.1/32 --tcp -p 8888 --db test.db --notify --interval 5
```

Программа будет проверять порт каждые 5 секунд. Останавливайте и запускайте сервис – уведомления будут приходить автоматически.  
Остановить: `Ctrl+C`.

### 8. Дополнительно: уведомления + syslog

```bash
./netprobe 127.0.0.1/32 --tcp -p 8888 --db test.db --notify --syslog --interval 5
```

Сообщения также пишутся в системный лог. Посмотреть:  
`journalctl -f | grep netprobe`

## Другие возможности NetProbe

### Сканирование подсети /24 (требует sudo для ICMP)

```bash
sudo ./netprobe 192.168.1.0/24 --tcp -p 22,80,443 --banner --service-detect --color -t 16
```

### Генерация HTML-отчёта

```bash
./netprobe 127.0.0.1/32 --tcp -p 8888 --html report.html
firefox report.html   # или xdg-open report.html
```

### Режим демона с лог-файлом (без уведомлений)

```bash
./netprobe 127.0.0.1/32 --tcp -p 8888 --interval 30 --daemon --pidfile /tmp/np.pid --logfile /tmp/np.json
# Остановить: kill $(cat /tmp/np.pid)
```

### Справка по всем опциям

```bash
./netprobe --help
```

## Системные требования

- Linux (ядро 3.2+)  
- Для ICMP обязателен запуск с `sudo` (raw sockets).  
- Для уведомлений – графическая среда с поддержкой `notify-send`.  
- Для syslog – стандартный системный логгер.

## Репозиторий

Исходный код: [https://github.com/EgorChechko/Netprobe-praktika-1](https://github.com/EgorChechko/Netprobe-praktika-1)

## Лицензия

MIT
