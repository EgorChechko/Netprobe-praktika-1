FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    build-essential \
    libsqlite3-dev \
    socat \
    libnotify-bin \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Копируем исходный код и компилируем
COPY netprobe.c .
RUN gcc -Wall -Wextra -pthread -lm -O2 -o netprobe netprobe.c -lsqlite3

# Копируем тестовый скрипт
COPY test.sh .
RUN chmod +x test.sh

ENTRYPOINT ["/app/test.sh"]