#!/usr/bin/env bash
set -euo pipefail

# где будет проект
WORKDIR=${WORKDIR:-"$HOME/netfence"}
DB_PATH="/etc/firewall.db"
BIN_PATH="/usr/local/bin/netfence"

echo "[*] Создаём рабочую директорию $WORKDIR"
mkdir -p "$WORKDIR"
cd "$WORKDIR"

# инициализируем go-модуль (если ещё не)
if [ ! -f go.mod ]; then
    echo "[*] go mod init example.com/netfence"
    go mod init example.com/netfence
fi

echo "[*] Подтягиваем зависимости"
go get github.com/spf13/cobra@v1.8.0
go get gopkg.in/yaml.v3@v3.0.1
go get modernc.org/sqlite@v1.30.1
go get github.com/vishvananda/netlink@v1.3.1

echo "[*] Сборка бинарника"
go build -o netfence ./cmd/netfence

echo "[*] Установка в $BIN_PATH (нужен sudo)"
install -m 0755 ./netfence "$BIN_PATH"

echo "[*] Подготовка БД $DB_PATH"
if [ ! -f "$DB_PATH" ]; then
    touch "$DB_PATH"
    chown root:root "$DB_PATH"
    chmod 0640 "$DB_PATH"
fi

echo "[*] Создано! Запуск: sudo $BIN_PATH list"
