# Amnezia VPN Bot

Telegram-бот для управления пирами Amnezia WireGuard. Запускается на том же VDS что и AmneziaWG, управляет контейнером через Docker socket — без SSH и лишних зависимостей.

## Возможности

- **📋 Список ключей** — все пиры: имя, IP, статус 🟢/⚫, последний хэндшейк, трафик ↓↑
- **➕ Новый ключ** — генерация ключей, QR-код + текст конфига с Amnezia-параметрами
- **🗑 Отозвать ключ** — немедленное удаление из интерфейса и конфига

## Деплой на VDS

### 1. Создать бота и узнать свой Telegram ID

1. Напишите [@BotFather](https://t.me/BotFather) → `/newbot` → получите `BOT_TOKEN`
2. Узнайте свой Telegram ID через [@userinfobot](https://t.me/userinfobot)

### 2. На VDS — склонировать репо и настроить .env

```bash
git clone https://github.com/GlenKoks/amnezia_vpn_bot.git
cd amnezia_vpn_bot
cp .env.example .env
nano .env
```

Заполните `.env`:

```env
BOT_TOKEN=1234567890:AAxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
ADMIN_TELEGRAM_ID=123456789
VPN_HOST=1.2.3.4
VPN_INTERFACE=awg0
VPN_DOCKER_CONTAINER=amnezia-awg2
```

### 3. Собрать и запустить

```bash
docker build -t amnezia-vpn-bot .

docker run -d \
  --name amnezia-vpn-bot \
  --restart unless-stopped \
  --env-file .env \
  -v /var/run/docker.sock:/var/run/docker.sock \
  amnezia-vpn-bot
```

### 4. Проверить логи

```bash
docker logs -f amnezia-vpn-bot
```

Должно быть `Starting bot...` — всё работает.

## Как это работает

Бот подключается к Docker daemon через `/var/run/docker.sock` и выполняет команды внутри контейнера `amnezia-awg2`:

- `awg genkey / pubkey / genpsk` — генерация ключей
- `awg addconf awg0 /dev/stdin` — добавление пира без перезапуска
- `awg set awg0 peer <pubkey> remove` — отзыв пира
- `awg show awg0 dump` — статистика
- Запись конфига через `base64` — безопасная запись без проблем с экранированием
