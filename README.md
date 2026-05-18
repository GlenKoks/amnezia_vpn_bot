# Amnezia VPN Bot

Telegram-бот для управления пирами Amnezia WireGuard через SSH. Позволяет администратору просматривать список ключей со статусом онлайн/офлайн, выдавать новые ключи (QR-код + текст конфига) и отзывать существующие.

## Требования

- VDS с установленным Amnezia WireGuard (`awg` / `awg-quick`)
- Конфиг: `/etc/amnezia/amneziawg/awg0.conf`
- Docker на машине, где будет запущен бот

## Деплой

### 1. Создать бота и узнать свой Telegram ID

1. Напишите [@BotFather](https://t.me/BotFather) → `/newbot` → получите `BOT_TOKEN`.
2. Узнайте свой Telegram ID через [@userinfobot](https://t.me/userinfobot).

### 2. Сгенерировать SSH-ключ

```bash
ssh-keygen -t ed25519 -f ~/.ssh/vpnbot_ed25519 -N ""
```

Добавьте публичный ключ на VDS:

```bash
ssh-copy-id -i ~/.ssh/vpnbot_ed25519.pub root@<VPN_HOST>
# или вручную:
cat ~/.ssh/vpnbot_ed25519.pub >> ~/.ssh/authorized_keys
```

### 3. Настроить sudo без пароля на VDS

Создайте файл `/etc/sudoers.d/vpnbot`:

```
root ALL=(ALL) NOPASSWD: /usr/bin/awg, /usr/sbin/awg, /usr/bin/tee, /bin/tee, /usr/bin/cat, /bin/cat
```

> Замените `root` на фактического SSH-пользователя, если используете не root.

### 4. Настроить .env

Скопируйте `.env.example` в `.env` и заполните значения:

```bash
cp .env.example .env
```

```env
BOT_TOKEN=1234567890:AAxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
ADMIN_TELEGRAM_ID=123456789
VPN_HOST=1.2.3.4
VPN_SSH_PORT=22
VPN_SSH_USER=root
VPN_SSH_KEY_PATH=/app/id_ed25519
VPN_INTERFACE=awg0
```

### 5. Собрать и запустить

```bash
docker build -t amnezia-vpn-bot .

docker run -d \
  --name amnezia-vpn-bot \
  --restart unless-stopped \
  --env-file .env \
  -v ~/.ssh/vpnbot_ed25519:/app/id_ed25519:ro \
  amnezia-vpn-bot
```

## Использование

Напишите боту `/start` — появится главное меню:

- **📋 Список ключей** — все пиры: имя, IP, статус 🟢/⚫, время последнего хэндшейка, трафик ↓↑
- **➕ Новый ключ** — бот попросит имя, создаст пир, вышлет QR-код и текст конфига
- **🗑 Отозвать ключ** — выберите ключ из списка, подтвердите — ключ немедленно удаляется из живого интерфейса и конфига

## Как это работает

Бот подключается к VDS по SSH и выполняет команды:

- `awg genkey / pubkey / genpsk` — генерация ключей
- `sudo awg addconf awg0 /dev/stdin` — добавление пира без перезапуска
- `sudo awg set awg0 peer <pubkey> remove` — отзыв пира из живого интерфейса
- `sudo awg show awg0 dump` — получение статистики
- Запись конфига через `base64 | sudo tee` — безопасная запись без проблем с экранированием
