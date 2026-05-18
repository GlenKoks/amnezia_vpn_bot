import io
import json
import logging
import os
from pathlib import Path

import qrcode
from aiogram import Bot, Dispatcher, F
from aiogram.filters import Command
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.fsm.storage.memory import MemoryStorage
from aiogram.types import (
    BufferedInputFile,
    CallbackQuery,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    KeyboardButton,
    Message,
    ReplyKeyboardMarkup,
)
from dotenv import load_dotenv

from vpn_manager import VPNManager

load_dotenv()

BOT_TOKEN = os.environ["BOT_TOKEN"]
ADMIN_ID = int(os.environ["ADMIN_TELEGRAM_ID"])
USERS_FILE = os.getenv("USERS_FILE", "/app/data/users.json")
KEYS_LOG_FILE = os.getenv("KEYS_LOG_FILE", "/app/data/keys_log.json")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

bot = Bot(token=BOT_TOKEN)
dp = Dispatcher(storage=MemoryStorage())
vpn = VPNManager()


# ── User store ────────────────────────────────────────────────────────────────
# Format: {str(user_id): {name, username, approved_at}}

_pending: dict[int, dict] = {}  # user_id -> {name, username} for pending requests


def _load_users() -> dict[str, dict]:
    try:
        with open(USERS_FILE) as f:
            data = json.load(f)
        # migrate old list format
        if isinstance(data, list):
            data = {str(uid): {"name": "—", "username": "нет", "approved_at": "—"} for uid in data}
        return data
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _save_users(users: dict[str, dict]) -> None:
    Path(USERS_FILE).parent.mkdir(parents=True, exist_ok=True)
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, ensure_ascii=False, indent=2)


def add_shared_user(user_id: int, name: str = "—", username: str = "нет") -> None:
    from datetime import datetime
    users = _load_users()
    users[str(user_id)] = {
        "name": name,
        "username": username,
        "approved_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
    }
    _save_users(users)


def is_shared(user_id: int) -> bool:
    return str(user_id) in _load_users()


# ── Keys log ──────────────────────────────────────────────────────────────────

def _log_key_issued(
    key_name: str,
    public_key: str,
    allowed_ip: str,
    issuer_id: int,
    issuer_name: str,
    issuer_username: str,
) -> None:
    from datetime import datetime
    try:
        try:
            with open(KEYS_LOG_FILE) as f:
                records = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            records = []
        records.append({
            "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
            "key_name": key_name,
            "public_key": public_key,
            "allowed_ip": allowed_ip,
            "issued_by_id": issuer_id,
            "issued_by_name": issuer_name,
            "issued_by_username": issuer_username,
        })
        Path(KEYS_LOG_FILE).parent.mkdir(parents=True, exist_ok=True)
        with open(KEYS_LOG_FILE, "w") as f:
            json.dump(records, f, ensure_ascii=False, indent=2)
    except Exception:
        log.exception("Failed to write keys log")


# ── Auth ──────────────────────────────────────────────────────────────────────

def is_admin(user_id: int) -> bool:
    return user_id == ADMIN_ID


def can_generate(user_id: int) -> bool:
    return is_admin(user_id) or is_shared(user_id)


async def deny(message: Message) -> None:
    await message.answer("Нет доступа.")


# ── FSM ───────────────────────────────────────────────────────────────────────

class AddPeerForm(StatesGroup):
    waiting_name = State()


class RevokePeerForm(StatesGroup):
    waiting_choice = State()
    waiting_confirm = State()


# ── Keyboards ─────────────────────────────────────────────────────────────────

def main_menu_kb() -> ReplyKeyboardMarkup:
    return ReplyKeyboardMarkup(
        keyboard=[
            [KeyboardButton(text="📋 Список ключей"), KeyboardButton(text="➕ Новый ключ")],
            [KeyboardButton(text="🗑 Отозвать ключ"), KeyboardButton(text="📜 Лог ключей")],
            [KeyboardButton(text="👥 Пользователи")],
        ],
        resize_keyboard=True,
    )


def limited_menu_kb() -> ReplyKeyboardMarkup:
    return ReplyKeyboardMarkup(
        keyboard=[[KeyboardButton(text="➕ Новый ключ")]],
        resize_keyboard=True,
    )


def _menu_for(user_id: int) -> ReplyKeyboardMarkup:
    return main_menu_kb() if is_admin(user_id) else limited_menu_kb()


def _access_request_kb(user_id: int) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[[
        InlineKeyboardButton(text="✅ Разрешить", callback_data=f"approve_user:{user_id}"),
        InlineKeyboardButton(text="❌ Запретить", callback_data=f"deny_user:{user_id}"),
    ]])


# ── /start ────────────────────────────────────────────────────────────────────

@dp.message(Command("start"))
async def cmd_start(message: Message) -> None:
    uid = message.from_user.id
    if is_admin(uid):
        await message.answer("VPN управление:", reply_markup=main_menu_kb())
        return
    if is_shared(uid):
        await message.answer("VPN управление:", reply_markup=limited_menu_kb())
        return

    # Unknown user — notify admin
    user = message.from_user
    parts = [user.first_name or "", user.last_name or ""]
    full_name = " ".join(p for p in parts if p) or "—"
    username = f"@{user.username}" if user.username else "нет"
    _pending[uid] = {"name": full_name, "username": username}

    await bot.send_message(
        ADMIN_ID,
        f"🔔 <b>Запрос доступа</b>\n\n"
        f"Имя: <b>{full_name}</b>\n"
        f"Username: {username}\n"
        f"ID: <code>{uid}</code>",
        parse_mode="HTML",
        reply_markup=_access_request_kb(uid),
    )
    await message.answer("Запрос отправлен администратору. Ожидайте решения.")
    log.info("Access request from %s (%s, id=%s)", full_name, username, uid)


# ── Reply keyboard handlers (registered before FSM to take priority) ─────────

@dp.message(F.text == "📋 Список ключей")
async def msg_list_peers(message: Message, state: FSMContext) -> None:
    if not is_admin(message.from_user.id):
        return
    await state.clear()
    await message.answer("⏳ Загружаю список...")
    try:
        peers = await vpn.list_peers()
    except Exception as e:
        log.exception("list_peers failed")
        await message.answer(f"Ошибка: {e}")
        return
    if not peers:
        await message.answer("Пиров нет.")
        return
    lines = []
    for p in peers:
        status = "🟢" if p.is_online else "⚫"
        lines.append(
            f"{status} <b>{p.name}</b> ({p.allowed_ip})\n"
            f"   Хэндшейк: {p.handshake_str}  {p.traffic_str}"
        )
    await message.answer("\n\n".join(lines), parse_mode="HTML")


@dp.message(F.text == "➕ Новый ключ")
async def msg_add_peer(message: Message, state: FSMContext) -> None:
    if not can_generate(message.from_user.id):
        return
    await state.clear()
    await message.answer("Введите имя нового ключа (например: Иван iPhone):")
    await state.set_state(AddPeerForm.waiting_name)


@dp.message(F.text == "🗑 Отозвать ключ")
async def msg_revoke_peer(message: Message, state: FSMContext) -> None:
    if not is_admin(message.from_user.id):
        return
    await state.clear()
    await message.answer("⏳ Загружаю список пиров…")
    try:
        peers = await vpn.list_peers()
    except Exception as e:
        log.exception("list_peers for revoke failed")
        await message.answer(f"Ошибка: {e}")
        return
    if not peers:
        await message.answer("Нет активных ключей.")
        return
    buttons = [
        [InlineKeyboardButton(
            text=f"{'🟢' if p.is_online else '⚫'} {p.name} ({p.allowed_ip}) · {p.handshake_str}",
            callback_data=f"revoke_select:{p.public_key}",
        )]
        for p in peers
    ]
    await message.answer(
        "Выберите ключ для отзыва:",
        reply_markup=InlineKeyboardMarkup(inline_keyboard=buttons),
    )
    await state.set_state(RevokePeerForm.waiting_choice)


@dp.message(F.text == "📜 Лог ключей")
async def msg_keys_log(message: Message, state: FSMContext) -> None:
    if not is_admin(message.from_user.id):
        return
    await state.clear()
    if not Path(KEYS_LOG_FILE).exists():
        await message.answer("Лог пустой — ключи ещё не выдавались.")
        return
    with open(KEYS_LOG_FILE, "rb") as f:
        data = f.read()
    await message.answer_document(
        BufferedInputFile(data, filename="keys_log.json"),
        caption="📜 Полный лог выданных ключей",
    )


@dp.message(F.text == "👥 Пользователи")
async def msg_users_list(message: Message, state: FSMContext) -> None:
    if not is_admin(message.from_user.id):
        return
    await state.clear()
    users = _load_users()
    if not users:
        await message.answer("Пользователей с доступом нет.")
        return
    keys_count: dict[str, int] = {}
    if Path(KEYS_LOG_FILE).exists():
        try:
            with open(KEYS_LOG_FILE) as f:
                for entry in json.load(f):
                    uid_str = str(entry.get("issued_by_id", ""))
                    keys_count[uid_str] = keys_count.get(uid_str, 0) + 1
        except (json.JSONDecodeError, OSError):
            pass
    buttons = []
    for uid_str, info in users.items():
        name = info.get("name", "—")
        username = info.get("username", "")
        count = keys_count.get(uid_str, 0)
        label = "1 ключ" if count == 1 else f"{count} ключей"
        display = f"{name} {username}".strip() if username else name
        buttons.append([InlineKeyboardButton(
            text=f"👤 {display} — {label}",
            callback_data=f"user_detail:{uid_str}",
        )])
    await message.answer(
        f"<b>👥 Пользователи с доступом: {len(users)}</b>",
        parse_mode="HTML",
        reply_markup=InlineKeyboardMarkup(inline_keyboard=buttons),
    )


# ── Access approve / deny ─────────────────────────────────────────────────────

@dp.callback_query(F.data.startswith("approve_user:"))
async def cb_approve_user(call: CallbackQuery) -> None:
    if not is_admin(call.from_user.id):
        await call.answer("Нет доступа.", show_alert=True)
        return
    user_id = int(call.data.split(":", 1)[1])
    info = _pending.pop(user_id, {})
    add_shared_user(user_id, info.get("name", "—"), info.get("username", "нет"))
    await call.answer("Доступ выдан.")
    await call.message.edit_text(
        call.message.text + "\n\n✅ Доступ выдан",
        parse_mode="HTML",
    )
    try:
        await bot.send_message(user_id, "✅ Доступ одобрен! Нажмите /start")
    except Exception:
        pass
    log.info("Admin approved access for user %s", user_id)


@dp.callback_query(F.data.startswith("deny_user:"))
async def cb_deny_user(call: CallbackQuery) -> None:
    if not is_admin(call.from_user.id):
        await call.answer("Нет доступа.", show_alert=True)
        return
    user_id = int(call.data.split(":", 1)[1])
    await call.answer("Запрос отклонён.")
    await call.message.edit_text(
        call.message.text + "\n\n❌ Доступ запрещён",
        parse_mode="HTML",
    )
    try:
        await bot.send_message(user_id, "❌ В доступе отказано.")
    except Exception:
        pass
    log.info("Admin denied access for user %s", user_id)


# ── List peers ────────────────────────────────────────────────────────────────

@dp.callback_query(F.data == "list_peers")
async def cb_list_peers(call: CallbackQuery) -> None:
    if not is_admin(call.from_user.id):
        await call.answer("Нет доступа.", show_alert=True)
        return
    await call.answer()
    await call.message.edit_text("⏳ Загружаю список...")
    try:
        peers = await vpn.list_peers()
    except Exception as e:
        log.exception("list_peers failed")
        await call.message.edit_text(f"Ошибка: {e}")
        return

    if not peers:
        await call.message.edit_text("Пиров нет.")
        return

    lines = []
    for p in peers:
        status = "🟢" if p.is_online else "⚫"
        lines.append(
            f"{status} <b>{p.name}</b> ({p.allowed_ip})\n"
            f"   Хэндшейк: {p.handshake_str}  {p.traffic_str}"
        )
    await call.message.edit_text("\n\n".join(lines), parse_mode="HTML")


# ── Add peer ──────────────────────────────────────────────────────────────────

@dp.callback_query(F.data == "add_peer")
async def cb_add_peer(call: CallbackQuery, state: FSMContext) -> None:
    if not can_generate(call.from_user.id):
        await call.answer("Нет доступа.", show_alert=True)
        return
    await call.answer()
    await call.message.edit_text("Введите имя нового ключа (например: Иван iPhone):")
    await state.set_state(AddPeerForm.waiting_name)


@dp.message(AddPeerForm.waiting_name)
async def fsm_add_peer_name(message: Message, state: FSMContext) -> None:
    if not can_generate(message.from_user.id):
        await deny(message)
        return
    name = message.text.strip()
    if not name:
        await message.answer("Имя не может быть пустым. Попробуйте ещё раз:")
        return

    await state.clear()
    status_msg = await message.answer(f"⏳ Создаю ключ для <b>{name}</b>…", parse_mode="HTML")
    try:
        client_config, pub_key = await vpn.add_peer(name)
    except Exception as e:
        log.exception("add_peer failed")
        await status_msg.edit_text(f"Ошибка: {e}", reply_markup=_menu_for(message.from_user.id))
        return

    # Extract assigned IP from config (Address = X.X.X.X/32)
    import re as _re
    ip_match = _re.search(r"Address\s*=\s*([\d.]+)", client_config)
    allowed_ip = ip_match.group(1) if ip_match else "?"

    user = message.from_user
    issuer_name = " ".join(p for p in [user.first_name or "", user.last_name or ""] if p) or "—"
    issuer_username = f"@{user.username}" if user.username else "нет"
    _log_key_issued(name, pub_key, allowed_ip, user.id, issuer_name, issuer_username)

    qr = qrcode.make(client_config)
    buf = io.BytesIO()
    qr.save(buf, format="PNG")
    buf.seek(0)

    await status_msg.delete()
    await message.answer_photo(
        BufferedInputFile(buf.read(), filename="vpn.png"),
        caption=f"<b>{name}</b>\nPublicKey: <code>{pub_key}</code>",
        parse_mode="HTML",
    )
    await message.answer(
        f"<code>{client_config}</code>",
        parse_mode="HTML",
        reply_markup=_menu_for(message.from_user.id),
    )


# ── Users list ───────────────────────────────────────────────────────────────

@dp.callback_query(F.data == "users_list")
async def cb_users_list(call: CallbackQuery) -> None:
    if not is_admin(call.from_user.id):
        await call.answer("Нет доступа.", show_alert=True)
        return
    await call.answer()

    users = _load_users()
    if not users:
        await call.message.edit_text("Пользователей с доступом нет.")
        return

    # Count issued keys per user from log
    keys_count: dict[str, int] = {}
    if Path(KEYS_LOG_FILE).exists():
        try:
            with open(KEYS_LOG_FILE) as f:
                for entry in json.load(f):
                    uid_str = str(entry.get("issued_by_id", ""))
                    keys_count[uid_str] = keys_count.get(uid_str, 0) + 1
        except (json.JSONDecodeError, OSError):
            pass

    buttons = []
    for uid_str, info in users.items():
        name = info.get("name", "—")
        username = info.get("username", "")
        count = keys_count.get(uid_str, 0)
        label = f"1 ключ" if count == 1 else f"{count} ключей"
        display = f"{name} {username}".strip() if username else name
        buttons.append([InlineKeyboardButton(
            text=f"👤 {display} — {label}",
            callback_data=f"user_detail:{uid_str}",
        )])
    buttons.append([InlineKeyboardButton(text="← Назад", callback_data="back_main")])

    await call.message.edit_text(
        f"<b>👥 Пользователи с доступом: {len(users)}</b>",
        parse_mode="HTML",
        reply_markup=InlineKeyboardMarkup(inline_keyboard=buttons),
    )


@dp.callback_query(F.data.startswith("user_detail:"))
async def cb_user_detail(call: CallbackQuery, state: FSMContext) -> None:
    if not is_admin(call.from_user.id):
        await call.answer("Нет доступа.", show_alert=True)
        return
    await call.answer()

    uid_str = call.data.split(":", 1)[1]
    users = _load_users()
    info = users.get(uid_str, {})
    name = info.get("name", "—")
    username = info.get("username", "нет")

    # Collect this user's public keys from log
    user_pubkeys: set[str] = set()
    if Path(KEYS_LOG_FILE).exists():
        try:
            with open(KEYS_LOG_FILE) as f:
                for entry in json.load(f):
                    if str(entry.get("issued_by_id")) == uid_str:
                        user_pubkeys.add(entry["public_key"])
        except (json.JSONDecodeError, OSError):
            pass

    if not user_pubkeys:
        await call.message.edit_text(
            f"👤 <b>{name}</b> {username}\n\nКлючей не выдавал.",
            parse_mode="HTML",
            reply_markup=InlineKeyboardMarkup(inline_keyboard=[[
                InlineKeyboardButton(text="← Назад", callback_data="users_list"),
            ]]),
        )
        return

    try:
        peers = await vpn.list_peers()
    except Exception as e:
        await call.message.edit_text(f"Ошибка: {e}")
        return

    # Only active peers belonging to this user, sorted oldest handshake first
    user_peers = sorted(
        [p for p in peers if p.public_key in user_pubkeys],
        key=lambda p: p.last_handshake,
    )

    if not user_peers:
        await call.message.edit_text(
            f"👤 <b>{name}</b> {username}\n\nВсе ключи отозваны.",
            parse_mode="HTML",
            reply_markup=InlineKeyboardMarkup(inline_keyboard=[[
                InlineKeyboardButton(text="← Назад", callback_data="users_list"),
            ]]),
        )
        return

    lines = [f"👤 <b>{name}</b> {username}"]
    buttons = []
    for p in user_peers:
        status = "🟢" if p.is_online else "⚫"
        lines.append(
            f"\n{status} <b>{p.name}</b> ({p.allowed_ip})\n"
            f"Хэндшейк: {p.handshake_str} · {p.traffic_str}"
        )
        buttons.append([InlineKeyboardButton(
            text=f"🗑 Отозвать {p.name}",
            callback_data=f"revoke_select:{p.public_key}",
        )])

    buttons.append([InlineKeyboardButton(text="← Назад", callback_data="users_list")])
    await state.update_data(back_to=f"user_detail:{uid_str}")
    await state.set_state(RevokePeerForm.waiting_choice)

    await call.message.edit_text(
        "\n".join(lines),
        parse_mode="HTML",
        reply_markup=InlineKeyboardMarkup(inline_keyboard=buttons),
    )


# ── Revoke peer (inline flow from callback) ───────────────────────────────────


@dp.callback_query(F.data.startswith("revoke_select:"))
async def cb_revoke_select(call: CallbackQuery, state: FSMContext) -> None:
    if not is_admin(call.from_user.id):
        await call.answer("Нет доступа.", show_alert=True)
        return
    pub_key = call.data.split(":", 1)[1]
    try:
        peers = await vpn.list_peers()
    except Exception as e:
        await call.answer(f"Ошибка: {e}", show_alert=True)
        return

    peer = next((p for p in peers if p.public_key == pub_key), None)
    name = peer.name if peer else pub_key[:16] + "…"

    await state.update_data(pub_key=pub_key, name=name)
    kb = InlineKeyboardMarkup(inline_keyboard=[[
        InlineKeyboardButton(text="✅ Да, отозвать", callback_data="revoke_confirm"),
        InlineKeyboardButton(text="❌ Отмена", callback_data="back_main"),
    ]])
    await call.message.edit_text(
        f"Отозвать ключ <b>{name}</b>?\n<code>{pub_key}</code>",
        parse_mode="HTML",
        reply_markup=kb,
    )
    await state.set_state(RevokePeerForm.waiting_confirm)
    await call.answer()


@dp.callback_query(F.data == "revoke_confirm", RevokePeerForm.waiting_confirm)
async def cb_revoke_confirm(call: CallbackQuery, state: FSMContext) -> None:
    if not is_admin(call.from_user.id):
        await call.answer("Нет доступа.", show_alert=True)
        return
    data = await state.get_data()
    pub_key = data["pub_key"]
    name = data["name"]
    back_to = data.get("back_to")
    await state.clear()
    await call.answer()
    await call.message.edit_text(f"⏳ Отзываю ключ <b>{name}</b>…", parse_mode="HTML")
    try:
        await vpn.revoke_peer(pub_key)
    except Exception as e:
        log.exception("revoke_peer failed")
        await call.message.edit_text(f"Ошибка: {e}")
        return

    if back_to and back_to.startswith("user_detail:"):
        kb = InlineKeyboardMarkup(inline_keyboard=[[
            InlineKeyboardButton(text="← К пользователю", callback_data=back_to),
        ]])
    else:
        kb = None
    await call.message.edit_text(
        f"Ключ <b>{name}</b> отозван.", parse_mode="HTML", reply_markup=kb
    )


@dp.callback_query(F.data == "back_main")
async def cb_back_main(call: CallbackQuery, state: FSMContext) -> None:
    await state.clear()
    await call.answer()
    await call.message.edit_reply_markup(reply_markup=None)


# ── Entry point ───────────────────────────────────────────────────────────────

@dp.errors()
async def error_handler(event, exception: Exception) -> None:
    log.exception("Unhandled error: %s", exception)


async def main() -> None:
    log.info("Starting bot...")
    await dp.start_polling(bot, allowed_updates=["message", "callback_query"])


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
