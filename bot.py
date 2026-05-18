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
    Message,
)
from dotenv import load_dotenv

from vpn_manager import VPNManager

load_dotenv()

BOT_TOKEN = os.environ["BOT_TOKEN"]
ADMIN_ID = int(os.environ["ADMIN_TELEGRAM_ID"])
USERS_FILE = os.getenv("USERS_FILE", "/app/data/users.json")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

bot = Bot(token=BOT_TOKEN)
dp = Dispatcher(storage=MemoryStorage())
vpn = VPNManager()


# ── User store ────────────────────────────────────────────────────────────────

def _load_users() -> set[int]:
    try:
        with open(USERS_FILE) as f:
            return set(json.load(f))
    except (FileNotFoundError, json.JSONDecodeError):
        return set()


def _save_users(users: set[int]) -> None:
    Path(USERS_FILE).parent.mkdir(parents=True, exist_ok=True)
    with open(USERS_FILE, "w") as f:
        json.dump(list(users), f)


def add_shared_user(user_id: int) -> None:
    users = _load_users()
    users.add(user_id)
    _save_users(users)


def remove_shared_user(user_id: int) -> None:
    users = _load_users()
    users.discard(user_id)
    _save_users(users)


def is_shared(user_id: int) -> bool:
    return user_id in _load_users()


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


class ShareForm(StatesGroup):
    waiting_user_id = State()


# ── Keyboards ─────────────────────────────────────────────────────────────────

def main_menu_kb() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="📋 Список ключей", callback_data="list_peers")],
        [InlineKeyboardButton(text="➕ Новый ключ", callback_data="add_peer")],
        [InlineKeyboardButton(text="🗑 Отозвать ключ", callback_data="revoke_peer")],
    ])


def limited_menu_kb() -> InlineKeyboardMarkup:
    """Menu for shared users — generate keys only."""
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="➕ Новый ключ", callback_data="add_peer")],
    ])


def _menu_for(user_id: int) -> InlineKeyboardMarkup:
    return main_menu_kb() if is_admin(user_id) else limited_menu_kb()


# ── /start ────────────────────────────────────────────────────────────────────

@dp.message(Command("start"))
async def cmd_start(message: Message) -> None:
    uid = message.from_user.id
    if is_admin(uid):
        await message.answer("VPN управление:", reply_markup=main_menu_kb())
    elif is_shared(uid):
        await message.answer("VPN управление:", reply_markup=limited_menu_kb())
    else:
        await deny(message)


# ── /share ────────────────────────────────────────────────────────────────────

@dp.message(Command("share"))
async def cmd_share(message: Message, state: FSMContext) -> None:
    if not is_admin(message.from_user.id):
        await deny(message)
        return
    await message.answer(
        "Введите Telegram ID пользователя, которому хотите дать доступ к генерации ключей.\n\n"
        "Пользователь может узнать свой ID через @userinfobot"
    )
    await state.set_state(ShareForm.waiting_user_id)


@dp.message(ShareForm.waiting_user_id)
async def fsm_share_user_id(message: Message, state: FSMContext) -> None:
    if not is_admin(message.from_user.id):
        await deny(message)
        return
    try:
        user_id = int(message.text.strip())
    except ValueError:
        await message.answer("Некорректный ID — введите число:")
        return
    if user_id == ADMIN_ID:
        await message.answer("Это ваш собственный ID.", reply_markup=main_menu_kb())
        await state.clear()
        return
    add_shared_user(user_id)
    await state.clear()
    await message.answer(
        f"✅ Пользователь <code>{user_id}</code> получил доступ к генерации ключей.\n"
        f"Пусть напишет боту /start",
        parse_mode="HTML",
        reply_markup=main_menu_kb(),
    )
    log.info("Admin granted access to user %s", user_id)


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
        await call.message.edit_text(f"Ошибка: {e}", reply_markup=main_menu_kb())
        return

    if not peers:
        await call.message.edit_text("Пиров нет.", reply_markup=main_menu_kb())
        return

    lines = []
    for p in peers:
        status = "🟢" if p.is_online else "⚫"
        lines.append(
            f"{status} <b>{p.name}</b> ({p.allowed_ip})\n"
            f"   Хэндшейк: {p.handshake_str}  {p.traffic_str}"
        )
    await call.message.edit_text("\n\n".join(lines), parse_mode="HTML", reply_markup=main_menu_kb())


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


# ── Revoke peer ───────────────────────────────────────────────────────────────

@dp.callback_query(F.data == "revoke_peer")
async def cb_revoke_peer(call: CallbackQuery, state: FSMContext) -> None:
    if not is_admin(call.from_user.id):
        await call.answer("Нет доступа.", show_alert=True)
        return
    await call.answer()
    await call.message.edit_text("⏳ Загружаю список пиров…")
    try:
        peers = await vpn.list_peers()
    except Exception as e:
        log.exception("list_peers for revoke failed")
        await call.message.edit_text(f"Ошибка: {e}", reply_markup=main_menu_kb())
        return

    if not peers:
        await call.message.edit_text("Нет активных ключей.", reply_markup=main_menu_kb())
        return

    buttons = [
        [InlineKeyboardButton(
            text=f"{'🟢' if p.is_online else '⚫'} {p.name} ({p.allowed_ip}) · {p.handshake_str}",
            callback_data=f"revoke_select:{p.public_key}",
        )]
        for p in peers
    ]
    buttons.append([InlineKeyboardButton(text="← Назад", callback_data="back_main")])
    kb = InlineKeyboardMarkup(inline_keyboard=buttons)
    await call.message.edit_text("Выберите ключ для отзыва:", reply_markup=kb)
    await state.set_state(RevokePeerForm.waiting_choice)


@dp.callback_query(F.data.startswith("revoke_select:"), RevokePeerForm.waiting_choice)
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
    kb = InlineKeyboardMarkup(inline_keyboard=[
        [
            InlineKeyboardButton(text="✅ Да, отозвать", callback_data="revoke_confirm"),
            InlineKeyboardButton(text="❌ Отмена", callback_data="back_main"),
        ]
    ])
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
    await state.clear()
    await call.answer()
    await call.message.edit_text(f"⏳ Отзываю ключ <b>{name}</b>…", parse_mode="HTML")
    try:
        await vpn.revoke_peer(pub_key)
    except Exception as e:
        log.exception("revoke_peer failed")
        await call.message.edit_text(f"Ошибка: {e}", reply_markup=main_menu_kb())
        return
    await call.message.edit_text(
        f"Ключ <b>{name}</b> отозван.", parse_mode="HTML", reply_markup=main_menu_kb()
    )


@dp.callback_query(F.data == "back_main")
async def cb_back_main(call: CallbackQuery, state: FSMContext) -> None:
    await state.clear()
    await call.answer()
    uid = call.from_user.id
    await call.message.edit_text("VPN управление:", reply_markup=_menu_for(uid))


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
