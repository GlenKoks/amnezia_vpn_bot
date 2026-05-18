from __future__ import annotations

import base64
import ipaddress
import re
import shlex
import time
from dataclasses import dataclass

import asyncssh
import os
from dotenv import load_dotenv

load_dotenv()

VPN_HOST = os.getenv("VPN_HOST", "")
VPN_SSH_PORT = int(os.getenv("VPN_SSH_PORT", "22"))
VPN_SSH_USER = os.getenv("VPN_SSH_USER", "root")
VPN_SSH_KEY_PATH = os.getenv("VPN_SSH_KEY_PATH", "/app/.ssh/id_ed25519")
VPN_INTERFACE = os.getenv("VPN_INTERFACE", "awg0")
VPN_DOCKER_CONTAINER = os.getenv("VPN_DOCKER_CONTAINER", "amnezia-awg2")
CONF_PATH = f"/opt/amnezia/awg/{VPN_INTERFACE}.conf"

# Amnezia-specific interface parameters to copy into client config
AMNEZIA_KEYS = ["Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4"]


@dataclass
class PeerInfo:
    name: str
    public_key: str
    allowed_ip: str
    last_handshake: int  # unix timestamp, 0 if never
    rx_bytes: int
    tx_bytes: int

    @property
    def is_online(self) -> bool:
        if self.last_handshake == 0:
            return False
        return (time.time() - self.last_handshake) < 180

    @property
    def handshake_str(self) -> str:
        if self.last_handshake == 0:
            return "никогда"
        delta = int(time.time() - self.last_handshake)
        if delta < 60:
            return f"{delta}с назад"
        if delta < 3600:
            return f"{delta // 60}м назад"
        if delta < 86400:
            return f"{delta // 3600}ч назад"
        return f"{delta // 86400}д назад"

    @staticmethod
    def _fmt_bytes(n: int) -> str:
        for unit in ("Б", "КБ", "МБ", "ГБ"):
            if n < 1024:
                return f"{n:.0f} {unit}"
            n /= 1024
        return f"{n:.1f} ТБ"

    @property
    def traffic_str(self) -> str:
        return f"↓{self._fmt_bytes(self.rx_bytes)} ↑{self._fmt_bytes(self.tx_bytes)}"


# ── Docker exec helpers ────────────────────────────────────────────────────────

def _docker(cmd: str) -> str:
    """Run a command inside the VPN container."""
    return f"docker exec {VPN_DOCKER_CONTAINER} {cmd}"


def _docker_sh(cmd: str) -> str:
    """Run a shell pipeline inside the VPN container."""
    return f"docker exec {VPN_DOCKER_CONTAINER} sh -c {shlex.quote(cmd)}"


def _b64_write(path: str, content: str) -> str:
    """Write content to a file inside the container via base64 (safe escaping)."""
    enc = base64.b64encode(content.encode()).decode()
    return _docker_sh(f"printf '%s' '{enc}' | base64 -d > {path}")


def _b64_pipe(content: str, cmd: str) -> str:
    """Pipe base64-decoded content to a command inside the container."""
    enc = base64.b64encode(content.encode()).decode()
    return _docker_sh(f"printf '%s' '{enc}' | base64 -d | {cmd}")


# ── VPNManager ─────────────────────────────────────────────────────────────────

class VPNManager:
    def __init__(self):
        self._conn_kwargs = dict(
            host=VPN_HOST,
            port=VPN_SSH_PORT,
            username=VPN_SSH_USER,
            client_keys=[VPN_SSH_KEY_PATH],
            known_hosts=None,
        )

    async def _run(self, conn: asyncssh.SSHClientConnection, cmd: str) -> str:
        result = await conn.run(cmd, check=True)
        return result.stdout.strip()

    async def list_peers(self) -> list[PeerInfo]:
        async with await asyncssh.connect(**self._conn_kwargs) as conn:
            conf_raw = await self._run(conn, _docker(f"cat {CONF_PATH}"))
            dump_raw = await self._run(conn, _docker(f"awg show {VPN_INTERFACE} dump"))
        return _parse_peers(conf_raw, dump_raw)

    async def add_peer(self, name: str) -> tuple[str, str]:
        async with await asyncssh.connect(**self._conn_kwargs) as conn:
            # Generate keys inside the container
            priv_key = await self._run(conn, _docker("awg genkey"))
            pub_key = await self._run(conn, _docker_sh(f"echo '{priv_key}' | awg pubkey"))
            psk = await self._run(conn, _docker("awg genpsk"))

            conf_raw = await self._run(conn, _docker(f"cat {CONF_PATH}"))
            srv = _parse_server_section(conf_raw)

            server_pubkey = await self._run(
                conn, _docker_sh(f"echo '{srv['private_key']}' | awg pubkey")
            )

            existing_ips = _extract_allowed_ips(conf_raw)
            client_ip = _next_free_ip(srv["network"], srv["server_addr"], existing_ips)

            peer_block = (
                f"\n# {name}\n"
                f"[Peer]\n"
                f"PublicKey = {pub_key}\n"
                f"PresharedKey = {psk}\n"
                f"AllowedIPs = {client_ip}/32\n"
            )

            # Apply to live interface without restarting
            await self._run(
                conn, _b64_pipe(peer_block, f"awg addconf {VPN_INTERFACE} /dev/stdin")
            )

            # Persist to config file
            new_conf = conf_raw.rstrip() + "\n" + peer_block
            await self._run(conn, _b64_write(CONF_PATH, new_conf))

        amnezia_lines = "\n".join(f"{k} = {v}" for k, v in srv["amnezia"].items())
        client_config = (
            f"[Interface]\n"
            f"PrivateKey = {priv_key}\n"
            f"Address = {client_ip}/32\n"
            f"DNS = 1.1.1.1\n"
        )
        if amnezia_lines:
            client_config += amnezia_lines + "\n"
        client_config += (
            f"\n[Peer]\n"
            f"PublicKey = {server_pubkey}\n"
            f"PresharedKey = {psk}\n"
            f"Endpoint = {VPN_HOST}:{srv['listen_port']}\n"
            f"AllowedIPs = 0.0.0.0/0, ::/0\n"
            f"PersistentKeepalive = 25\n"
        )
        return client_config, pub_key

    async def revoke_peer(self, public_key: str) -> None:
        async with await asyncssh.connect(**self._conn_kwargs) as conn:
            await self._run(
                conn, _docker(f"awg set {VPN_INTERFACE} peer {public_key} remove")
            )
            conf_raw = await self._run(conn, _docker(f"cat {CONF_PATH}"))
            new_conf = _remove_peer_block(conf_raw, public_key)
            await self._run(conn, _b64_write(CONF_PATH, new_conf))


# ── Config parsing ─────────────────────────────────────────────────────────────

def _parse_server_section(conf: str) -> dict:
    m = re.search(r"\[Interface\](.*?)(?=\n\[|\Z)", conf, re.S)
    block = m.group(1) if m else ""

    def get(key: str) -> str:
        km = re.search(rf"^{key}\s*=\s*(.+)$", block, re.M)
        return km.group(1).strip() if km else ""

    address = get("Address")
    iface = ipaddress.ip_interface(address) if address else ipaddress.ip_interface("10.8.1.0/24")
    server_addr = str(iface.ip)
    network = str(iface.network)

    amnezia = {k: v for k in AMNEZIA_KEYS if (v := get(k))}

    return {
        "private_key": get("PrivateKey"),
        "listen_port": get("ListenPort"),
        "server_addr": server_addr,
        "network": network,
        "amnezia": amnezia,
    }


def _extract_allowed_ips(conf: str) -> list[str]:
    return re.findall(r"AllowedIPs\s*=\s*([\d.]+)/\d+", conf)


def _next_free_ip(network_str: str, server_addr: str, used: list[str]) -> str:
    net = ipaddress.ip_network(network_str, strict=False)
    used_set = set(used) | {server_addr}
    for host in net.hosts():
        if str(host) not in used_set:
            return str(host)
    raise RuntimeError("No free IPs in subnet")


def _parse_peers(conf: str, dump: str) -> list[PeerInfo]:
    # Build pubkey -> name from "# Name" comments above [Peer] blocks
    name_map: dict[str, str] = {}
    lines = conf.splitlines()
    for i, line in enumerate(lines):
        if line.strip() == "[Peer]":
            name = ""
            for j in range(i - 1, max(i - 4, -1), -1):
                prev = lines[j].strip()
                if prev.startswith("#"):
                    name = prev.lstrip("#").strip()
                    break
                if prev:
                    break
            for j in range(i + 1, min(i + 10, len(lines))):
                pk_m = re.match(r"PublicKey\s*=\s*(.+)", lines[j].strip())
                if pk_m:
                    name_map[pk_m.group(1).strip()] = name
                    break

    # awg show dump peer line columns (tab-separated):
    # pubkey  psk  endpoint  allowed_ips  last_handshake  rx  tx  keepalive
    peers: list[PeerInfo] = []
    for line in dump.splitlines()[1:]:  # skip server line
        parts = line.split("\t")
        if len(parts) < 7:
            continue
        pub_key = parts[0]
        allowed_ips_field = parts[3]
        # Server line has listen port in parts[2] (no colon+port), skip it
        if not ("/" in allowed_ips_field):
            continue
        handshake_ts = int(parts[4]) if parts[4].isdigit() else 0
        rx = int(parts[5]) if parts[5].isdigit() else 0
        tx = int(parts[6]) if parts[6].isdigit() else 0
        ip = allowed_ips_field.split("/")[0]

        raw_name = name_map.get(pub_key, "")
        display_name = raw_name if raw_name else pub_key[:20] + "…"

        peers.append(PeerInfo(
            name=display_name,
            public_key=pub_key,
            allowed_ip=ip,
            last_handshake=handshake_ts,
            rx_bytes=rx,
            tx_bytes=tx,
        ))
    return peers


def _remove_peer_block(conf: str, public_key: str) -> str:
    lines = conf.splitlines(keepends=True)
    result: list[str] = []
    i = 0
    while i < len(lines):
        if lines[i].strip() == "[Peer]":
            # Collect block until next section or EOF
            j = i + 1
            while j < len(lines) and not lines[j].strip().startswith("["):
                j += 1
            block = lines[i:j]
            if any(
                re.match(rf"PublicKey\s*=\s*{re.escape(public_key)}", l.strip())
                for l in block
            ):
                # Strip trailing comment (peer name) already added to result
                while result and result[-1].strip().startswith("#"):
                    result.pop()
                while result and result[-1].strip() == "":
                    result.pop()
                i = j
                continue
            result.extend(block)
            i = j
        else:
            result.append(lines[i])
            i += 1
    return "".join(result).rstrip() + "\n"
