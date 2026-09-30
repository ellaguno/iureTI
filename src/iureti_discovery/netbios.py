"""NetBIOS Node Status (UDP 137): nombre y grupo de trabajo/dominio de equipos Windows y Samba."""

from __future__ import annotations

import asyncio
import os
import struct


def _encode_name(name: bytes) -> bytes:
    name = name.ljust(16, b"\x00")
    encoded = bytes(b for c in name for b in ((c >> 4) + 0x41, (c & 0x0F) + 0x41))
    return b"\x20" + encoded + b"\x00"


def build_query(txid: int) -> bytes:
    header = struct.pack(">HHHHHH", txid, 0x0000, 1, 0, 0, 0)
    return header + _encode_name(b"*") + struct.pack(">HH", 0x21, 0x01)  # NBSTAT, IN


def parse_response(data: bytes) -> dict:
    """Devuelve {"name", "group", "names"} a partir de una respuesta NBSTAT."""
    try:
        offset = 12
        # nombre de la pregunta (normalmente 34 bytes) o puntero de compresión
        if data[offset] & 0xC0 == 0xC0:
            offset += 2
        else:
            while data[offset] != 0:
                offset += data[offset] + 1
            offset += 1
        offset += 2 + 2 + 4 + 2  # type, class, ttl, rdlength
        count = data[offset]
        offset += 1
        names = []
        for _ in range(count):
            raw = data[offset : offset + 18]
            if len(raw) < 18:
                break
            name = raw[:15].decode("ascii", errors="replace").strip()
            suffix = raw[15]
            flags = struct.unpack(">H", raw[16:18])[0]
            names.append({"name": name, "suffix": suffix, "group": bool(flags & 0x8000)})
            offset += 18
    except (IndexError, struct.error):
        return {}
    host = next((n["name"] for n in names if n["suffix"] == 0x00 and not n["group"]), "")
    group = next((n["name"] for n in names if n["suffix"] == 0x00 and n["group"]), "")
    return {"name": host, "group": group} if host else {}


class _Proto(asyncio.DatagramProtocol):
    def __init__(self, future: asyncio.Future):
        self.future = future

    def datagram_received(self, data, addr):
        if not self.future.done():
            self.future.set_result(data)

    def error_received(self, exc):
        if not self.future.done():
            self.future.set_result(b"")


async def query(ip: str, timeout: float = 1.0) -> dict:
    loop = asyncio.get_running_loop()
    future = loop.create_future()
    try:
        transport, _ = await loop.create_datagram_endpoint(lambda: _Proto(future), remote_addr=(ip, 137))
    except OSError:
        return {}
    try:
        transport.sendto(build_query(int.from_bytes(os.urandom(2), "big")))
        data = await asyncio.wait_for(future, timeout)
        return parse_response(data) if data else {}
    except asyncio.TimeoutError:
        return {}
    finally:
        transport.close()
