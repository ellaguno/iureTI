"""Modelos de datos: Observation (lo que ve un collector) y Asset (activo conciliado)."""

from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

DEVICE_TYPES = [
    "workstation",
    "laptop",
    "server",
    "switch",
    "router",
    "firewall",
    "access_point",
    "printer",
    "ups",
    "nas",
    "hypervisor",
    "camera",
    "phone",
    "mobile",
    "iot",
    "unknown",
]


def utcnow() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


@dataclass
class SnmpInfo:
    sys_descr: str = ""
    sys_object_id: str = ""
    sys_name: str = ""
    sys_location: str = ""
    sys_contact: str = ""
    serial: str = ""
    model: str = ""
    credential: str = ""  # nombre de la credencial que respondió (nunca el secreto)


@dataclass
class Observation:
    ip: str
    mac: str = ""
    hostname: str = ""
    vendor: str = ""
    open_ports: list[int] = field(default_factory=list)
    alive_by: list[str] = field(default_factory=list)  # ping, tcp, arp
    is_gateway: bool = False  # puerta de enlace por omisión de la sonda
    is_probe: bool = False  # la propia sonda
    virtual_net: str = ""  # interfaz virtual de la sonda por la que se ve (docker0, br-…): contenedor/VM local
    ttl: int | None = None
    mdns: dict | None = None  # {"host", "services", "names", "txt"}
    upnp: dict | None = None  # descripción UPnP del dispositivo raíz
    http: dict | None = None  # {"server", "title", "realm", "model_candidates", "url"}
    netbios: dict | None = None  # {"name", "group"}
    snmp: SnmpInfo | None = None
    observed_at: str = field(default_factory=utcnow)

    @property
    def sources(self) -> list[str]:
        src = ["sweep"]
        if self.open_ports:
            src.append("ports")
        if self.vendor and not self.vendor.startswith("("):
            src.append("oui")
        if self.snmp:
            src.append("snmp")
        for name in ("mdns", "upnp", "http", "netbios"):
            if getattr(self, name):
                src.append(name)
        return src


@dataclass
class Asset:
    id: str = field(default_factory=lambda: uuid.uuid4().hex)
    fingerprint: str = ""
    device_type: str = "unknown"
    type_locked: bool = False  # True si el tipo lo fijó una persona (no se reclasifica)
    confidence: float = 0.0
    reasons: list[str] = field(default_factory=list)
    hostname: str = ""
    ips: list[str] = field(default_factory=list)
    macs: list[str] = field(default_factory=list)
    vendor: str = ""
    model: str = ""
    serial: str = ""
    os: str = ""
    location: str = ""
    open_ports: list[int] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    attributes: dict = field(default_factory=dict)
    first_seen: str = field(default_factory=utcnow)
    last_seen: str = field(default_factory=utcnow)
    synced_at: str = ""
    inventory_id: str = ""  # UUID del activo en iurefficient
    remote_status: str = ""  # matched | created_pending | ignored | rejected (respuesta de la API)
    remote_reason: str = ""
    notes: str = ""

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> Asset:
        known = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in data.items() if k in known})
