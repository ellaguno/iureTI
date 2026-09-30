"""Orquestación de un escaneo: barrido → huella de puertos → enriquecimiento (DNS, OUI, SNMP)."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

from . import netutil, snmp
from .models import Observation, utcnow
from .netutil import CLOSED, OPEN
from .oui import OuiDatabase

# Puertos para decidir rápidamente si un host está vivo
DISCOVERY_PORTS = [22, 80, 135, 443, 445, 3389, 8080, 9100]
# Puertos adicionales de huella, solo en hosts vivos
FINGERPRINT_PORTS = [
    21, 23, 25, 53, 88, 139, 389, 515, 554, 631, 636, 902, 1433, 2049, 3268, 3306,
    5060, 5432, 5480, 5985, 5986, 6379, 8006, 8443, 27017,
]


@dataclass
class ScanOptions:
    targets: list[str]
    snmp_credentials: list[snmp.SnmpCredential] = field(default_factory=list)
    concurrency: int = 256
    tcp_timeout: float = 0.8
    use_ping: bool = True
    resolve_dns: bool = True


@dataclass
class ScanProgress:
    phase: str = "idle"
    total: int = 0
    done: int = 0
    alive: int = 0
    started_at: str = ""
    finished_at: str = ""
    error: str = ""
    targets: list[str] = field(default_factory=list)
    cancelled: bool = False

    @property
    def running(self) -> bool:
        return bool(self.started_at) and not self.finished_at

    def to_dict(self) -> dict:
        return {**self.__dict__, "running": self.running}


class Scanner:
    def __init__(self, options: ScanOptions, oui: OuiDatabase | None = None, progress: ScanProgress | None = None):
        self.opts = options
        self.oui = oui or OuiDatabase()
        self.progress = progress or ScanProgress()
        self._sem = asyncio.Semaphore(options.concurrency)

    def cancel(self) -> None:
        self.progress.cancelled = True

    async def _probe(self, ip: str, port: int) -> str:
        async with self._sem:
            return await netutil.tcp_probe(ip, port, self.opts.tcp_timeout)

    async def _ping(self, ip: str) -> bool:
        async with self._sem:
            return await netutil.ping(ip)

    def _phase(self, name: str, total: int) -> None:
        self.progress.phase, self.progress.total, self.progress.done = name, total, 0

    async def _gather(self, coros):
        results = []
        for fut in asyncio.as_completed(coros):
            results.append(await fut)
            self.progress.done += 1
            if self.progress.cancelled:
                break
        return results

    async def _discover(self, ip: str) -> tuple[str, list[str], set[int]]:
        tasks = [self._probe(ip, p) for p in DISCOVERY_PORTS]
        if self.opts.use_ping:
            tasks.append(self._ping(ip))
        res = await asyncio.gather(*tasks)
        tcp_states = res[: len(DISCOVERY_PORTS)]
        alive_by = []
        if self.opts.use_ping and res[-1]:
            alive_by.append("ping")
        if any(s in (OPEN, CLOSED) for s in tcp_states):
            alive_by.append("tcp")
        open_ports = {p for p, s in zip(DISCOVERY_PORTS, tcp_states) if s == OPEN}
        return ip, alive_by, open_ports

    async def _fingerprint(self, obs: Observation) -> None:
        states = await asyncio.gather(*(self._probe(obs.ip, p) for p in FINGERPRINT_PORTS))
        opened = {p for p, s in zip(FINGERPRINT_PORTS, states) if s == OPEN}
        obs.open_ports = sorted(set(obs.open_ports) | opened)

    async def _enrich(self, obs: Observation) -> None:
        if self.opts.resolve_dns:
            obs.hostname = await netutil.reverse_dns(obs.ip)
        if obs.mac:
            obs.vendor = self.oui.lookup(obs.mac)
        if self.opts.snmp_credentials:
            async with self._sem:
                obs.snmp = await snmp.query_any(obs.ip, self.opts.snmp_credentials)

    async def run(self) -> list[Observation]:
        p = self.progress
        p.started_at, p.finished_at, p.error, p.cancelled, p.alive = utcnow(), "", "", False, 0
        p.targets = list(self.opts.targets)
        try:
            ips = netutil.expand_targets(self.opts.targets)

            self._phase("barrido", len(ips))
            found = await self._gather([self._discover(ip) for ip in ips])

            arp = netutil.read_arp_cache()
            target_set = set(ips)
            observations: dict[str, Observation] = {}
            for ip, alive_by, open_ports in found:
                if ip in arp:
                    alive_by = alive_by + ["arp"]
                if alive_by:
                    observations[ip] = Observation(ip=ip, mac=arp.get(ip, ""), open_ports=sorted(open_ports), alive_by=alive_by)
            # Hosts que solo contestaron ARP (bloquean ICMP y TCP) también cuentan
            for ip, mac in arp.items():
                if ip in target_set and ip not in observations and not p.cancelled:
                    observations[ip] = Observation(ip=ip, mac=mac, alive_by=["arp"])
            gateways = netutil.default_gateways()
            own = {n.address for n in netutil.local_networks()}
            for ip, o in observations.items():
                o.is_gateway, o.is_probe = ip in gateways, ip in own
            p.alive = len(observations)
            obs_list = list(observations.values())

            if not p.cancelled:
                self._phase("puertos", len(obs_list))
                await self._gather([self._fingerprint(o) for o in obs_list])
            if not p.cancelled:
                self._phase("enriquecimiento", len(obs_list))
                await self._gather([self._enrich(o) for o in obs_list])

            now = utcnow()
            for o in obs_list:
                o.observed_at = now
            p.phase = "cancelado" if p.cancelled else "terminado"
            return obs_list
        except Exception as exc:
            p.phase, p.error = "error", str(exc)
            raise
        finally:
            p.finished_at = utcnow()
