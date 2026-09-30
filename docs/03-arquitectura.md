# 03 — Arquitectura

```
┌──────────────── Sonda iureTI Discovery (Linux) ─────────────────┐
│                                                                  │
│  Interfaz web local (FastAPI + HTML/JS)  ◀── navegador           │
│      rangos, credenciales, escaneos, previsualización, envío     │
│                                                                  │
│  Motor de descubrimiento (asyncio)                               │
│   ├─ sweep     ARP / ICMP / TCP connect                          │
│   ├─ ports     huella por puertos                                │
│   ├─ oui       fabricante por MAC                                │
│   ├─ snmp      v2c / v3                                          │
│   ├─ (v2) mdns, ssdp, netbios, ldap, lldp/cdp, tablas ARP/MAC    │
│   └─ (v3) winrm, ssh, APIs de plataformas                        │
│                                                                  │
│  Clasificador ─▶ Conciliador (dedup) ─▶ SQLite local             │
│                                                                  │
│  Sincronizador ── HTTPS + token ──▶ API inventario iurefficient  │
└──────────────────────────────────────────────────────────────────┘
```

## Stack

| Pieza | Elección | Motivo |
|---|---|---|
| Lenguaje | Python 3.11+ | Mejor ecosistema de red (pysnmp, ldap3, pywinrm, paramiko, zeroconf) |
| Concurrencia | asyncio | Miles de sondeos TCP/UDP concurrentes sin hilos |
| SNMP | pysnmp 7 | Puro Python, v1/v2c/v3 |
| Web | FastAPI + HTML/JS sin build | Una sola dependencia, funciona con o sin escritorio |
| Almacenamiento | SQLite | Sin servicios externos; la sonda funciona desconectada |
| Empaquetado | `uv` / pip; luego .deb, AppImage, Docker | |

Sin privilegios de root el MVP funciona (TCP connect + caché ARP del kernel + `ping`
del sistema). Con `CAP_NET_RAW` se podrán agregar ARP activo y ICMP propio.

## Modelo de datos

### Observation
Lo que una fuente reporta de un equipo en un momento dado:
`source`, `ip`, `mac`, `hostname`, `vendor`, `open_ports`, `snmp{sys_descr, sys_object_id,
sys_name, serial, model, location}`, `observed_at`.

### Asset
Resultado de conciliar observaciones:

| Campo | Descripción |
|---|---|
| `id` | UUID local de la sonda |
| `fingerprint` | Clave de identidad (ver abajo) |
| `device_type` | `workstation`, `laptop`, `server`, `switch`, `router`, `firewall`, `access_point`, `printer`, `ups`, `nas`, `hypervisor`, `camera`, `phone`, `iot`, `unknown` |
| `confidence` | 0–1, confianza de la clasificación |
| `hostname`, `ips[]`, `macs[]`, `vendor`, `model`, `serial`, `os` | |
| `open_ports[]` | |
| `sources[]` | Qué collectors lo vieron |
| `first_seen`, `last_seen` | |
| `synced_at`, `remote_status`, `inventory_id` | Último envío y respuesta de iurefficient (`matched`, `created_pending`, `ignored`, `rejected`); `inventory_id` es UUID |

## Identidad y deduplicación

Prioridad de la clave de identidad:

1. `serial` (normalizado, descartando valores basura como `0`, `N/A`, `To be filled by O.E.M.`)
2. `mac` **universalmente administrada** (no aleatoria)
3. `hostname` normalizado (sin dominio, minúsculas)
4. `ip` (solo último recurso; identidad débil)

Dos observaciones se fusionan si comparten cualquiera de las claves fuertes (1–3). La IP
solo se usa si no hay nada más.

## Clasificación

Reglas con puntaje (se suman indicios, gana el tipo con mayor puntaje):

- `sysObjectID` enterprise conocido (Cisco, HP, Fortinet, Ubiquiti, Mikrotik…) + `sysDescr`
- Palabras en `sysDescr` / modelo (`switch`, `FortiGate`, `LaserJet`, `UniFi AP`, `Smart-UPS`…)
- Puertos (9100/631 → impresora; 3389+445 → Windows; 8006 → Proxmox; 902 → ESXi)
- Fabricante OUI (p.ej. Ubiquiti/Aruba → AP probable; Brother/Epson → impresora)

La clasificación nunca es definitiva: se corrige en la bandeja de descubiertos de
iurefficient (`device_type` es un campo propio del inventario, no una categoría). El campo
`type_locked` queda reservado para respetar un tipo fijado por una persona.

Indicios adicionales: la **puerta de enlace por omisión** de la sonda suma a router, y los
nombres sintéticos de systemd-resolved (`_gateway`) no se usan como hostname.

## Estructura del código

```
src/iureti_discovery/
  models.py        dataclasses Observation / Asset
  netutil.py       rangos, interfaces locales, ping, TCP connect, caché ARP, DNS inverso
  oui.py           base OUI IEEE (descarga y caché)
  snmp.py          consultas SNMP v2c/v3
  classify.py      clasificador por reglas
  reconcile.py     conciliación / deduplicación
  scanner.py       orquestador de un escaneo
  store.py         persistencia SQLite
  sync.py          envío a la API y CSV para Inventario › Importar
  service.py       operaciones compartidas por CLI y web
  web/             FastAPI + UI
  cli.py           línea de comandos
```
