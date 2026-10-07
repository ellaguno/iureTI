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
│   ├─ mdns, ssdp/upnp, http, netbios, ttl, dmi (la sonda)         │
│   ├─ snmp-arp, virtual (anfitriones: ARP/VMs por SNMP, puentes) │
│   ├─ (v2) ldap, lldp/cdp, tablas ARP/MAC                         │
│   └─ (v3) winrm, ssh, APIs de plataformas                        │
│                                                                  │
│  Clasificador ─▶ Conciliador (dedup) ─▶ SQLite local             │
│  Enriquecimiento opcional ── HTTPS ──▶ Claude + búsqueda web     │
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
| `device_type` | `workstation`, `laptop`, `server`, `switch`, `router`, `firewall`, `access_point`, `printer`, `ups`, `nas`, `hypervisor`, `camera`, `phone` (teléfono IP), `mobile` (celular/tablet), `iot`, `unknown` |
| `confidence` | 0–1, confianza de la clasificación |
| `hostname`, `ips[]`, `macs[]`, `vendor`, `model`, `serial`, `os` | |
| `open_ports[]` | |
| `sources[]` | Qué collectors lo vieron |
| `first_seen`, `last_seen` | |
| `synced_at`, `remote_status`, `inventory_id` | Último envío y respuesta de iurefficient (`matched`, `created_pending`, `ignored`, `rejected`); `inventory_id` es UUID |
| `attributes.virtual` (v0.5) | Si es contenedor o VM: `kind` (`container`/`vm`), `platform` (docker, kvm, proxmox, vmware, hyperv…), `host_id`/`host_name`/`host_ip` (el activo que lo aloja), `confidence` (`alta` por evidencia directa, `media` si es probable), `evidence`, `reach` (`network` o `host` si solo se ve desde su anfitrión), `host_candidates` si no se pudo decidir |
| `attributes.guests` (v0.5) | En un anfitrión: lista de `{id, name, ip, kind, platform}` de lo que aloja |
| `attributes.hosting` (v0.5) | Lo que dijo SNMP del anfitrión: interfaces de virtualización, plataformas, VMs de ESXi |
| `attributes.names` (v0.5) | Todos los nombres con que se vio al equipo (DNS, sysName, NetBIOS, mDNS, nombre de VM) |
| `attributes.merged_from` (v0.5) | Duplicados que absorbió: `{id, fingerprint}` (se envían como `superseded_probe_asset_ids`) |

## Identidad y deduplicación

Prioridad de la clave de identidad:

1. `serial` (normalizado, descartando valores basura como `0`, `N/A`, `To be filled by O.E.M.`)
2. `mac` **universalmente administrada** (no aleatoria)
3. `hostname` normalizado (sin dominio, minúsculas)
4. `ip` (solo último recurso; identidad débil)

Dos observaciones se fusionan si comparten cualquiera de las claves fuertes (1–3). La IP
solo se usa si no hay nada más. La MAC localmente administrada es clave **débil** (0.4.2): va al final y
una coincidencia exacta casa; quedan fuera las derivadas (Docker `02:42:<ip>`).

**Entre escaneos (v0.5).** Un equipo puede verse con claves distintas en escaneos distintos (hoy la MAC,
mañana solo el nombre desde otra subred). Por eso:

- Se indexan **todos los nombres** con que se vio (DNS, sysName, NetBIOS, mDNS, nombre de VM), no solo el
  principal.
- Si una observación casa con **varios activos** por claves distintas, eran el mismo equipo: se **fusionan**
  en el de la clave más fuerte (IPs, MACs, fuentes, atributos; `first_seen` el más antiguo; se conservan
  `inventory_id` y el tipo fijado a mano). El absorbido se borra y el principal guarda `merged_from` y se
  reenvía con `superseded_probe_asset_ids`.
- Los duplicados que ya hubiera en la base se **consolidan al cargar** (y con `iureti-discovery consolidate`).
- Los hosts de **otras subredes** no tienen MAC por ARP; la **tabla ARP del router** (SNMP) se la da, y así
  se reconocen por MAC entre escaneos (`attributes.mac_from = snmp-arp:<router>`).
- Un invitado que solo se ve desde su anfitrión (contenedor NAT: `172.17.0.2` existe en cada servidor con
  Docker) tiene su IP **en el ámbito de su anfitrión**: clave propia `guest:<anfitrión>/<mac|ip>` (solo de la
  sonda; a iurefficient llega como `fingerprint`).

## Contenedores y máquinas virtuales (v0.5)

Módulo `virtual.py`. Qué es virtual y qué equipo real lo contiene, de más a menos seguro:

1. **Tabla ARP del anfitrión por SNMP** en una interfaz virtual (docker0, virbr0, vmbr0, vnet…): el invitado
   cuelga de ese equipo. Si no se alcanza desde la red se da de alta igual, «visto solo a través del
   anfitrión» (`reach = host`, `alive_by = snmp-arp`). Configurable: *Incluir contenedores y VMs que solo se ven
   desde su anfitrión* (`include_hosted_guests`).
2. **Tabla de VMs de ESXi** (VMWARE-VMINFO-MIB): nombre y MAC de cada VM.
3. **El equipo de la sonda**: lo visto por sus redes virtuales o colgado de sus puentes (`bridge fdb show`).
4. **MAC dinámica de Hyper-V**: codifica los dos últimos octetos de la IP del anfitrión → *probable*.
5. **Prefijo de MAC**: dice que es virtual. Si la sonda corre en un anfitrión con interfaces de virtualización
   del mismo tipo, se le atribuye como *probable* (suposición educada); si no, los hipervisores de esa familia
   vistos en la red quedan como `host_candidates` y el anfitrión como desconocido.

La relación se recalcula entera tras cada escaneo sobre todos los activos (`virtual.annotate`): el invitado
guarda `host_id`; el anfitrión, `guests`. El tipo de dispositivo no cambia por ser virtual (una VM Windows
Server sigue siendo `server`); lo virtual es un atributo ortogonal. Un anfitrión suma a `hypervisor` (VMs por
SNMP, puertos vnet/tap, 2179 Hyper-V) o a `server` (contenedores).

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
  mdns.py          mDNS / DNS-SD (zeroconf)
  upnp.py          SSDP + descripción UPnP
  httpinfo.py      huella de la página web del equipo
  netbios.py       NetBIOS Node Status
  localhost.py     datos DMI de la propia sonda
  enrich.py        identificación por internet (Claude + búsqueda web) e imagen del producto
  classify.py      clasificador por reglas
  virtual.py       contenedores y VMs: qué es virtual y qué equipo lo aloja
  reconcile.py     conciliación / deduplicación (fusión de duplicados entre escaneos)
  scanner.py       orquestador de un escaneo
  store.py         persistencia SQLite
  sync.py          envío a la API y CSV para Inventario › Importar
  service.py       operaciones compartidas por CLI y web
  web/             FastAPI + UI
  cli.py           línea de comandos
```
