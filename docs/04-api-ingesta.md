# 04 — Contrato de la API de ingesta

Propuesta de contrato entre la sonda y el módulo de Inventario de iurefficient.
**Borrador**: debe alinearse con el modelo de datos real del módulo de inventario.

> **Decisiones (2026-09-30)** — plan del lado de iurefficient en
> `Colaborador especialista/docs/PLAN_INVENTARIO_DESCUBRIMIENTO_2026-09-30.md`:
> 1. **La aprobación ocurre en iurefficient**, no en la sonda: la sonda envía todo lo que
>    ve y la bandeja de descubiertos decide (aprobar, ligar a un activo existente o ignorar).
> 2. `device_type` es un **campo propio** del inventario (no una categoría).
> 3. GLPI-Agent e inventario de software pasan a la **v2**.
> 4. Correcciones al contrato: la ruta real es
>    `POST /api/plugins/inventory/discovery/batches` y `inventory_id` es un **UUID** (texto).

> **Cambio v0.2 (2026-09-30)**: el catálogo `device_type` suma **`mobile`** (celular/tablet) para no
> confundir smartphones con `phone` (teléfono IP de escritorio). Son 16 tipos; D0 debe incluirlo.
> `attributes` suma `product` (identificación por internet: `product_name`, `description`, `specs`,
> `product_url`, `image_url`, `confidence`…), `announced_name`, `os_family` y `upnp_serial_decoded`.

## Autenticación

- Cada sonda se registra en iurefficient y recibe un **token de sonda** (por tenant/cliente).
- Encabezado: `Authorization: Bearer <token>`.
- Solo HTTPS. El token solo permite *ingesta* (no lectura del inventario).

## `POST /api/plugins/inventory/discovery/batches`

Envía un lote de activos descubiertos. Idempotente por `batch_id`.

```json
{
  "batch_id": "0d6c3b1e-8f0a-4a57-9b7e-2a0c9c1e4f11",
  "probe": {
    "id": "sonda-matriz-01",
    "version": "0.1.0",
    "site": "Matriz CDMX"
  },
  "scan": {
    "started_at": "2026-09-30T15:00:00Z",
    "finished_at": "2026-09-30T15:04:12Z",
    "targets": ["192.168.100.0/24"],
    "collectors": ["sweep", "ports", "oui", "snmp"]
  },
  "assets": [
    {
      "probe_asset_id": "3f1e...",
      "fingerprint": "serial:FCW2233L0AB",
      "device_type": "switch",
      "confidence": 0.9,
      "hostname": "sw-core-01",
      "ips": ["192.168.100.2"],
      "macs": ["00:1a:2b:3c:4d:5e"],
      "vendor": "Cisco Systems",
      "model": "C9300-48P",
      "serial": "FCW2233L0AB",
      "os": "Cisco IOS XE 17.9.4",
      "open_ports": [22, 443],
      "location": "Site: Matriz, Rack 2",
      "sources": ["sweep", "snmp"],
      "first_seen": "2026-09-01T10:00:00Z",
      "last_seen": "2026-09-30T15:03:55Z",
      "attributes": { "snmp_sys_object_id": "1.3.6.1.4.1.9.1.2494" }
    }
  ]
}
```

### Respuesta `202 Accepted`

```json
{
  "batch_id": "0d6c3b1e-8f0a-4a57-9b7e-2a0c9c1e4f11",
  "received": 1,
  "results": [
    { "probe_asset_id": "3f1e...", "status": "matched", "inventory_id": "7b0c1f2e-…" }
  ]
}
```

`status` por activo:
- `matched` — se asoció a un activo existente (se actualiza `last_seen`, IPs, etc.)
- `created_pending` — nuevo; queda **pendiente de aprobación** en iurefficient
- `rejected` — con `reason`

## Gestión de sondas: `POST /api/plugins/inventory/discovery/heartbeat`

Va en el mismo blueprint público que `/discovery/batches` (autenticación por token de sonda, sin sesión).
La sonda **solo hace conexiones salientes** (HTTPS a iurefficient); nunca abre puertos. Cada
`heartbeat_seconds` (300 por omisión) reporta su estado y recibe configuración y órdenes. Mismo token de
sonda que la ingesta. El primer heartbeat de un token registra la sonda («conectada»).

### Petición

```json
{
  "probe": {
    "id": "sonda-matriz-01",
    "version": "0.3.0",
    "site": "Matriz CDMX",
    "hostname": "srv-inventario",
    "os": "Ubuntu 24.04.5 LTS",
    "arch": "x86_64",
    "install": "deb"
  },
  "status": {
    "state": "idle",
    "assets": 214,
    "unsynced": 3,
    "last_scan": {"started_at": "…", "finished_at": "…", "targets": ["10.0.0.0/24"],
                  "alive": 180, "new_assets": 2, "error": ""},
    "last_sync": {"at": "…", "sent": 214, "error": ""}
  },
  "networks": [{"interface": "eth0", "network": "10.0.0.0/24"}],
  "capabilities": ["sweep", "ports", "oui", "snmp", "mdns", "ssdp", "http", "netbios", "enrich"],
  "config_version": "c-2026-09-30-3",
  "acks": [{"id": "cmd-17", "status": "done", "detail": "180 hosts vivos"}]
}
```

- `networks` permite a iurefficient **sugerir rangos** al administrador.
- `acks` confirma las órdenes recibidas en heartbeats anteriores (`done` | `failed` | `ignored`).

### Respuesta `200 OK`

```json
{
  "config_version": "c-2026-09-30-3",
  "config": {
    "targets": ["10.0.0.0/24", "10.0.10.0/24"],
    "schedule": {"interval_minutes": 1440, "window": "01:00-05:00"},
    "collectors": {"snmp": true, "mdns": true, "ssdp": true, "http": true, "netbios": true, "ping": true, "dns": true},
    "concurrency": 256,
    "tcp_timeout": 0.8,
    "auto_sync": true,
    "auto_enrich": false,
    "heartbeat_seconds": 300
  },
  "commands": [{"id": "cmd-18", "type": "scan_now", "args": {"targets": ["10.0.0.0/24"]}}],
  "latest_version": "0.3.1"
}
```

- `config` es `null` (o se omite) si `config_version` no cambió; la sonda conserva la que tiene.
- Todos los campos de `config` son opcionales; lo que no venga no cambia.
- `schedule.window` es hora **local de la sonda**, `""` = cualquier hora; `interval_minutes: 0` = sin
  escaneos programados.
- Órdenes (`commands[].type`): `scan_now` (con `args.targets` opcional), `sync_now`, `enrich_now`,
  `forget_assets` (`args.ids`). Las desconocidas se confirman como `ignored`.
- `latest_version`: si es mayor que la instalada, la interfaz local avisa (la actualización la hace el
  sistema de paquetes o `install.sh --upgrade`; ver [07](07-distribucion.md)).

**Secretos**: las credenciales SNMP y las claves de IA **no** viajan en `config`; se capturan en la
sonda (interfaz local o CLI). iurefficient solo sabe qué recolectores están activos.

**Compatibilidad**: si el endpoint responde `404` (iurefficient sin el tramo de sondas), la sonda sigue
en modo local con su programación propia y reintenta en el siguiente ciclo.

## Reglas del lado de iurefficient

1. **Coincidencia** con activos existentes usando la misma prioridad que la sonda:
   serie → MAC universal → hostname.
2. Los activos nuevos **no** entran directo al inventario: llegan a una bandeja
   “Descubiertos / pendientes” para aprobación humana.
3. Campos capturados manualmente en iurefficient (responsable, centro de costo, ubicación
   física, factura) **nunca** se sobrescriben con datos de la sonda.
4. Campos técnicos (IP, firmware, SO, `last_seen`) sí se actualizan, con historial.
5. Un activo no visto en N días se marca como “no visto recientemente” (no se borra).

## Fallback sin API

Mientras la API no exista, la sonda exporta el mismo JSON (`GET /api/export.json` en la UI
local, o `iureti-discovery export --format json`) y un CSV para importación manual
(`GET /api/export.csv`, o `iureti-discovery export --format csv`).

**El CSV usa los encabezados de la plantilla de importación del inventario 1.1.0**
(`SKU`, `Nombre`, `Tipo`, `Estado`, `Categoría`, `Ubicación`, `Marca`, `Modelo`, `Serie`,
…, `Notas`) más `Descripción`, que el importador también reconoce. El importador simula
antes de guardar, reconoce por SKU o serie y no pisa celdas vacías.

| Columna | Valor que pone la sonda |
|---|---|
| `Nombre` | hostname sin dominio; si no hay, «<tipo> <marca> <modelo> (<IP>)» |
| `Tipo` | siempre `Hardware` |
| `Marca` / `Modelo` / `Serie` | fabricante (OUI o sysObjectID), modelo y serie SNMP |
| `Descripción` | resumen técnico: tipo de dispositivo, hostname, IPs, MACs, SO/firmware, ubicación SNMP, última vez visto |
| `SKU`, `Estado`, `Categoría`, `Ubicación`, `Responsable`, `Notas`, compra, garantía… | **vacías a propósito**: son datos capturados a mano en iurefficient |

Limitaciones del camino manual: el importador solo reconoce activos por SKU o serie (no por
MAC ni hostname, eso llega con D0), y al actualizar un activo coincidente sí escribe
`Nombre`, `Marca`, `Modelo` y `Descripción`. Por eso conviene revisar la simulación antes de
confirmar.
