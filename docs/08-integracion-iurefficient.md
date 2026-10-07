# 08 — Integración con iurefficient (entrega para el módulo de inventario)

**Para**: quien desarrolla `iur-inventory` en iurefficient (`Colaborador especialista/instance/backend/plugins/iur_inventory`).
**Fecha**: 2026-09-30, actualizado 2026-10-07 (§8) · **Sonda**: iureTI Discovery 0.5.0 · **Inventario revisado**: iur-inventory 1.3.0 (discovery_service.py con bandeja D3 y clave débil 1.7.1)

Este documento dice **qué falta del lado de iurefficient** para que la sonda funcione completa. Se
escribió leyendo el código actual del plugin: lo que ya está bien no se repite, solo se lista.

Archivos de apoyo, generados con el código de la sonda (`uv run python scripts/export_integration_files.py`):

| Archivo | Para qué |
|---|---|
| [`integracion/identity_cases.json`](integracion/identity_cases.json) | Reemplaza `scripts/_inventory_identity_cases.json` (mismo formato) |
| [`integracion/ejemplo-lote.json`](integracion/ejemplo-lote.json) | Lote real de la sonda: módem ONT, celular, switch con SNMP, impresora |
| [`integracion/ejemplo-heartbeat.json`](integracion/ejemplo-heartbeat.json) | Petición real de heartbeat |

Contrato completo: [04 — API de ingesta y gestión de sondas](04-api-ingesta.md).

---

## Lo que ya funciona (1.3.0) — no tocar

- Token de sonda `iurprobe_` con huella SHA-256, revocable, solo ingesta (`InventoryProbe`).
- `POST /api/plugins/inventory/discovery/batches`: idempotente por `batch_id`, 2000 activos máx., 16 MB,
  límite por token, un activo que falla no tumba el lote. **Compatible con la sonda 0.3.1 tal cual.**
- Identidad portada de la sonda (`identity.py`) con prueba de paridad; regla de MACs basura
  (`00:00:00:00:00:00`, `ff:ff:ff:ff:ff:ff`) — **la sonda ya la aplica también** desde 0.3.1.
- Solo lo técnico se escribe sobre un activo existente; serie/marca/modelo/tipo solo si estaban vacíos;
  movimiento con lo que cambió.
- Bandeja de descubiertos: aprobar, ligar, ignorar (se recuerda por huella).
- GLPI-Agent y software instalado.

---

## 1. Paridad de identidad — obligatorio, ~15 minutos

Corriendo el `identity.py` actual contra los casos nuevos:

| Prueba | Resultado hoy |
|---|---|
| Catálogo de tipos | ✗ falta `mobile` |
| Serie | ✓ 14/14 |
| MAC | ✓ 12/12 |
| Hostname | ✗ 9/11 — `_gateway`, `_outbound` |
| Claves de identidad | ✗ 7/8 — mismo caso `_gateway` |

Cambios en `plugins/iur_inventory/identity.py`:

```python
DEVICE_TYPES = (
    'workstation', 'laptop', 'server', 'switch', 'router', 'firewall',
    'access_point', 'printer', 'ups', 'nas', 'hypervisor', 'camera', 'phone',
    'mobile',   # celular / tablet (sonda 0.2+); «phone» es teléfono IP de escritorio
    'iot', 'unknown',
)

def normalize_hostname(hostname):
    h = (hostname or '').strip().lower().rstrip('.')
    # PTR que es solo la IP, o nombre sintético de systemd-resolved («_gateway», «_outbound»): no identifican
    if not h or h.startswith('_') or re.fullmatch(r'[\d.]+', h):
        return ''
    return h.split('.')[0]
```

- Copiar `docs/integracion/identity_cases.json` sobre `scripts/_inventory_identity_cases.json` y correr
  `_inventory_identity_smoke.py`.
- Frontend: etiqueta de `mobile` = **«Celular / tablet»** (y `phone` = «Teléfono IP»).
- **Hoy, sin este cambio, los celulares que manda la sonda entran como `unknown`** (`_asset_fields`
  descarta los tipos que no conoce).

---

## 2. Heartbeat y gestión de sondas — lo que habilita la operación continua

La sonda 0.3 corre como servicio y cada 5 minutos llama:

```
POST /api/plugins/inventory/discovery/heartbeat
Authorization: Bearer iurprobe_…
```

Hoy recibe 404 y sigue en **modo local** (programación propia): no se rompe nada, pero iurefficient no
ve las sondas ni puede configurarlas. Petición y respuesta: [04, «Gestión de sondas»](04-api-ingesta.md)
y [`ejemplo-heartbeat.json`](integracion/ejemplo-heartbeat.json).

### 2.1 Modelo

Columnas nuevas en `InventoryProbe` (migración):

| Columna | Tipo | Origen |
|---|---|---|
| `last_heartbeat_at` | DateTime, índice | hora de recepción |
| `hostname`, `os_name`, `arch`, `install_type` | String | `probe.*` |
| `state` | String(20) | `status.state`: `idle` / `scanning` |
| `status` | JSON | `status` completo (activos, pendientes, último escaneo, último envío) |
| `networks` | JSON | `networks` — para **sugerir rangos** |
| `capabilities` | JSON | `capabilities` |
| `config` | JSON | lo que edita el administrador |
| `config_version` | String(40) | cambia en cada edición de `config` (p. ej. `c-<epoch>`) |

`last_version` ya existe: actualizarlo también desde el heartbeat.

Tabla nueva `plg_inventory_probe_command`:

| Columna | Notas |
|---|---|
| `id` (String 36) | lo que viaja como `commands[].id` |
| `probe_id` | FK, índice, `ondelete=CASCADE` |
| `type` | `scan_now` · `sync_now` · `enrich_now` · `forget_assets` |
| `args` | JSON (`{"targets": [...]}`, `{"ids": [...]}`) |
| `status` | `queued` → `sent` → `done` / `failed` / `ignored` |
| `detail` | texto del ack |
| `created_by`, `created_at`, `sent_at`, `done_at` | |

### 2.2 Endpoint (en `discovery_routes.py`, mismo blueprint público)

```python
@bp.route('/heartbeat', methods=['POST'])
@limiter.limit("120 per hour", key_func=_limit_key)
def heartbeat():
    probe, err = _probe_or_401()
    if err:
        return err
    if (request.content_length or 0) > 256 * 1024:
        return jsonify({'error': 'heartbeat demasiado grande'}), 413
    from plugins.iur_inventory.probe_service import handle_heartbeat
    return jsonify(handle_heartbeat(probe, request.get_json(silent=True) or {})), 200
```

`handle_heartbeat(probe, body)`:
1. Guardar `last_heartbeat_at`, `last_version`, `hostname`, `os_name`, `arch`, `install_type`, `state`,
   `status`, `networks`, `capabilities` (recortar textos; `networks` máx. 50).
2. **Acks**: por cada `acks[]` cuyo `id` sea un comando **de esta sonda**, pasarlo a `done`/`failed`/
   `ignored` con `detail` y `done_at`. Ignorar ids ajenos.
3. **Configuración**: si `body.config_version != probe.config_version` y `probe.config` no es nulo →
   devolver `config` y `config_version`; si coinciden, `config: null`.
4. **Órdenes**: devolver los comandos `queued` (máx. 10, por antigüedad) y marcarlos `sent`.
   Un comando `sent` sin ack en 24 h → `failed` («sin respuesta de la sonda»).
5. `latest_version`: la última versión publicada (GitHub `repos/ellaguno/iureTI/releases/latest`,
   con caché de 24 h), o un ajuste del plugin si se prefiere no consultar GitHub.

La sonda ya hace lo suyo: aplica `config`, ejecuta las órdenes una a una y manda los `acks` en el
siguiente heartbeat; valida rangos (máx. 65 536 direcciones) y descarta los inválidos.

**Validar también en iurefficient al guardar** (para que el administrador vea el error): rangos CIDR,
`a.b.c.d-e` o IPs sueltas, máx. 65 536 direcciones por rango; ventana `HH:MM-HH:MM`;
`interval_minutes` ≥ 30 o 0.

Estado derivado para la interfaz: **conectada** si `last_heartbeat_at` es más reciente que
2 × `heartbeat_seconds` (10 min por omisión); **desconectada** si no; **nunca conectada** si es nulo.

### 2.3 Pantalla Sondas (`ProbesSection.tsx`)

- **Al crear la sonda**, además del token (que ya se muestra una vez), mostrar el **comando de
  instalación** listo para copiar, con la URL pública de la instancia:
  ```bash
  curl -fsSL https://github.com/ellaguno/iureTI/releases/latest/download/install.sh | sudo sh -s -- \
    --url https://<instancia> --token iurprobe_… --name "<nombre>" --site "<sitio>"
  ```
  y la alternativa Docker:
  ```bash
  docker run -d --name iureti --network host --restart unless-stopped -v iureti-data:/data ghcr.io/ellaguno/iureti:latest
  docker exec iureti iureti-discovery enroll --url https://<instancia> --token iurprobe_… --name "<nombre>" --site "<sitio>"
  ```
- **Lista**: conectada/desconectada, versión (+ «actualización disponible» si `last_version` <
  `latest_version`), último contacto, estado (escaneando), último escaneo (vivos, nuevos, error),
  activos y pendientes de envío, redes detectadas.
- **Configurar** (edita `config` y cambia `config_version`): rangos (con las redes detectadas como
  sugerencias de un clic), cada cuántas horas y ventana horaria, recolectores (SNMP, mDNS, UPnP, web,
  NetBIOS, ping, DNS), enviar al terminar (`auto_sync`), buscar productos en internet (`auto_enrich`).
- **Acciones** → comandos: *Escanear ahora* (rangos opcionales), *Enviar ahora*, *Buscar productos*.
  Mostrar el historial de órdenes con su estado y detalle.
- Credenciales SNMP y claves de IA **no** se editan aquí: viven en la sonda (decisión de seguridad; la
  pantalla puede decir «se configuran en la sonda: `sudo iureti-discovery serve` → Configuración»).

---

## 3. Identificación de producto e imagen

Desde 0.2 cada activo puede traer `attributes.product` (identificación por internet con IA). Ejemplo
en el primer activo de [`ejemplo-lote.json`](integracion/ejemplo-lote.json):

```json
"product": {"product_name": "Huawei EchoLife HG8145X6", "manufacturer": "Huawei", "model": "HG8145X6",
            "description": "ONT GPON con Wi-Fi 6 …", "specs": ["GPON", "Wi-Fi 6 AX3000", …],
            "release_year": "2021", "support_status": "vigente",
            "product_url": "https://…", "image_url": "https://…", "confidence": "alta", "fetched_at": "…"}
```

Qué hacer con él:

| Dato | Uso |
|---|---|
| `image_url` | `InventoryItem.image_url` **solo si está vacío**. Recomendado: descargarla del lado del servidor y guardarla como archivo propio (no enlazar la URL externa). Al descargar: solo `http(s)`, solo hosts públicos (resolver y rechazar IPs privadas, loopback, link-local), `Content-Type` de imagen, máx. 5 MB. |
| `product_name` | Nombre sugerido al aprobar: `hostname` > `product_name` > `marca + modelo` > IP (hoy `suggested_name` no lo usa). |
| `description`, `specs`, `product_url`, `release_year`, `support_status` | Mostrar en la bandeja y en la ficha; guardar en `hardware_detail["product"]`. `description` del activo **solo si está vacía**. |
| `confidence` | Si es `baja`, mostrar pero no rellenar nada. |

Otros atributos útiles para la **bandeja** (ayudan a decidir):
`classification_reasons` (por qué la sonda cree que es un switch/celular…), `announced_name`
(«Pixel 9 Pro»), `os_family` (`unix`/`windows`/`network`, por TTL), `upnp_serial_decoded`
(serie GPON legible: `HWTC6371E3B5`). Hoy la bandeja muestra `open_ports` del payload; mostrar
también estos y la foto.

---

## 4. Detalles del contrato (sin cambios necesarios, para que se sepa)

- Respuestas por activo: la sonda trata `matched`, `created_pending`, `ignored` como recibidos y solo
  `rejected` como pendiente de reenviar. `discovered_id`, `summary` y `pending_total` extra: bien.
- La sonda manda lotes de 500 y, en modo servicio, **todo** tras cada escaneo (no solo cambios), para
  mantener `last_seen_at` al día: con el límite de 120 lotes/h caben 60 000 activos por hora.
- `enroll` valida con el heartbeat, no con `/discovery/ping` (se puede dejar `ping` para otros usos).
- Hostnames de celulares: `Android_XXXXXXXX` (nombre mDNS de Android) — sí identifica al equipo.
- La MAC de celulares y de las Mac/Windows modernas es **privada** (localmente administrada). Desde
  0.4.2 es **clave débil**, en ambos lados: va después de serie, MAC universal y hostname, y una
  coincidencia exacta casa (`localmac:<mac>`). Lo que no garantiza es encontrar al equipo cuando
  rota o cambia de red; ahí lo salva el hostname. Quedan fuera las MAC locales **derivadas**
  (Docker `02:42:<ip>`, que se repiten entre hosts).
- El nombre NetBIOS sintético de macOS (`MAC-xxxxxx`, cuando el nombre real no cabe en SMB) **no
  identifica** y no gana al nombre mDNS: una Mac vista así un día y por mDNS al siguiente salía
  dos veces (INST-002, oct-2026).

---

## 5. Pruebas de aceptación

1. **Paridad**: `_inventory_identity_smoke.py` en verde con el `identity_cases.json` nuevo.
2. **Lote**: crear una sonda, `POST` de `ejemplo-lote.json` con su token →
   4 `created_pending`; reenviar el mismo `batch_id` → misma respuesta con `duplicate: true`.
   En la bandeja: el módem como *Router* con foto y «Huawei EchoLife HG8145X6»; el celular como
   *Celular / tablet* «Pixel 9 Pro»; el switch con serie `FCW2233L0AB`; la impresora como *Impresora*.
3. **Heartbeat**: `POST` de `ejemplo-heartbeat.json` → 200, sonda «conectada» con sus redes.
   Guardar configuración en la pantalla → el siguiente heartbeat trae `config`; el que sigue (con el
   mismo `config_version`) trae `config: null`. *Escanear ahora* → aparece en `commands`; el ack llega
   en el heartbeat siguiente y el comando queda `done`.
4. **Sonda real** contra un entorno de pruebas:
   ```bash
   docker run -d --name iureti --network host -v iureti-data:/data ghcr.io/ellaguno/iureti:latest
   docker exec iureti iureti-discovery enroll --url https://<staging> --token iurprobe_…
   docker exec iureti iureti-discovery status
   ```
   Debe decir «✓ Conectada». Programar desde la pantalla Sondas y ver llegar el lote.

---

## 6. Decisiones vigentes (no cambian)

- La aprobación ocurre en iurefficient; un lote nunca crea activos directamente.
- `device_type` es un campo propio (16 tipos), no una categoría.
- Nunca se pisan responsable, ubicación, categoría, compra, notas ni nombre con datos de la sonda.
- Secretos (SNMP, claves de IA) solo en la sonda; iurefficient solo sabe qué recolectores están activos.
- La sonda solo hace conexiones salientes.
- Si cambia una regla de identidad o el catálogo, se cambia en ambos lados y se regenera
  `identity_cases.json` con `scripts/export_integration_files.py`.

## 7. Cambios de seguridad de la sonda 0.4.0 (a tener en cuenta)

- **Credenciales SNMP**: ahora cada credencial puede traer `networks` (lista de CIDR). No afecta al
  contrato de ingesta ni al heartbeat; es configuración local de la sonda.
- **Configuración remota acotada**: la sonda **recorta** lo que manda iurefficient a redes permitidas
  (privadas + las propias) y a límites seguros. Si la pantalla Sondas ofrece rangos públicos o valores
  extremos, la sonda los ignorará (y lo registra). Conviene que la pantalla valide igual y muestre las
  `networks` del heartbeat como sugerencia (ya excluyen interfaces virtuales).
- **Heartbeat**: sin cambios de forma respecto a [04](04-api-ingesta.md).

## 8. Contenedores, VMs y duplicados fusionados (sonda 0.5.0 ↔ iurefficient 1.8.x)

iurefficient 1.8.0 ya recibe contenedores y VMs como **parte de un equipo real** (`virtual_kind`,
`virtual_runtime`, `host_item_id`; la lista los esconde, la ficha del host los lista) con el contrato
`attributes.virtualization`. La sonda 0.5.0 **lo manda** con ese mismo contrato y lo amplía; además fusiona
duplicados y lo avisa. Detalle del contrato en [04, «Virtuales y duplicados»](04-api-ingesta.md).

### 8.1 Lo que la sonda manda (0.5.0)

```json
"attributes": {
  "virtualization": {
    "kind": "vm", "runtime": "vmware", "name": "srv-contabilidad", "reach": "network",
    "label": "máquina virtual VMware", "evidence": "VM «srv-contabilidad» en la tabla de VMs de esx-01",
    "host": {"hostname": "esx-01", "serial": "7XQ2K93", "macs": ["00:1a:2b:00:00:40"],
             "probe_asset_id": "9a1c…", "inventory_id": "7b0c1f2e-…", "ip": "10.0.0.40", "confidence": "alta"}
  },
  "guests": [{"probe_asset_id": "…", "name": "srv-contabilidad", "ip": "10.0.0.31", "kind": "vm", "platform": "vmware"}],
  "hosts_virtual": {"vm_count": 1},
  "superseded_probe_asset_ids": ["<probe_asset_id de un duplicado que absorbió>"],
  "mac_from": "snmp-arp:10.0.1.1"
}
```

De dónde sale (por confianza): tabla ARP del anfitrión en interfaces virtuales y tabla de VMs de ESXi
(SNMP), puentes y redes virtuales del equipo de la sonda (`bridge fdb`), MAC dinámica de Hyper-V (codifica
la IP del anfitrión; *media*), y el equipo de la sonda como anfitrión *probable* cuando solo lo sugiere el
prefijo de MAC y la sonda corre en un anfitrión de ese tipo. Sin evidencia, `host` no viene y
`host_candidates` lista los hipervisores de esa familia vistos en la red. `virtual_net` (≤0.4.2) se sigue
mandando por compatibilidad.

### 8.2 Lo que ya hace iurefficient 1.8.0 (no tocar)

- `virtualization_of`: lee `kind`, `runtime`, `name`, `host.{hostname, serial, macs, probe_asset_id}`.
- `resolve_virtual_host`: el anfitrión por identidad (serie > MAC > hostname) o, con `virtual_net`, el equipo
  de la sonda por el hostname del heartbeat.
- Al aprobar: nace `virtual_kind`/`virtual_runtime` y `host_item_id` si el anfitrión está inventariado;
  `suggested_name` prefiere `virtualization.name`.

### 8.3 Lo que añadió iurefficient 1.8.1 (hecho el 2026-10-07; smoke 48/48 con el `ejemplo-lote.json` real)

| Qué | Dónde |
|---|---|
| Resolver el anfitrión también por `host.inventory_id` (UUID) y por `host.probe_asset_id` cuando ese pendiente ya se aprobó/ligó (`InventoryDiscovered.payload.probe_asset_id` → `item_id`) | `resolve_virtual_host` |
| Un activo **ya inventariado** (`matched`) que llega marcado como virtual: rellenar `virtual_kind`, `virtual_runtime` y `host_item_id` **si estaban vacíos** (misma regla que serie/marca/modelo) | `_update_existing` |
| `superseded_probe_asset_ids`: retirar de la bandeja los pendientes de esa sonda con esos `probe_asset_id`; si alguno ya era `approved`/`linked`, el activo que llega **es** ese `item` (tratarlo como `matched`) | `ingest_batch` |
| Bandeja: si el anfitrión no está inventariado pero la sonda lo nombró, decir «corre en esx-01 (aún no inventariado)» y la confianza (`media` = probable) | `DiscoveredInbox.tsx`, `discovery_hints` |
| `runtime` suma `kubernetes` y `parallels` al catálogo | `VIRTUAL_RUNTIMES` |
| `reach == "host"`: la IP de un contenedor NAT se repite entre anfitriones; no se usa como pista de duplicado | (la bandeja no busca por IP) |

### 8.4 Pruebas de aceptación

5. **Fusión**: lote con dos activos del mismo equipo (uno solo con MAC, otro solo con nombre) → dos
   `created_pending`. Luego el activo fusionado con `superseded_probe_asset_ids` → el pendiente absorbido
   desaparece de la bandeja y queda uno solo.
6. **Virtual**: `ejemplo-lote.json` trae un ESXi (`esx-01`, con `guests`) y una VM (`srv-contabilidad`, con
   `virtualization.host`). En la bandeja la VM se ve como «VM · vmware · corre en esx-01»; al aprobar ambos,
   la VM queda con `host_item_id` del ESXi y la ficha del ESXi la lista.
7. **Matched**: un servidor ya inventariado que llega con `virtualization` queda `virtual_kind = vm` y su
   `host_item_id` si el anfitrión existe; un `virtual_kind` puesto a mano no se pisa.
