# 06 — Roadmap

## MVP (v0.1) — en curso
Estimado: 4–6 semanas, 1 desarrollador.

- [x] Documentación inicial (visión, fuentes, arquitectura, contrato API, seguridad)
- [x] Estructura del proyecto Python (`uv`, `pyproject.toml`) y CLI (`iureti-discovery`)
- [x] Barrido de hosts sin root: TCP connect + `ping` + caché ARP del kernel
- [x] Huella por puertos (TCP connect asíncrono)
- [x] Fabricante por OUI (descarga del registro IEEE, caché local) y detección de MAC aleatoria
- [x] DNS inverso (descarta nombres sintéticos como `_gateway`)
- [x] Puerta de enlace por omisión como indicio de router/firewall
- [x] SNMP v2c / v3: sysDescr, sysObjectID, sysName, sysLocation, serie y modelo (ENTITY-MIB / Printer-MIB)
- [x] Clasificador por reglas
- [x] Conciliación / deduplicación (serie > MAC universal > hostname > IP)
- [x] Persistencia SQLite
- [x] UI web local: configurar, escanear y previsualizar (sin aprobación: se aprueba en iurefficient)
- [x] Exportación JSON (contrato de [04](04-api-ingesta.md)) y CSV con la plantilla de Inventario › Importar 1.1.0
- [x] Envío a iurefficient en lotes de 500 (`/api/plugins/inventory/discovery/batches`), guardando la respuesta por activo
- [x] Pruebas automatizadas (34) y escaneo real de una red doméstica /24 (≈11 s, sin root)
- [ ] Pruebas SNMP contra equipos reales (switch, impresora, UPS)
- [ ] Pruebas en red real de cliente
- [ ] Endpoint de ingesta del lado de iurefficient (tramos D0–D3 del plan de iurefficient)

## v0.2 — identificación ampliada (2026-09-30)
- [x] mDNS / DNS-SD escuchando durante todo el barrido (celulares Android/iOS, Chromecast, impresoras, HomeKit…)
- [x] SSDP/UPnP: fabricante, modelo, serie (incluye decodificación de serie GPON) y tipo de dispositivo
- [x] Huella de la página web: título, `Server`, realm y candidatos de modelo
- [x] NetBIOS (nombre y grupo de Windows/Samba), TTL → familia de SO, puerto 62078 (iPhone/iPad)
- [x] La sonda se describe a sí misma (DMI + os-release)
- [x] Tipo `mobile` (celular/tablet) separado de `phone` (teléfono IP)
- [x] Identificación por internet con IA + búsqueda web: nombre comercial, descripción, ficha y foto; caché por producto
- [x] Proveedores: OpenRouter (Gemini, GPT, DeepSeek, Qwen…; por omisión) y Anthropic; costo por consulta visible
- [ ] Probar la identificación por internet con claves reales (solo probado con clientes simulados)
- [ ] Claves de API en keyring en vez de la BD local

## v0.3 — distribución y modo servicio (2026-09-30)
- [x] Contrato de gestión de sondas: heartbeat, configuración remota, órdenes (`docs/04`)
- [x] Agente: heartbeat, configuración de iurefficient, órdenes (`scan_now`, `sync_now`, `enrich_now`,
      `forget_assets`), escaneos programados con ventana horaria, envío y búsqueda automáticos
- [x] CLI `enroll`, `status`, `schedule`; `serve --agent`
- [x] `.deb` con Python propio + systemd endurecido (amd64/arm64), probado en Ubuntu 22.04/24.04 y Debian 12
- [x] Imagen Docker multi‑arquitectura; `install.sh` con verificación SHA‑256
- [x] GitHub Actions: CI y release por tag
- [x] Primer release publicado (`v0.3.0`): `.deb` amd64 y arm64 (instalación probada en CI en ambas arquitecturas), imagen `ghcr.io/ellaguno/iureti` pública, `install.sh` verificado contra el release real
- [ ] Del lado de iurefficient: pantalla Sondas + endpoint de heartbeat — entrega en [08](08-integracion-iurefficient.md)
- [ ] Appliance Raspberry Pi / OVA; repositorio apt firmado

## v0.4 — endurecimiento de seguridad (2026-10-01)
Tras una revisión de seguridad (modelo de amenazas: dispositivo hostil en la red, sitio web en el equipo
de la sonda, iurefficient comprometido, cadena de suministro). Detalle en [05](05-seguridad.md).

- [x] Interfaz: comprobación de Host (anti DNS rebinding), cabecera propia anti-CSRF, token al exponerla,
      CSP estricta, cabeceras de seguridad, `/docs` desactivado, enlaces solo http(s)
- [x] Configuración remota de iurefficient acotada a redes permitidas y a límites seguros (no puede
      sacar a la sonda a escanear internet)
- [x] Credenciales SNMP limitables por subred; aviso de usar SNMP v3; la community no se envía fuera de alcance
- [x] Descarga de imágenes/páginas a prueba de SSRF (valida host y cada redirección)
- [x] CSV sin inyección de fórmulas; `/etc/default` 0640; token por entorno/stdin; systemd más restringido
- [x] Cadena de suministro: permisos mínimos por job, acciones por SHA, imágenes por digest, atestación de
      procedencia (keyless) de `.deb` e imagen, Dependabot
- [x] 16 pruebas de seguridad que reproducen cada ataque
- [ ] Cifrado de secretos en reposo (keyring) — sigue pendiente

## v0.5 — duplicados entre escaneos y equipos virtuales con su anfitrión (2026-10-07)
- [x] Una observación que casa con varios activos por claves distintas los **fusiona** (eran el mismo equipo);
      los duplicados que ya había en la base se consolidan al cargar y con `iureti-discovery consolidate`
- [x] Se indexan todos los nombres con que se vio el equipo (DNS, sysName, NetBIOS, mDNS, nombre de VM)
- [x] Tabla ARP del router por SNMP → MAC para hosts de otras subredes (identidad entre escaneos)
- [x] Contenedores y VMs marcados como virtuales (`attributes.virtual`) con su **anfitrión**: puentes y redes
      virtuales de la sonda (`bridge fdb`), tabla ARP y de VMs (ESXi) del anfitrión por SNMP, MAC de Hyper-V,
      anfitrión probable = el equipo de la sonda; el anfitrión lista sus invitados (`guests`)
- [x] Invitados que solo se ven desde su anfitrión (contenedor NAT) se dan de alta en el ámbito de su anfitrión
      (opcional: `include_hosted_guests`)
- [x] Puertos 2179 (Hyper-V), 2375/2376 (API Docker); interfaces de virtualización por SNMP → anfitrión
- [x] Contrato: `virtual`, `guests`, `hosts_virtual`, `superseded_probe_asset_ids`, `mac_from`; UI con filtro
      físicos/virtuales/anfitriones; 13 pruebas nuevas
- [x] Del lado de iurefficient (1.8.1): «corre en <anfitrión>», ligar al anfitrión al aprobar, retirar los
      pendientes de `superseded_probe_asset_ids` (ver [08](08-integracion-iurefficient.md) §8)
- [ ] Tabla MAC de switches (BRIDGE-MIB): VM y su hipervisor comparten puerto → anfitrión sin SNMP en el host
- [ ] Nombres de contenedores del equipo de la sonda (requiere acceso al socket de Docker/Podman; decisión de
      seguridad pendiente)

## v2 — +4–6 semanas
- **GLPI-Agent (adelantado de v3)**: inventario de laptops y de software instalado; el
  software se cruza con los asientos de licencia del inventario de iurefficient
- Tablas MAC de switches vía SNMP (la tabla ARP de routers ya está en v0.5)
- LLDP / CDP y vista de topología
- mDNS, SSDP, NetBIOS
- AD / LDAP
- Escaneos programados
- Autenticación y TLS en la UI; secretos en keyring
- Varias sondas por cliente (la sonda ya lo soporta; falta la pantalla en iurefficient)

## v3 — +6–8 semanas
- WinRM / SSH: hardware y software instalado
- APIs: vCenter, Proxmox, UniFi, Meraki, FortiGate, nube
- Detección de cambios y alertas (equipo nuevo, equipo desaparecido, cambio de firmware)
