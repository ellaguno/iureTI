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
- [ ] Primer release publicado (`v0.3.0`) y prueba del runner arm64
- [ ] Del lado de iurefficient: pantalla Sondas + endpoint de heartbeat
- [ ] Appliance Raspberry Pi / OVA; repositorio apt firmado

## v2 — +4–6 semanas
- **GLPI-Agent (adelantado de v3)**: inventario de laptops y de software instalado; el
  software se cruza con los asientos de licencia del inventario de iurefficient
- Tablas ARP de routers y MAC de switches vía SNMP (descubrimiento de otras subredes)
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
