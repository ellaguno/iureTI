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
- [x] Identificación por internet con Claude + búsqueda web: nombre comercial, descripción, ficha y foto; caché por producto
- [ ] Probar la identificación por internet con clave real (solo probado con cliente simulado)
- [ ] Clave de Anthropic en keyring en vez de la BD local

## v2 — +4–6 semanas
- **GLPI-Agent (adelantado de v3)**: inventario de laptops y de software instalado; el
  software se cruza con los asientos de licencia del inventario de iurefficient
- Tablas ARP de routers y MAC de switches vía SNMP (descubrimiento de otras subredes)
- LLDP / CDP y vista de topología
- mDNS, SSDP, NetBIOS
- AD / LDAP
- Escaneos programados
- Autenticación y TLS en la UI; secretos en keyring
- Paquetes .deb / AppImage / imagen Docker
- Varias sondas por cliente

## v3 — +6–8 semanas
- WinRM / SSH: hardware y software instalado
- APIs: vCenter, Proxmox, UniFi, Meraki, FortiGate, nube
- Detección de cambios y alertas (equipo nuevo, equipo desaparecido, cambio de firmware)
