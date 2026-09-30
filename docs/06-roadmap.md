# 06 — Roadmap

## MVP (v0.1) — en curso
Estimado: 4–6 semanas, 1 desarrollador.

- [x] Documentación inicial (visión, fuentes, arquitectura, contrato API, seguridad)
- [ ] Estructura del proyecto Python (`uv`, `pyproject.toml`)
- [ ] Barrido de hosts sin root: TCP connect + `ping` + caché ARP del kernel
- [ ] Huella por puertos (TCP connect asíncrono)
- [ ] Fabricante por OUI (descarga del registro IEEE, caché local) y detección de MAC aleatoria
- [ ] DNS inverso
- [ ] SNMP v2c / v3: sysDescr, sysObjectID, sysName, sysLocation, serie y modelo (ENTITY-MIB)
- [ ] Clasificador por reglas
- [ ] Conciliación / deduplicación (serie > MAC > hostname > IP)
- [ ] Persistencia SQLite
- [ ] UI web local: lanzar escaneo, ver activos, aprobar/ignorar, cambiar tipo, exportar
- [ ] Exportación JSON (contrato de [04](04-api-ingesta.md)) y CSV
- [ ] Envío a la API de iurefficient (configurable; pendiente que exista el endpoint)
- [ ] Pruebas en red real de cliente
- [ ] Endpoint de ingesta del lado de iurefficient

## v2 — +4–6 semanas
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
- Integración con GLPI-Agent para laptops móviles
- Detección de cambios y alertas (equipo nuevo, equipo desaparecido, cambio de firmware)
