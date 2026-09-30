# Documentación — iureTI Discovery

Sonda de **autodescubrimiento de recursos de TI** que corre en Linux (en un equipo de
la red o en un servidor) y alimenta el módulo de **Inventario de iurefficient**.

| Documento | Contenido |
|---|---|
| [01 — Visión y factibilidad](01-vision-factibilidad.md) | Qué problema resuelve, qué es posible y qué no, obstáculos en empresas medianas/grandes |
| [02 — Fuentes de descubrimiento](02-fuentes-descubrimiento.md) | Técnicas por capa: ARP/ICMP, puertos, mDNS/SSDP, SNMP, AD/LDAP, WinRM/SSH, APIs, agente |
| [03 — Arquitectura](03-arquitectura.md) | Componentes de la sonda, modelo de datos, clasificación y deduplicación |
| [04 — Contrato de la API de ingesta](04-api-ingesta.md) | Formato con el que la sonda envía activos a iurefficient |
| [05 — Seguridad y operación](05-seguridad.md) | Autorización, credenciales, huella en la red, relación con IDS/EDR |
| [06 — Roadmap](06-roadmap.md) | Fases MVP → v2 → v3 y estado actual |
| [07 — Distribución e instalación](07-distribucion.md) | `.deb` + systemd, Docker, `install.sh`, dónde va la sonda, publicar versiones |
