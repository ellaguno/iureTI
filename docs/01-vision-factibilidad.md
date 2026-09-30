# 01 — Visión y factibilidad

## Problema

Mantener el inventario de TI (PCs, laptops, servidores, switches, firewalls, impresoras,
access points, UPS, etc.) de forma manual es lento, se desactualiza y no detecta equipos
no autorizados. iurefficient ya tiene un módulo de inventario; falta una forma de
**poblarlo automáticamente**.

## Propuesta

Una aplicación autónoma para Linux — **iureTI Discovery** — que:

1. Se instala en un equipo de la red del cliente (PC con escritorio, VM o servidor).
2. Descubre activos combinando varias fuentes (red, SNMP, directorio, APIs).
3. Clasifica y deduplica lo encontrado.
4. Presenta los hallazgos en una interfaz para revisión.
5. Envía los activos aprobados a la API de inventario de iurefficient.

La interfaz es **web local** (servida por la propia sonda): funciona igual en un equipo
con escritorio (se abre en el navegador local) que en un servidor sin GUI (se accede
por navegador desde otro equipo). No es necesario exigir entorno gráfico.

## ¿Es factible?

Sí. Existen precedentes maduros (Lansweeper, GLPI + GLPI-Agent, OCS Inventory,
NetBox + herramientas de discovery, Snipe-IT + scanners). La clave es **no depender
de una sola técnica**: en redes corporativas modernas el “escaneo ingenuo” ve poco,
pero la combinación de fuentes cubre la gran mayoría del parque.

Cobertura esperada por técnica:

| Técnica | Sin credenciales | Qué aporta | Cobertura típica |
|---|---|---|---|
| ARP / ICMP / puertos | Sí | IP, MAC, fabricante, hostname, tipo probable | Solo segmentos alcanzables; Windows suele bloquear ICMP |
| mDNS / SSDP / NetBIOS | Sí | Nombre y modelo de impresoras, APs, equipos Apple, IoT | Solo el segmento L2 local |
| SNMP v2c/v3 | Credencial de solo lectura | Modelo, serie, firmware, interfaces, **tablas ARP/MAC**, **vecinos LLDP/CDP** | Toda la infraestructura de red + descubrimiento indirecto de otras subredes |
| AD / LDAP | Cuenta de solo lectura | Todas las computadoras del dominio, incluso apagadas | Todo el parque Windows unido a dominio |
| WinRM / SSH | Cuenta con permisos de lectura | Hardware, software instalado, usuario | Equipos alcanzables con credencial |
| APIs (vCenter, Proxmox, controladoras Wi-Fi, firewalls, nube) | Token de API | VMs, APs gestionados, clientes | Según plataformas del cliente |
| Agente (p.ej. GLPI-Agent) | Instalación en endpoint | Inventario completo, incluso fuera de la red | Laptops móviles / home office |

**SNMP + AD/LDAP** por sí solos suelen cubrir el 70–80 % de lo que una empresa necesita.

## Obstáculos reales en empresas medianas y grandes

| Obstáculo | Mitigación |
|---|---|
| Firewall de Windows bloquea ICMP / WMI | Usar AD/LDAP; habilitar WinRM por GPO; agente |
| Segmentación (VLANs, ACLs) | Leer tablas ARP/MAC de routers/switches vía SNMP; varias sondas por sitio/VLAN |
| IDS/EDR interpretan el escaneo como ataque | IP de sonda documentada y en lista blanca; límite de velocidad; preferir SNMP/AD sobre barridos |
| SNMP deshabilitado o v3 obligatorio | Soporte SNMPv3 desde el MVP; configuración única del cliente |
| Políticas de seguridad | Proceso formal de autorización; solo credenciales de lectura (ver [05](05-seguridad.md)) |
| Duplicados (Wi-Fi + cable, DHCP) | Conciliación por serie > MAC > hostname (ver [03](03-arquitectura.md)) |
| MACs aleatorias (móviles, Windows/macOS modernos) | Detectar MAC localmente administrada y no usarla como identidad fuerte |

## Posicionamiento

Se vende como **“descubrimiento autorizado con credenciales de solo lectura”**, no como
“escáner de red”. Es la diferencia entre pasar o no el filtro de seguridad del cliente.

Valor adicional además del inventario: detección de equipos no autorizados, topología
física (qué equipo está en qué puerto de qué switch), y alertas de cambios.
