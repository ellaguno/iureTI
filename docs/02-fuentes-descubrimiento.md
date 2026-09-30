# 02 — Fuentes de descubrimiento

Ordenadas de menos a más invasivas. Cada fuente es un *collector* independiente en la
sonda; todos producen `Observation`s que luego se concilian (ver [03](03-arquitectura.md)).

## 1. Red sin credenciales

### Barrido de hosts
- **ARP** (segmento L2 local): la fuente más confiable para saber qué está vivo. Requiere
  estar en la misma VLAN. Sin privilegios root se aprovecha la caché ARP del kernel
  (`/proc/net/arp`) después de provocar tráfico hacia cada IP.
- **ICMP echo**: útil, pero Windows lo bloquea por defecto.
- **TCP connect** a puertos comunes: detecta hosts que bloquean ICMP.

### Huella por puertos
| Puerto | Indica |
|---|---|
| 22 | SSH (Linux, equipos de red) |
| 23 | Telnet (equipos de red antiguos) |
| 80 / 443 / 8080 / 8443 | Interfaz web (firewalls, APs, impresoras, NAS) |
| 135 / 139 / 445 | Windows (RPC / SMB) |
| 3389 | RDP (Windows) |
| 5985 / 5986 | WinRM |
| 161/udp | SNMP |
| 515 / 631 / 9100 | Impresoras (LPD, IPP, JetDirect) |
| 902 / 5480 | VMware ESXi / vCenter |
| 8006 | Proxmox VE |
| 554 | RTSP (cámaras) |
| 5060 | SIP (telefonía IP) |
| 3306 / 5432 / 1433 | Bases de datos (servidores) |

### Fabricante por MAC (OUI)
Los primeros 3 bytes de la MAC identifican al fabricante (registro IEEE). Si el bit
“localmente administrado” está encendido, la MAC es aleatoria y **no** sirve como
identificador ni para fabricante.

### Protocolos de anuncio (v2)
- **mDNS/Bonjour** (`_ipp._tcp`, `_printer._tcp`, `_airplay._tcp`, `_workstation._tcp`…)
- **SSDP/UPnP**: descripción XML con fabricante y modelo.
- **NetBIOS / LLMNR**: nombre de equipos Windows.

## 2. SNMP (infraestructura)

Versiones: v2c (community) y v3 (usuario + auth SHA/MD5 + priv AES/DES). Solo lectura.

| OID / MIB | Dato |
|---|---|
| `sysDescr` 1.3.6.1.2.1.1.1.0 | Descripción (SO/firmware) |
| `sysObjectID` 1.3.6.1.2.1.1.2.0 | Identifica fabricante/familia (enterprise OID) |
| `sysName` 1.3.6.1.2.1.1.5.0 | Hostname |
| `sysLocation` / `sysContact` | Ubicación / responsable |
| ENTITY-MIB `entPhysicalSerialNum` 1.3.6.1.2.1.47.1.1.1.1.11 | Número de serie |
| ENTITY-MIB `entPhysicalModelName` 1.3.6.1.2.1.47.1.1.1.1.13 | Modelo |
| Printer-MIB `prtMarkerSuppliesLevel` | Niveles de consumibles |
| IF-MIB | Interfaces, MACs, velocidades |
| IP-MIB `ipNetToMediaTable` (v2) | **Tabla ARP del router** → descubre hosts de otras subredes |
| BRIDGE-MIB / Q-BRIDGE `dot1qTpFdbTable` (v2) | **Tabla MAC del switch** → qué MAC en qué puerto |
| LLDP-MIB / CISCO-CDP-MIB (v2) | **Vecinos** → topología |

La combinación ARP del router + MAC del switch + LLDP permite ubicar físicamente cada
equipo sin escanear subredes remotas.

## 3. Directorio (v2)
- **Active Directory / LDAP**: objetos `computer` con `dNSHostName`, `operatingSystem`,
  `operatingSystemVersion`, `lastLogonTimestamp`, OU. Cuenta de solo lectura.
- **Entra ID / Intune** (v3) vía Microsoft Graph.

## 4. Inventario profundo con credenciales (v3)
- **Windows**: WinRM (CIM: `Win32_ComputerSystem`, `Win32_BIOS`, `Win32_Processor`,
  `Win32_DiskDrive`, software instalado).
- **Linux / macOS**: SSH (`dmidecode`, `lsblk`, `/etc/os-release`, `system_profiler`).

## 5. APIs de plataformas (v3)
vCenter, Proxmox, Hyper-V, controladoras UniFi / Meraki / Aruba, FortiGate, pfSense/OPNsense,
Azure / AWS / GCP.

## 6. Agente (v3)
Para laptops que no siempre están en la red: integrar **GLPI-Agent** (open source,
formato de inventario estándar) en vez de desarrollar un agente propio.
