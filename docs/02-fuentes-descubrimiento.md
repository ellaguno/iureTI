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

### Protocolos de anuncio (implementados en v0.2)
Solo alcanzan el segmento L2 de la sonda (multicast), salvo NetBIOS y HTTP.

| Fuente | Qué aporta | Ejemplo real |
|---|---|---|
| **mDNS / DNS-SD** | Nombre `.local`, servicios anunciados, TXT con modelo | Pixel: `Android_9XP64ZT9`, `_FC9F5ED42C8A._tcp` (Nearby), KDE Connect `name=Pixel 9 Pro`, `type=phone` |
| **SSDP / UPnP** | Descripción XML: fabricante, modelo, **serie**, tipo de dispositivo, íconos | Módem: `InternetGatewayDevice`, Huawei EchoLife, serie `485754436371E3B5` = GPON `HWTC6371E3B5` |
| **Página web del equipo** | `Server`, `<title>`, realm de autenticación, tokens que parecen modelo | Módem: `HG8145X6` en la página de acceso |
| **NetBIOS (UDP 137)** | Nombre y grupo de trabajo/dominio de Windows/Samba | |
| **TTL del ping** | Familia de SO: 64 Linux/Android/macOS/iOS, 128 Windows, 255 red | |
| **Puerto 62078** | Servicio de sincronización de iPhone/iPad | |
| **La propia sonda** | `/sys/class/dmi/id` y `/etc/os-release` sin root | ThinkPad P52, Ubuntu 24.04 |

Notas de campo:
- Un teléfono **en reposo** contesta mDNS de forma intermitente (con ahorro de energía del Wi-Fi). Por eso la
  sonda escucha mDNS durante todo el barrido, y lo que vio una vez se conserva: Android mantiene una MAC
  privada estable por red, así que el siguiente escaneo reconoce al mismo equipo.
- La MAC privada/aleatoria sola ya sugiere celular o tablet (probabilidad baja).
- mDNS se escucha en paralelo al barrido; SSDP se consulta después, porque con miles de sondeos en curso se
  pierden respuestas multicast.

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

## 6. Identificación por internet (v0.2, opcional)
Con las pistas locales (marca, modelo genérico, descripción UPnP/SNMP, título de la página, candidatos de modelo)
la sonda pide a **Claude con búsqueda web** que identifique el producto exacto: nombre comercial, descripción,
características, año, estado de soporte, ficha y **foto**. Ver [05](05-seguridad.md) para qué datos salen.

- La foto se toma de la URL que dio la búsqueda o de la `og:image` de la ficha del producto; la sonda la
  descarga, valida que sea imagen (≤ 5 MB) y la guarda en caché local.
- Caché por huella de producto: diez módems iguales = una consulta.
- Si la confianza es «baja», se muestra pero no cambia modelo ni tipo.

## 7. Agente (v2)
Para laptops que no siempre están en la red: integrar **GLPI-Agent** (open source,
formato de inventario estándar) en vez de desarrollar un agente propio.
