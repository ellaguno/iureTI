# 05 — Seguridad y operación

## Principios

1. **Solo con autorización.** Cada despliegue requiere autorización escrita del cliente
   que indique rangos, horarios y la IP de la sonda. Escanear redes ajenas sin permiso
   puede ser ilegal.
2. **Solo lectura.** Credenciales SNMP read-only, cuenta LDAP de lectura, cuentas WinRM/SSH
   sin privilegios de escritura. La sonda nunca modifica configuraciones.
3. **Mínima huella.** Límite de concurrencia y velocidad configurables; preferir fuentes
   pasivas o con credencial (SNMP, AD) sobre barridos masivos.
4. **Las credenciales no salen de la sonda.** Se guardan cifradas localmente y nunca se
   envían a iurefficient.

## Checklist de despliegue con el cliente

- [ ] Autorización firmada (rangos, horario, contacto de seguridad)
- [ ] IP / hostname de la sonda registrados en IDS/EDR/SIEM como escáner autorizado
- [ ] Reglas de firewall: sonda → redes objetivo (ICMP, TCP puertos de huella, UDP 161)
- [ ] Community SNMPv2c o usuario SNMPv3 de solo lectura, con ACL limitada a la IP de la sonda
- [ ] (v2) Cuenta de servicio LDAP de solo lectura
- [ ] (v3) WinRM habilitado por GPO para la cuenta de inventario
- [ ] Token de sonda emitido en iurefficient

## Modelo de amenazas y defensas (0.4.0)

La sonda vive DENTRO de la red del cliente y procesa datos de equipos que no controla. Se blindó contra
cuatro frentes; cada defensa tiene pruebas que reproducen el ataque (`tests/test_security.py`).

### La interfaz web
- Escucha solo en `127.0.0.1` por omisión. Toda la API comprueba la cabecera **Host** (defensa contra
  *DNS rebinding*: una página web cuyo dominio apunte a `127.0.0.1` recibe un **400**).
- Cada petición a `/api/*` exige una **cabecera propia** (`X-Iureti-UI`) que una página de otro sitio no
  puede poner sin un *preflight* CORS, que nunca se concede: bloquea CSRF y lecturas de otro origen. El
  `Origin` ajeno se rechaza.
- Al exponerla fuera de loopback (`--host 0.0.0.0`) se genera un **token de interfaz** obligatorio; se
  entrega por `?token=…` y se guarda en la sesión del navegador. Aun así, lo recomendado sigue siendo un
  túnel SSH (`ssh -L 8765:127.0.0.1:8765 …`) en vez de abrir el puerto.
- Respuestas con **CSP** estricta (`default-src 'none'`, `script-src 'self'`), `X-Frame-Options: DENY`,
  `nosniff` y `no-referrer`. `/docs` y `/openapi.json` desactivados. El script va en `/app.js` (sin JS en
  línea). Los enlaces que muestra la ficha de producto solo pueden ser `http(s)` (nada de `javascript:`).

### La configuración que llega de iurefficient
- Se recorta a límites seguros (`security.clamp_remote_config`): los **rangos deben caer dentro de las
  redes permitidas** (privadas + las propias de la sonda, o la lista que fije el operador en Configuración);
  un iurefficient comprometido **no** puede hacer que la sonda escanee internet. Concurrencia, timeout,
  heartbeat e intervalo se acotan.
- Los secretos (SNMP, claves de IA) **no** viajan en la configuración; se capturan en la sonda.

### Las credenciales SNMP
- Una *community* SNMP v2c viaja sin cifrar; quien escuche en el puerto 161 de un equipo la captura. Por eso
  cada credencial se puede **limitar a subredes** (su VLAN de gestión): fuera de ellas no se envía. Se
  recomienda **SNMP v3** (autenticación y cifrado). La interfaz avisa de esto en cada credencial v2c.

### Las URLs de la red / de la IA (SSRF)
- Toda URL que la sonda va a pedir (foto de producto, página de un equipo) se valida resolviendo el host y
  exigiendo que **todas** sus IPs sean públicas; se conecta a esa IP fija y se **validan todas las
  redirecciones** una a una (una redirección a `192.168.x` se corta). Imágenes: solo
  `image/jpeg|png|webp|gif`, máx. 5 MB.

## Protección del servicio y los secretos
- El servicio corre como el usuario `iureti` (sin shell, sin root), con endurecimiento de systemd
  (`ProtectSystem=strict`, `ProtectHome`, `NoNewPrivileges`, `RestrictAddressFamilies`, `UMask=0077`…) y
  como único privilegio `CAP_NET_RAW` para `ping`.
- Base de datos SQLite con permisos `600`; `/etc/default/iureti-discovery` con `0640 root:iureti` (puede
  llevar claves de IA). El token de sonda se da por `IURETI_TOKEN` o por entrada estándar, nunca en la línea
  de comandos (visible en `ps`).
- El CSV de exportación neutraliza la **inyección de fórmulas** (un equipo llamado `=…` no se ejecuta en
  Excel).
- Pendiente (roadmap): cifrar los secretos en reposo (keyring del sistema o clave de máquina).
- Registro (log) de cada escaneo: quién lo lanzó, rangos, fuentes, duración.

## Cadena de suministro
- `release.yml` con **permisos mínimos por job** (el job de pruebas no escribe nada), acciones **fijadas por
  SHA** de commit (Dependabot las actualiza) e imágenes base **por digest**.
- Los `.deb` y la imagen se publican con **atestación de procedencia** (keyless, OIDC): se puede comprobar
  que salieron de este repositorio y de este workflow.
  ```bash
  gh attestation verify iureti-discovery_0.4.0_amd64.deb --repo ellaguno/iureTI
  gh attestation verify oci://ghcr.io/ellaguno/iureti:v0.4.0 --repo ellaguno/iureTI
  ```
- `install.sh` verifica el SHA-256 del `.deb` antes de instalarlo.

## Identificación por internet (opcional, desactivada por omisión)

Se activa en Configuración › Búsqueda en internet y requiere una clave de **OpenRouter** (por omisión) o de
**Anthropic**. Con OpenRouter los datos pasan por OpenRouter y por el proveedor del modelo elegido; la sonda
pide `provider.data_collection: "deny"` para usar solo proveedores que no guardan ni entrenan con los datos.

**Qué se envía** (función `enrich.product_facts`, con prueba automática que lo verifica): tipo probable,
fabricante, modelo, SO/firmware, sysObjectID y sysDescr de SNMP, fabricante/modelo/tipo UPnP, título y
servidor de la página web del equipo con sus candidatos de modelo, servicios mDNS y su TXT de modelo, el
nombre anunciado **solo si parece un producto** («Pixel 9 Pro»), familia de SO por TTL y puertos abiertos.

**Qué nunca se envía**: IPs, MACs, hostnames, números de serie, `sysLocation`/`sysContact`, nombres que
pone el usuario (`friendlyName`, «iPhone de Juan»), ni nada del cliente o de la red.

Además, como última barrera, antes de enviar se borran de **todos** los campos de texto el hostname, el
sysName, el nombre NetBIOS/mDNS, las series, las IPs y las MACs del equipo (p. ej. el `sysDescr` de Linux
incluye el hostname: «Linux srv-contabilidad 5.15…» → «Linux [equipo] 5.15…»).

**Protecciones**:
- La sonda solo descarga imágenes/páginas de URLs **públicas**, resolviendo el host, exigiendo que todas
  sus IPs sean públicas, conectándose a esa IP fija y validando **cada redirección** (ver «Las URLs de la
  red / de la IA» arriba): una URL devuelta por la búsqueda no puede llevarla a la red interna.
- Imágenes: solo `image/jpeg|png|webp|gif`, máximo 5 MB, guardadas en la caché local.
- Las claves de API se guardan en la BD local (permisos 600) y se enmascaran en la interfaz; también se
  pueden dar por variable de entorno (`OPENROUTER_API_KEY`, `ANTHROPIC_API_KEY`).
- Con Anthropic, modelo por omisión `claude-opus-5-5` con `fallbacks: "default"`: si el modelo declina una
  consulta, la API la reintenta en el modelo de respaldo recomendado.

## Consideraciones legales / privacidad

- Hostnames y usuarios de sesión pueden ser datos personales: tratarlos conforme al aviso
  de privacidad del cliente.
- La sonda no captura tráfico ni contenido de comunicaciones.
